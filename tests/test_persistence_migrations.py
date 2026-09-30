"""Migrations apply once, survive a crash part-way and refuse drift; the schema guards itself."""

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

from fiat_checkpoints.domain.transitions import TRANSITIONS, Evidence
from fiat_checkpoints.persistence.database import Database, PersistenceRefusal
from fiat_checkpoints.persistence.migrations import DEFAULT_DIRECTORY, load_migrations, migrate
from fiat_checkpoints.persistence.scratch import ENVIRONMENT, ScratchDatabase, socket_directory
from tests.persistence_support import T0, DatabaseCase, passed, run_threads


ROOT = Path(__file__).resolve().parents[1]
# Later steps add migrations; these checks follow the shipped set and write
# their own specimens as the next version after it.
SHIPPED = tuple(item.version for item in load_migrations())
NEXT = len(SHIPPED) + 1


def next_name(label, version=NEXT):
    return f"{version:04d}_{label}.sql"


class MigrationDirectory:
    """A private copy of the shipped migrations the test may change."""

    def __init__(self, case):
        self.path = Path(tempfile.mkdtemp())
        case.addCleanup(shutil.rmtree, self.path)
        for name in os.listdir(DEFAULT_DIRECTORY):
            shutil.copyfile(DEFAULT_DIRECTORY / name, self.path / name)

    def write(self, name, text):
        (self.path / name).write_text(text)


class ScratchCase(unittest.TestCase):
    def setUp(self):
        self.scratch = ScratchDatabase()
        self.addCleanup(self.scratch.close)
        self.database = self.scratch.database

    def ledger(self):
        connection = self.database.connect()
        try:
            return [(row["version"], row["name"], row["sha256"]) for row in
                    connection.execute("SELECT version, name, sha256 FROM schema_migrations ORDER BY version")]
        finally:
            connection.close()

    def tables(self):
        connection = self.database.connect()
        try:
            return {row["tablename"] for row in
                    connection.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")}
        finally:
            connection.close()


class MigrationTests(ScratchCase):
    def test_shipped_directory_is_the_repository_migrations(self):
        self.assertEqual(DEFAULT_DIRECTORY, ROOT / "migrations")
        loaded = load_migrations()
        self.assertEqual([item.version for item in loaded], list(range(1, len(loaded) + 1)))
        for item in loaded:
            raw = (ROOT / "migrations" / f"{item.version:04d}_{item.name}.sql").read_bytes()
            self.assertEqual(item.sha256, hashlib.sha256(raw).hexdigest())

    def test_fresh_database_migrates_once_and_a_restart_is_a_no_op(self):
        self.assertEqual(migrate(self.database), SHIPPED)
        before = self.ledger()
        self.assertEqual(before[0][:2], (1, "coordination"))
        # A restarted process runs the same migrations again and changes nothing.
        self.assertEqual(migrate(self.database), ())
        self.assertEqual(self.ledger(), before)
        self.assertLessEqual({"candidates", "idempotency_keys", "quota_usage", "reservations",
                              "upload_attempts", "validation_attempts", "publication_intents",
                              "outbox_jobs", "audit_events", "actors", "run_registrations"}, self.tables())

    def test_a_failing_migration_leaves_nothing_and_a_rerun_completes(self):
        directory = MigrationDirectory(self)
        directory.write(next_name("next"), "CREATE TABLE half_done (id integer);\nSELECT no_such_function();\n")
        with self.assertRaises(PersistenceRefusal) as caught:
            migrate(self.database, directory.path)
        self.assertEqual(caught.exception.code, "persistence_failed")
        self.assertEqual([row[0] for row in self.ledger()], list(SHIPPED))
        self.assertNotIn("half_done", self.tables())
        directory.write(next_name("next"), "CREATE TABLE half_done (id integer);\n")
        self.assertEqual(migrate(self.database, directory.path), (NEXT,))
        self.assertIn("half_done", self.tables())

    def test_a_connection_killed_mid_migration_rolls_back_and_the_rerun_applies_it(self):
        migrate(self.database)
        directory = MigrationDirectory(self)
        directory.write(next_name("slow"), "CREATE TABLE slow_table (id integer);\nSELECT pg_sleep(30);\n")
        outcome = {}

        def run():
            try:
                migrate(self.database, directory.path)
            except PersistenceRefusal as error:
                outcome["code"] = error.code

        thread = threading.Thread(target=run)
        thread.start()
        admin = self.scratch.admin.connect()
        try:
            deadline = time.monotonic() + 30
            killed = False
            while not killed and time.monotonic() < deadline:
                killed = any(row["killed"] for row in admin.execute(
                    "SELECT pg_terminate_backend(pid) AS killed FROM pg_stat_activity "
                    "WHERE datname = %s AND query LIKE %s", (self.database.dbname, "%pg_sleep(30)%")))
                time.sleep(0.05)
        finally:
            admin.close()
        thread.join(60)
        self.assertTrue(killed)
        self.assertEqual(outcome.get("code"), "database_unavailable")
        self.assertEqual([row[0] for row in self.ledger()], list(SHIPPED))
        self.assertNotIn("slow_table", self.tables())
        directory.write(next_name("slow"), "CREATE TABLE slow_table (id integer);\n")
        self.assertEqual(migrate(self.database, directory.path), (NEXT,))

    def test_concurrent_runners_apply_each_migration_exactly_once(self):
        results = run_threads(6, lambda _index: migrate(self.database))
        self.assertTrue(all(isinstance(result, tuple) for result in results), results)
        self.assertEqual(sorted(results), [(), (), (), (), (), SHIPPED])
        self.assertEqual([row[0] for row in self.ledger()], list(SHIPPED))

    def test_changed_applied_migration_refuses_as_drift(self):
        migrate(self.database)
        directory = MigrationDirectory(self)
        name = sorted(os.listdir(directory.path))[0]
        directory.write(name, (directory.path / name).read_text() + "\n-- edited\n")
        with self.assertRaises(PersistenceRefusal) as caught:
            migrate(self.database, directory.path)
        self.assertEqual(caught.exception.code, "migration-drift")

    def test_database_newer_than_the_code_refuses(self):
        directory = MigrationDirectory(self)
        directory.write(next_name("future"), "CREATE TABLE future_table (id integer);\n")
        migrate(self.database, directory.path)
        with self.assertRaises(PersistenceRefusal) as caught:
            migrate(self.database)
        self.assertEqual(caught.exception.code, "migration-unknown")

    def test_migration_set_refuses_links_gaps_strays_and_bad_text(self):
        cases = {
            "gap": lambda path: (path / next_name("gap", NEXT + 1)).write_text("SELECT 1;\n"),
            "stray": lambda path: (path / "notes.txt").write_text("x"),
            "hidden": lambda path: (path / ".gitkeep").write_text(""),
            "symlink": lambda path: os.symlink(path / "0001_coordination.sql", path / next_name("link")),
            "directory": lambda path: (path / next_name("dir")).mkdir(),
            "encoding": lambda path: (path / next_name("bytes")).write_bytes(b"\xff\xfe"),
            "oversize": lambda path: (path / next_name("big")).write_bytes(b"-" * 262_145),
        }
        for label, change in cases.items():
            with self.subTest(case=label):
                directory = MigrationDirectory(self)
                change(directory.path)
                with self.assertRaises(PersistenceRefusal) as caught:
                    load_migrations(directory.path)
                self.assertEqual(caught.exception.code, "migration-set-invalid")
        with tempfile.TemporaryDirectory() as temporary:
            link = Path(temporary) / "linked"
            os.symlink(DEFAULT_DIRECTORY, link)
            with self.assertRaises(PersistenceRefusal) as caught:
                load_migrations(link)
            self.assertEqual(caught.exception.code, "migration-set-unavailable")
            with self.assertRaises(PersistenceRefusal) as caught:
                load_migrations(Path(temporary))
            self.assertEqual(caught.exception.code, "migration-set-invalid")


class SchemaGuardTests(DatabaseCase):
    def execute(self, statement, parameters=()):
        connection = self.database.connect()
        try:
            connection.execute(statement, parameters)
        finally:
            connection.close()

    def assert_refused(self, statement, parameters=()):
        connection = self.database.connect()
        try:
            with self.assertRaises(Exception) as caught:
                connection.execute(statement, parameters)
            self.assertEqual(getattr(caught.exception, "sqlstate", None), "23514")
        finally:
            connection.close()

    def test_sql_transition_table_is_the_domain_table(self):
        rows = {(row["source"], row["target"]) for row in self.query("SELECT source, target FROM candidate_transitions")}
        self.assertEqual(rows, {(source.value, target.value) for source, target in TRANSITIONS})
        self.assertEqual(len(rows), 28)

    def test_no_statement_moves_a_candidate_along_a_missing_row(self):
        candidate = self.announce().candidate_id
        for target in ("accepted", "publishing", "quarantined", "revoked", "denied"):
            with self.subTest(target=target):
                self.assert_refused("UPDATE candidates SET state = %s, version = version + 1 WHERE candidate_id = %s",
                                    (target, candidate))
        self.assert_refused("UPDATE candidates SET archive_sha256 = %s, version = version + 1 "
                            "WHERE candidate_id = %s", ("d" * 64, candidate))
        self.assert_refused("UPDATE candidates SET retry_reason = 'x' WHERE candidate_id = %s", (candidate,))
        self.assert_refused("UPDATE candidates SET fence = -1, version = version + 1 WHERE candidate_id = %s",
                            (candidate,))
        self.assertEqual(self.scalar("SELECT state FROM candidates"), "announced")

    def test_a_candidate_is_only_ever_inserted_as_announced(self):
        self.announce()
        run_key = self.scalar("SELECT run_key FROM run_registrations")
        self.assert_refused(
            "INSERT INTO candidates (candidate_id, run_key, actor_id, state, version, fence, archive_sha256, "
            "declared_size, announced_at, expires_at, updated_at) VALUES (gen_random_uuid(), %s, 9001, "
            "'accepted', 1, 0, %s, 1, now(), now() + interval '1 day', now())", (run_key, "e" * 64))

    def test_intents_and_audit_events_cannot_be_rewritten(self):
        self.quarantined()
        claim = self.coordinator.claim_validation({Evidence.ISOLATED_WORKER}, T0)
        self.coordinator.complete_validation(claim.lease, passed(), T0)
        for statement in ("UPDATE publication_intents SET fence = fence + 1", "DELETE FROM publication_intents",
                          "TRUNCATE publication_intents CASCADE", "UPDATE audit_events SET code = 'x'",
                          "DELETE FROM audit_events", "TRUNCATE audit_events"):
            with self.subTest(statement=statement):
                self.assert_refused(statement)
        self.assertEqual(self.scalar("SELECT count(*) FROM publication_intents"), 1)


class DatabaseBoundaryTests(unittest.TestCase):
    def test_configuration_is_bounded_and_carries_no_host(self):
        for arguments in (("relative/path", "db"), ("/run/x", "bad name"), ("/run/x", "d" * 64),
                          ("/run/x", "db; drop"), ("/run/x", "")):
            with self.subTest(arguments=arguments):
                with self.assertRaises(PersistenceRefusal) as caught:
                    Database(*arguments)
                self.assertEqual(caught.exception.code, "database_config_invalid")

    def test_a_closed_environment_still_finds_the_test_server_socket(self):
        # The Elenchus runner starts checks without FIAT_TEST_POSTGRES.
        with mock.patch.dict(os.environ):
            os.environ.pop(ENVIRONMENT, None)
            try:
                found = socket_directory()
            except PersistenceRefusal as error:
                found = error.code
        self.assertEqual(found, "/run/fiat-postgres")
        with mock.patch.dict(os.environ, {ENVIRONMENT: "relative/socket"}):
            with self.assertRaises(PersistenceRefusal) as caught:
                socket_directory()
        self.assertEqual(caught.exception.code, "database_unavailable")

    def test_unreachable_server_is_a_fixed_code_with_no_library_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Database(temporary, "nothing_here")
            with self.assertRaises(PersistenceRefusal) as caught:
                database.transaction(lambda connection: connection.execute("SELECT 1"))
        error = caught.exception
        self.assertEqual((error.code, str(error)), ("database_unavailable", "database_unavailable"))
        self.assertIsNone(error.__cause__)
        self.assertTrue(error.__suppress_context__)


class TransactionBoundaryTests(DatabaseCase):
    def test_unexpected_failures_become_fixed_codes_and_roll_back(self):
        def fails_in_python(connection):
            connection.execute("INSERT INTO actors (actor_id, first_seen_at) VALUES (77, now())")
            raise RuntimeError("secret detail")

        def fails_in_sql(connection):
            connection.execute("INSERT INTO actors (actor_id, first_seen_at) VALUES (78, now())")
            connection.execute("SELECT 1 / 0")

        for work in (fails_in_python, fails_in_sql):
            with self.subTest(work=work.__name__):
                with self.assertRaises(PersistenceRefusal) as caught:
                    self.database.transaction(work)
                self.assertEqual(str(caught.exception), "persistence_failed")
                self.assertIsNone(caught.exception.__cause__)
                self.assertTrue(caught.exception.__suppress_context__)
        self.assertEqual(self.scalar("SELECT count(*) FROM actors WHERE actor_id IN (77, 78)"), 0)

    def test_statement_timeout_is_bounded(self):
        database = Database(self.scratch.socket, self.database.dbname, statement_timeout_ms=200)
        with self.assertRaises(PersistenceRefusal) as caught:
            database.transaction(lambda connection: connection.execute("SELECT pg_sleep(5)"))
        self.assertEqual(caught.exception.code, "database_unavailable")
