"""Crashes and restarts: killed connections, dropped state and stale workers after a restart."""

import threading
import time
import unittest

from fiat_checkpoints.domain.coordination import CoordinationRefusal
from fiat_checkpoints.domain.transitions import Evidence
from fiat_checkpoints.persistence import restart
from fiat_checkpoints.persistence.coordinator import SEAL_CALLER_EVIDENCE
from fiat_checkpoints.persistence.migrations import migrate
from tests.persistence_support import ACTOR, DIGEST, SCOPE, SIZE, T0, DatabaseCase, at, key, passed, request


WORKER = {Evidence.ISOLATED_WORKER}


class RestartScenarioTests(unittest.TestCase):
    def test_every_restart_observation_holds(self):
        observations = restart.observe()
        self.assertEqual(set(observations), {
            "first-migration", "crash-mid-write-rolls-back", "restart-migration-no-op",
            "live-lease-not-reclaimed", "reclaimed-with-higher-fence", "stale-validation-refused",
            "current-worker-records-intent", "stale-upload-refused", "one-intent-from-current-fence",
            "nothing-accepted", "expiry-releases-restarted-work"})
        self.assertEqual([name for name, held in observations.items() if not held], [])

    def test_an_unobservable_scenario_is_false_not_an_error(self):
        original = restart.ScratchDatabase

        def unavailable():
            raise CoordinationRefusal("database_unavailable")

        restart.ScratchDatabase = unavailable
        try:
            self.assertIs(restart.holds(), False)
        finally:
            restart.ScratchDatabase = original


class CrashTests(DatabaseCase):
    def blocked_then_killed(self, call, lock_statement, parameters):
        """Hold a row lock, start `call`, terminate its blocked backend, return its refusal code."""
        holder = self.database.connect()
        admin = self.scratch.admin.connect()
        outcome = {}
        try:
            holder.execute("BEGIN")
            holder.execute(lock_statement, parameters)

            def body():
                try:
                    outcome["result"] = call()
                except CoordinationRefusal as error:
                    outcome["code"] = error.code

            thread = threading.Thread(target=body)
            thread.start()
            killed, deadline = False, time.monotonic() + 30
            while not killed and time.monotonic() < deadline:
                killed = any(row["killed"] for row in admin.execute(
                    "SELECT pg_terminate_backend(pid) AS killed FROM pg_stat_activity WHERE datname = %s "
                    "AND wait_event_type = 'Lock' AND pid <> %s", (self.database.dbname, holder.info.backend_pid)))
                time.sleep(0.02)
            holder.execute("ROLLBACK")
            thread.join(60)
        finally:
            holder.close()
            admin.close()
        self.assertTrue(killed)
        return outcome.get("code")

    def test_announce_killed_mid_transaction_leaves_no_candidate_key_or_quota(self):
        self.announce(label="first")
        code = self.blocked_then_killed(
            lambda: self.coordinator.announce(SCOPE, ACTOR, key("second"), request(archive="d" * 64), T0),
            "SELECT 1 FROM quota_usage WHERE scope_kind = 'global' FOR UPDATE", ())
        self.assertEqual(code, "database_unavailable")
        self.assertEqual(self.scalar("SELECT count(*) FROM candidates"), 1)
        self.assertEqual(self.scalar("SELECT count(*) FROM idempotency_keys"), 1)
        self.assert_quota_consistent()
        # The client retries the same key after the crash and gets one candidate.
        retried = self.coordinator.announce(SCOPE, ACTOR, key("second"), request(archive="d" * 64), T0)
        self.assertFalse(retried.replayed)
        self.assertEqual(self.scalar("SELECT count(*) FROM candidates"), 2)

    def test_seal_killed_mid_transaction_can_be_retried_by_the_same_lease(self):
        candidate = self.announce().candidate_id
        lease = self.coordinator.begin_upload(SCOPE, ACTOR, candidate, {Evidence.RUN_GRANT}, T0)
        code = self.blocked_then_killed(
            lambda: self.coordinator.seal_upload(lease, SIZE, DIGEST, SEAL_CALLER_EVIDENCE, at(1)),
            "SELECT 1 FROM candidates WHERE candidate_id = %s FOR UPDATE", (candidate,))
        self.assertEqual(code, "database_unavailable")
        self.assertEqual(self.scalar("SELECT state FROM candidates"), "uploading")
        self.assertEqual(self.scalar("SELECT count(*) FROM outbox_jobs"), 0)
        self.assertEqual(self.coordinator.seal_upload(lease, SIZE, DIGEST, SEAL_CALLER_EVIDENCE, at(2)), 1)
        self.assertEqual(self.scalar("SELECT count(*) FROM outbox_jobs"), 1)

    def test_a_crashed_validator_is_replaced_only_after_its_lease_expires(self):
        self.quarantined()
        crashed = self.coordinator.claim_validation(WORKER, T0)
        restarted = self.make_coordinator()
        migrate(self.database)
        self.assertIsNone(restarted.claim_validation(WORKER, at(899)))
        replacement = restarted.claim_validation(WORKER, at(900))
        self.assertEqual(replacement.lease.fence, crashed.lease.fence + 1)
        self.assertEqual(self.scalar("SELECT state FROM validation_attempts WHERE attempt_number = 1"), "abandoned")
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_validation(crashed.lease, passed(), at(901))
        self.assertEqual(caught.exception.code, "lease_stale")
        restarted.complete_validation(replacement.lease, passed(), at(902))
        self.assertEqual(self.query("SELECT fence FROM publication_intents"), [{"fence": replacement.lease.fence}])

    def test_losing_every_lease_and_job_row_never_manufactures_progress(self):
        self.quarantined()
        self.coordinator.claim_validation(WORKER, T0)
        connection = self.database.connect()
        try:
            connection.execute("DELETE FROM validation_attempts")
            connection.execute("DELETE FROM outbox_jobs")
        finally:
            connection.close()
        self.assertIsNone(self.coordinator.claim_validation(WORKER, at(10_000)))
        self.assertEqual(self.coordinator.expire_due(at(86_400)), 1)
        self.assertEqual(self.scalar("SELECT state FROM candidates"), "expired")
        self.assertEqual(self.scalar("SELECT count(*) FROM publication_intents"), 0)
        self.assert_quota_consistent()
