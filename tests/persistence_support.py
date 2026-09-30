"""Shared set-up for checks that need the pinned PostgreSQL 16 test server.

Each test gets its own freshly migrated scratch database, dropped afterwards.
Without a server at `FIAT_TEST_POSTGRES`, or at `/run/fiat-postgres` when that
is unset, the set-up raises, so the test errors rather than skipping: a
persistence group cannot pass without a real server.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import io
import json
import logging
import random
import threading
import unittest

from fiat_checkpoints.domain.coordination import AnnounceRequest, QuotaPolicy, RunScope
from fiat_checkpoints.domain.identities import CheckpointIdentities
from fiat_checkpoints.domain.transitions import Evidence
from fiat_checkpoints.persistence.coordinator import (
    PASS_CALLER_EVIDENCE, REFUSE_CALLER_EVIDENCE, SEAL_CALLER_EVIDENCE, Coordinator, Passed, Refused,
)
from fiat_checkpoints.persistence.migrations import migrate
from fiat_checkpoints.persistence.scratch import ScratchDatabase
from fiat_checkpoints.telemetry.logging import EventFormatter


T0 = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
SCOPE = RunScope("fiat-checkpoints", 101, "run-alpha")
OTHER_SCOPE = RunScope("fiat-checkpoints", 101, "run-beta")
ACTOR = 9001
OTHER_ACTOR = 9002
SIZE = 4096
DIGEST = "a" * 64
IDENTITIES = CheckpointIdentities("b" * 64, "c" * 64, DIGEST)
EVIDENCE = b'{"synthetic":true}'


def key(label):
    """A 16-to-128 character synthetic idempotency key."""
    return ("key-" + label).ljust(16, "x")


def request(archive=DIGEST, size=SIZE, **fields):
    return AnnounceRequest(archive, size, dict(fields))


def at(seconds):
    return T0 + timedelta(seconds=seconds)


def passed(identities=IDENTITIES, evidence=EVIDENCE):
    return Passed(identities, evidence, PASS_CALLER_EVIDENCE)


def refused(code="protocol_refused"):
    return Refused(code, REFUSE_CALLER_EVIDENCE)


class DatabaseCase(unittest.TestCase):
    """A migrated scratch database and a coordinator with seeded jitter."""

    quotas = None

    def setUp(self):
        self.scratch = ScratchDatabase()
        self.addCleanup(self.scratch.close)
        self.database = self.scratch.database
        migrate(self.database)
        self.coordinator = self.make_coordinator()

    def make_coordinator(self, **options):
        options.setdefault("quotas", self.quotas or QuotaPolicy())
        options.setdefault("random_source", random.Random(7))
        return Coordinator(self.database, **options)

    def query(self, statement, parameters=()):
        connection = self.database.connect()
        try:
            return connection.execute(statement, parameters).fetchall()
        finally:
            connection.close()

    def scalar(self, statement, parameters=()):
        rows = self.query(statement, parameters)
        return next(iter(rows[0].values()))

    def announce(self, label="one", actor=ACTOR, scope=SCOPE, now=T0, **options):
        return self.coordinator.announce(scope, actor, key(label), request(**options), now)

    def quarantined(self, label="one", actor=ACTOR, scope=SCOPE, now=T0):
        """Announce, upload and seal one candidate; return its id."""
        announced = self.announce(label, actor, scope, now)
        lease = self.coordinator.begin_upload(scope, actor, announced.candidate_id, {Evidence.RUN_GRANT}, now)
        self.coordinator.seal_upload(lease, SIZE, DIGEST, SEAL_CALLER_EVIDENCE, now)
        return announced.candidate_id

    def assert_quota_consistent(self):
        """Every counter equals the sum of the unreleased reservations it covers."""
        rows = self.query(
            "SELECT q.scope_kind, q.scope_key, q.candidates, q.reserved_bytes, q.streams, "
            "(SELECT count(*) FROM reservations r JOIN candidates c USING (candidate_id) "
            " WHERE r.kind = 'candidate' AND r.released_at IS NULL AND (q.scope_kind = 'global' "
            " OR (q.scope_kind = 'run' AND c.run_key = q.scope_key) "
            " OR (q.scope_kind = 'actor' AND c.actor_id = q.scope_key))) AS expected_candidates, "
            "(SELECT coalesce(sum(r.reserved_bytes), 0) FROM reservations r JOIN candidates c USING (candidate_id) "
            " WHERE r.kind = 'candidate' AND r.released_at IS NULL AND (q.scope_kind = 'global' "
            " OR (q.scope_kind = 'run' AND c.run_key = q.scope_key) "
            " OR (q.scope_kind = 'actor' AND c.actor_id = q.scope_key))) AS expected_bytes, "
            "(SELECT count(*) FROM reservations r JOIN candidates c USING (candidate_id) "
            " WHERE r.kind = 'stream' AND r.released_at IS NULL AND (q.scope_kind = 'global' "
            " OR (q.scope_kind = 'actor' AND c.actor_id = q.scope_key))) AS expected_streams "
            "FROM quota_usage q")
        for row in rows:
            with self.subTest(scope=row["scope_kind"]):
                self.assertEqual(row["candidates"], row["expected_candidates"])
                self.assertEqual(row["reserved_bytes"], row["expected_bytes"])
                self.assertEqual(row["streams"], row["expected_streams"])


def run_threads(count, target):
    """Start `count` threads behind one barrier; return each result or exception by index."""
    barrier = threading.Barrier(count)
    results = [None] * count

    def body(index):
        barrier.wait()
        try:
            results[index] = target(index)
        except Exception as error:
            results[index] = error

    threads = [threading.Thread(target=body, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(120)
    return results


@contextmanager
def recorded_events():
    logger = logging.getLogger("fiat_checkpoints")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(EventFormatter())
    previous = (logger.handlers[:], logger.level, logger.propagate)
    logger.handlers[:] = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    events = []
    try:
        yield events
    finally:
        logger.handlers[:], logger.level, logger.propagate = previous
        events.extend(json.loads(line) for line in stream.getvalue().splitlines())
