"""A restart and crash scenario against a scratch database, for the design gate.

It kills a worker's connection while that worker is writing an intent, drops
every in-memory object as a restarted service would, reruns the migrations,
and lets a stale upload and a stale validation worker try to finish. Each
observation is a boolean; the scenario holds only if every one is true.
"""

from datetime import datetime, timedelta, timezone
import threading
import time

from fiat_checkpoints.domain.coordination import AnnounceRequest, CoordinationRefusal, RunScope
from fiat_checkpoints.domain.identities import CheckpointIdentities
from fiat_checkpoints.domain.transitions import Evidence
from fiat_checkpoints.persistence.coordinator import (
    PASS_CALLER_EVIDENCE, SEAL_CALLER_EVIDENCE, Coordinator, IntentRecorded, Passed,
)
from fiat_checkpoints.persistence.database import Database
from fiat_checkpoints.persistence.migrations import load_migrations, migrate
from fiat_checkpoints.persistence.scratch import ScratchDatabase


T0 = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
SCOPE = RunScope("fiat-checkpoints", 1, "restart-scenario")
DIGEST = "1" * 64
SIZE = 2048
IDENTITIES = CheckpointIdentities("2" * 64, "3" * 64, DIGEST)
EVIDENCE = b'{"synthetic":"restart-scenario"}'


def _at(seconds):
    return T0 + timedelta(seconds=seconds)


def _refusal(call):
    try:
        call()
    except CoordinationRefusal as error:
        return error.code
    return None


def _count(database, statement, parameters=()):
    connection = database.connect()
    try:
        return next(iter(connection.execute(statement, parameters).fetchone().values()))
    finally:
        connection.close()


def _crash_during_completion(scratch, coordinator, lease):
    """Block the completion on the candidate row lock, then terminate its backend."""
    holder = scratch.database.connect()
    admin = scratch.admin.connect()
    outcome = {}
    try:
        holder.execute("BEGIN")
        holder.execute("SELECT 1 FROM candidates WHERE candidate_id = %s FOR UPDATE", (lease.candidate_id,))

        def complete():
            outcome["code"] = _refusal(lambda: coordinator.complete_validation(
                lease, Passed(IDENTITIES, EVIDENCE, PASS_CALLER_EVIDENCE), _at(10)))

        worker = threading.Thread(target=complete)
        worker.start()
        killed = False
        deadline = time.monotonic() + 30
        while not killed and time.monotonic() < deadline:
            killed = any(row["killed"] for row in admin.execute(
                "SELECT pg_terminate_backend(pid) AS killed FROM pg_stat_activity "
                "WHERE datname = %s AND wait_event_type = 'Lock' AND pid <> %s",
                (scratch.name, holder.info.backend_pid)))
            time.sleep(0.02)
        holder.execute("ROLLBACK")
        worker.join(60)
        return killed and not worker.is_alive() and outcome.get("code") == "database_unavailable"
    finally:
        holder.close()
        admin.close()


def observe():
    """Run the scenario once and return each named observation."""
    observations = {}
    with ScratchDatabase() as scratch:
        shipped = tuple(item.version for item in load_migrations())
        observations["first-migration"] = migrate(scratch.database) == shipped
        before = Coordinator(scratch.database)
        uploading = before.announce(SCOPE, 11, "restart-upload-key", AnnounceRequest(DIGEST, SIZE, {}), T0)
        stale_upload = before.begin_upload(SCOPE, 11, uploading.candidate_id, {Evidence.RUN_GRANT}, T0)
        validating = before.announce(SCOPE, 12, "restart-validate-key", AnnounceRequest(DIGEST, SIZE, {}), T0)
        lease = before.begin_upload(SCOPE, 12, validating.candidate_id, {Evidence.RUN_GRANT}, T0)
        before.seal_upload(lease, SIZE, DIGEST, SEAL_CALLER_EVIDENCE, _at(1))
        stale = before.claim_validation({Evidence.ISOLATED_WORKER}, _at(2)).lease
        observations["crash-mid-write-rolls-back"] = (
            _crash_during_completion(scratch, before, stale)
            and _count(scratch.database, "SELECT count(*) FROM publication_intents") == 0)
        del before

        # A restarted service: new connection settings, objects and migration run.
        database = Database(scratch.socket, scratch.name)
        after = Coordinator(database)
        observations["restart-migration-no-op"] = migrate(database) == ()
        observations["live-lease-not-reclaimed"] = after.claim_validation({Evidence.ISOLATED_WORKER}, _at(11)) is None
        current = after.claim_validation({Evidence.ISOLATED_WORKER}, _at(2 + 900))
        observations["reclaimed-with-higher-fence"] = current is not None and current.lease.fence > stale.fence
        observations["stale-validation-refused"] = _refusal(lambda: after.complete_validation(
            stale, Passed(IDENTITIES, EVIDENCE, PASS_CALLER_EVIDENCE), _at(903))) == "lease_stale"
        recorded = after.complete_validation(current.lease, Passed(IDENTITIES, EVIDENCE, PASS_CALLER_EVIDENCE),
                                             _at(904))
        observations["current-worker-records-intent"] = isinstance(recorded, IntentRecorded)
        observations["stale-upload-refused"] = _refusal(lambda: after.seal_upload(
            stale_upload, SIZE, DIGEST, SEAL_CALLER_EVIDENCE, _at(1800))) == "lease_stale"
        fresh = after.begin_upload(SCOPE, 11, uploading.candidate_id, {Evidence.RUN_GRANT}, _at(1800))
        after.seal_upload(fresh, SIZE, DIGEST, SEAL_CALLER_EVIDENCE, _at(1801))
        observations["one-intent-from-current-fence"] = _count(
            database, "SELECT count(*) FROM publication_intents WHERE fence = %s AND candidate_id = %s",
            (current.lease.fence, validating.candidate_id)) == 1 and _count(
            database, "SELECT count(*) FROM publication_intents") == 1
        observations["nothing-accepted"] = _count(
            database, "SELECT count(*) FROM candidates WHERE state NOT IN "
            "('announced', 'uploading', 'quarantined', 'validating', 'publishing', 'rejected', 'expired')") == 0
        observations["expiry-releases-restarted-work"] = (
            after.expire_due(_at(86_400)) == 1
            and after.usage() == {"candidates": 1, "reserved_bytes": SIZE, "streams": 0})
    return observations


def holds():
    """True only when every observation holds; any failure to observe is False."""
    try:
        observations = observe()
    except Exception:
        # An unobservable scenario is a failed gate, never a pass.
        return False
    return bool(observations) and all(observations.values())
