"""Coordinate candidates, quota reservations, fenced attempts and the outbox.

PostgreSQL here is a transactional index and work coordinator, never the
source of accepted truth. No call in this module can produce an accepted,
signed or published state: the furthest a candidate moves is `publishing`,
with one immutable publication intent for issue #2 to consume.

Every call is one transaction. A candidate row is locked before anything that
belongs to it, and quota rows are always locked global, run, actor, so two
calls cannot wait on each other in a cycle. Every completion rechecks the
current fence and lease expiry; an expired or superseded worker cannot move a
candidate. Structured events are logged only after their transaction commits.
See adr/coordinate-intake-with-fenced-leases.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import logging
import random
import threading
import uuid

from fiat_checkpoints.domain.coordination import (
    CANDIDATE_LIFETIME, DEPENDENCY_REASONS, IDEMPOTENCY_RETENTION, MAX_EVIDENCE_BYTES, TOOL_REASONS,
    AnnounceRequest, CoordinationRefusal, Lease, LeasePolicy, QuotaPolicy, RunScope,
    canonical_bytes, candidate_uuid, digest, fixed_code, idempotency_key, positive_int, require_now,
    retry_delay_ms,
)
from fiat_checkpoints.domain.identities import CheckpointIdentities
from fiat_checkpoints.domain.transitions import Evidence, State, TransitionRefused, advance


LOGGER = logging.getLogger("fiat_checkpoints")
# Until the service configures its handler, events go nowhere rather than to
# the interpreter's last-resort stderr handler.
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())
MAX_UPLOAD_ATTEMPTS = 16
MAX_VALIDATION_ATTEMPTS = 4096
# Each open upload attempt holds one stream, so at most `streams_global` exist.
MAX_STREAM_RECLAIMS = 64
# A claim that loses its job to a concurrent claim looks again this many times.
MAX_CLAIM_PASSES = 8
# Before an intent exists nothing can have reached a signer, so the service's
# own cancellation is the only cancellation there is (see the decision record).
LOCALLY_EXPIRABLE = ("announced", "uploading", "quarantined", "validating")
UPLOAD_CALLER_EVIDENCE = frozenset({Evidence.RUN_GRANT})
SEAL_CALLER_EVIDENCE = frozenset({Evidence.STREAM_COUNT_AND_HASH, Evidence.QUARANTINE_READ_BACK})
CLAIM_CALLER_EVIDENCE = frozenset({Evidence.ISOLATED_WORKER})
PASS_CALLER_EVIDENCE = frozenset({Evidence.PROTOCOL_CHECKS, Evidence.RECONSTRUCTION, Evidence.IDENTITY,
                                  Evidence.AUTHORIZATION, Evidence.DENIAL_CHECK})
REFUSE_CALLER_EVIDENCE = frozenset({Evidence.DETERMINISTIC_REFUSAL})


@dataclass(frozen=True)
class Announced:
    candidate_id: uuid.UUID
    replayed: bool
    expires_at: datetime


@dataclass(frozen=True)
class CandidateView:
    candidate_id: uuid.UUID
    state: State
    archive_sha256: str
    declared_size: int
    expires_at: datetime
    retry_reason: str | None
    terminal_code: str | None


@dataclass(frozen=True)
class ValidationClaim:
    lease: Lease
    archive_sha256: str
    declared_size: int
    input_attempt: int


@dataclass(frozen=True)
class Passed:
    identities: CheckpointIdentities
    evidence: bytes
    caller_evidence: frozenset


@dataclass(frozen=True)
class Refused:
    code: str
    caller_evidence: frozenset


@dataclass(frozen=True)
class Unavailable:
    reason: str


@dataclass(frozen=True)
class IntentRecorded:
    intent_id: uuid.UUID
    replayed: bool


@dataclass(frozen=True)
class RetryScheduled:
    delay_ms: int
    held: bool


class _Events:
    """Events gathered inside a transaction and emitted after it commits.

    A transaction that ends in a refusal rolls back, so only the events that
    describe the refusal itself (`refusal=True`) are emitted for it.
    """

    def __init__(self):
        self.items = []

    def add(self, name, level=logging.INFO, refusal=False, **fields):
        self.items.append((level, name, refusal, fields))

    def emit(self, refused=False):
        for level, name, refusal, fields in self.items:
            if refusal or not refused:
                LOGGER.log(level, name, extra={"event": name, **fields})


def _age_ms(now, then):
    return max(0, int((now - then) / timedelta(milliseconds=1)))


class Coordinator:
    """The persistence operations Steps 4 to 6 call.

    Each method takes the service clock's `now` as an aware UTC datetime so
    that expiry and lease decisions have one time source. A refusal is a
    `CoordinationRefusal` with a fixed code and nothing else.
    """

    def __init__(self, database, *, quotas=None, leases=None, random_source=None):
        self.database = database
        self.quotas = QuotaPolicy() if quotas is None else quotas
        self.leases = LeasePolicy() if leases is None else leases
        if not isinstance(self.quotas, QuotaPolicy) or not isinstance(self.leases, LeasePolicy):
            raise CoordinationRefusal("request_invalid")
        self._random = random.SystemRandom() if random_source is None else random_source
        self._random_lock = threading.Lock()

    def _run(self, work):
        events = _Events()

        def attempt(connection):
            # A deadlock reruns the whole call; the rolled-back attempt's events
            # describe nothing that committed.
            events.items.clear()
            return work(connection, events)

        try:
            result = self.database.transaction(attempt)
        except CoordinationRefusal:
            events.emit(refused=True)
            raise
        events.emit()
        if isinstance(result, CoordinationRefusal):
            # Work that must commit before it refuses returns the refusal instead.
            raise result
        return result

    # Candidate rows ---------------------------------------------------------

    @staticmethod
    def _lock_candidate(connection, candidate_id):
        return connection.execute(
            "SELECT * FROM candidates WHERE candidate_id = %s FOR UPDATE", (candidate_id,)).fetchone()

    @staticmethod
    def _lock_scoped(connection, scope, actor_id, candidate_id):
        """Lock one candidate the caller may see; anything else is `not_found`."""
        row = connection.execute(
            "SELECT c.* FROM candidates c JOIN run_registrations r USING (run_key) "
            "WHERE c.candidate_id = %s AND c.actor_id = %s AND r.service_id = %s "
            "AND r.repository_id = %s AND r.run_id = %s FOR UPDATE OF c",
            (candidate_id, actor_id, scope.service_id, scope.repository_id, scope.run_id)).fetchone()
        if row is None:
            raise CoordinationRefusal("not_found")
        return row

    @staticmethod
    def _update(connection, row, now, **changes):
        """Compare-and-swap one candidate row on its version; return the new row."""
        columns = sorted(changes)
        assignments = "".join(f", {name} = %({name})s" for name in columns)
        updated = connection.execute(
            "UPDATE candidates SET version = version + 1, updated_at = %(now)s" + assignments
            + " WHERE candidate_id = %(candidate_id)s AND version = %(version)s RETURNING *",
            {**changes, "now": now, "candidate_id": row["candidate_id"], "version": row["version"]},
        ).fetchone()
        if updated is None:
            raise CoordinationRefusal("state_conflict")
        return updated

    def _transition(self, connection, events, row, target, evidence, now, event, **changes):
        try:
            advance(State(row["state"]), target, frozenset(evidence))
        except TransitionRefused as error:
            raise CoordinationRefusal(error.code) from None
        updated = self._update(connection, row, now, state=target.value, **changes)
        connection.execute(
            "INSERT INTO audit_events (candidate_id, event, from_state, to_state, fence, code, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (row["candidate_id"], event, row["state"], target.value, updated["fence"],
             changes.get("terminal_code") or changes.get("retry_reason"), now))
        events.add(event, candidate=str(row["candidate_id"]), from_state=row["state"], to_state=target.value,
                   fence=updated["fence"], age_ms=_age_ms(now, row["updated_at"]))
        return updated

    # Quota ------------------------------------------------------------------

    def _reserve_candidate(self, connection, events, run_key, actor_id, size):
        connection.execute(
            "INSERT INTO quota_usage (scope_kind, scope_key) VALUES ('run', %s), ('actor', %s) "
            "ON CONFLICT DO NOTHING", (run_key, actor_id))
        quotas = self.quotas
        for scope, key, count_limit, byte_limit in (
            ("global", 0, quotas.candidates_global, quotas.bytes_global),
            ("run", run_key, quotas.candidates_per_run, quotas.bytes_per_run),
            ("actor", actor_id, quotas.candidates_per_actor, quotas.bytes_per_actor),
        ):
            granted = connection.execute(
                "UPDATE quota_usage SET candidates = candidates + 1, reserved_bytes = reserved_bytes + %s "
                "WHERE scope_kind = %s AND scope_key = %s AND candidates + 1 <= %s "
                "AND reserved_bytes + %s <= %s RETURNING candidates",
                (size, scope, key, count_limit, size, byte_limit)).fetchone()
            if granted is None:
                events.add("quota-refused", logging.WARNING, True, scope=scope, kind="candidate")
                return CoordinationRefusal("quota_exceeded")
        return None

    def _reclaim_expired_streams(self, connection, events, now):
        """Abandon upload attempts whose lease has expired and release their streams.

        A stream counts against the concurrency ceilings only while its lease
        lives. Otherwise an upload that stopped without sealing kept its slot
        until the same candidate began again or reached its 24-hour deadline,
        and abandoned uploads refused every other stream. A candidate another
        call holds is skipped rather than waited on, so the candidate-first
        lock order holds; its attempt is still open after the lock only if
        nothing sealed or replaced it meanwhile.
        """
        expired = connection.execute(
            "SELECT candidate_id FROM upload_attempts WHERE state = 'open' AND lease_expires_at <= %s "
            "ORDER BY lease_expires_at LIMIT %s", (now, MAX_STREAM_RECLAIMS)).fetchall()
        for item in expired:
            row = connection.execute("SELECT * FROM candidates WHERE candidate_id = %s FOR UPDATE SKIP LOCKED",
                                     (item["candidate_id"],)).fetchone()
            if row is None:
                continue
            for attempt in connection.execute(
                    "UPDATE upload_attempts SET state = 'abandoned', updated_at = %s WHERE candidate_id = %s "
                    "AND state = 'open' AND lease_expires_at <= %s RETURNING attempt_number, fence",
                    (now, row["candidate_id"], now)).fetchall():
                self._release(connection, events, row, now, kinds=("stream",), attempt=attempt["attempt_number"])
                events.add("lease-expired", logging.WARNING, candidate=str(row["candidate_id"]), kind="upload",
                           attempt=attempt["attempt_number"], fence=attempt["fence"])

    def _reserve_stream(self, connection, events, actor_id):
        for scope, key, limit in (("global", 0, self.quotas.streams_global),
                                  ("actor", actor_id, self.quotas.streams_per_actor)):
            granted = connection.execute(
                "UPDATE quota_usage SET streams = streams + 1 WHERE scope_kind = %s AND scope_key = %s "
                "AND streams + 1 <= %s RETURNING streams", (scope, key, limit)).fetchone()
            if granted is None:
                events.add("quota-refused", logging.WARNING, True, scope=scope, kind="stream")
                return CoordinationRefusal("quota_exceeded")
        return None

    @staticmethod
    def _release(connection, events, row, now, *, kinds=("candidate", "stream"), attempt=None):
        """Release unreleased reservations of `kinds`; a second release finds none."""
        released = connection.execute(
            "UPDATE reservations SET released_at = %s WHERE candidate_id = %s AND released_at IS NULL "
            "AND kind = ANY(%s) AND (%s::integer IS NULL OR attempt_number = %s) "
            "RETURNING kind, reserved_bytes",
            (now, row["candidate_id"], list(kinds), attempt, attempt)).fetchall()
        candidates = sum(1 for item in released if item["kind"] == "candidate")
        size = sum(item["reserved_bytes"] for item in released if item["kind"] == "candidate")
        streams = sum(1 for item in released if item["kind"] == "stream")
        for scope, key, stream_scope in (("global", 0, True), ("run", row["run_key"], False),
                                         ("actor", row["actor_id"], True)):
            stream_count = streams if stream_scope else 0
            if candidates or stream_count:
                connection.execute(
                    "UPDATE quota_usage SET candidates = candidates - %s, reserved_bytes = reserved_bytes - %s, "
                    "streams = streams - %s WHERE scope_kind = %s AND scope_key = %s",
                    (candidates, size, stream_count, scope, key))
        if released:
            events.add("quota-released", candidate=str(row["candidate_id"]), count=len(released))

    # Announce and read ------------------------------------------------------

    def announce(self, scope, actor_id, key, request, now):
        """Create one candidate and reserve its quota, or replay the same key's result.

        The fingerprint binds operation, actor, scope and every canonical body
        field. The same key with any other fingerprint is `idempotency_conflict`.
        """
        if not isinstance(scope, RunScope) or not isinstance(request, AnnounceRequest):
            raise CoordinationRefusal("request_invalid")
        positive_int(actor_id)
        idempotency_key(key)
        now = require_now(now)
        fingerprint = hashlib.sha256(canonical_bytes({
            "operation": "announce", "actor_id": actor_id, "scope": scope.canonical(),
            "body": request.body()})).hexdigest()
        candidate_id = uuid.uuid4()
        expires_at = now + CANDIDATE_LIFETIME

        def work(connection, events):
            connection.execute("INSERT INTO actors (actor_id, first_seen_at) VALUES (%s, %s) "
                               "ON CONFLICT DO NOTHING", (actor_id, now))
            connection.execute(
                "INSERT INTO run_registrations (service_id, repository_id, run_id, registered_at) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
                (scope.service_id, scope.repository_id, scope.run_id, now))
            run_key = connection.execute(
                "SELECT run_key FROM run_registrations WHERE service_id = %s AND repository_id = %s "
                "AND run_id = %s", (scope.service_id, scope.repository_id, scope.run_id)).fetchone()["run_key"]
            # A mapping past its retention no longer answers for the key.
            connection.execute(
                "DELETE FROM idempotency_keys WHERE actor_id = %s AND operation = 'announce' "
                "AND idempotency_key = %s AND expires_at <= %s", (actor_id, key, now))
            claimed = connection.execute(
                "INSERT INTO idempotency_keys (actor_id, operation, idempotency_key, fingerprint, candidate_id, "
                "created_at, expires_at) VALUES (%s, 'announce', %s, %s, %s, %s, %s) "
                "ON CONFLICT DO NOTHING RETURNING candidate_id",
                (actor_id, key, fingerprint, candidate_id, now, now + IDEMPOTENCY_RETENTION)).fetchone()
            if claimed is None:
                existing = connection.execute(
                    "SELECT i.fingerprint, i.candidate_id, c.expires_at FROM idempotency_keys i "
                    "JOIN candidates c USING (candidate_id) WHERE i.actor_id = %s "
                    "AND i.operation = 'announce' AND i.idempotency_key = %s", (actor_id, key)).fetchone()
                if existing is None:
                    raise CoordinationRefusal("persistence_contention")
                if existing["fingerprint"] != fingerprint:
                    events.add("idempotency-conflict", logging.WARNING, True, kind="announce")
                    raise CoordinationRefusal("idempotency_conflict")
                events.add("announce-replayed", candidate=str(existing["candidate_id"]))
                return Announced(existing["candidate_id"], True, existing["expires_at"])
            refusal = self._reserve_candidate(connection, events, run_key, actor_id, request.declared_size)
            if refusal is not None:
                raise refusal
            connection.execute(
                "INSERT INTO candidates (candidate_id, run_key, actor_id, state, version, fence, archive_sha256, "
                "declared_size, announced_at, expires_at, updated_at) "
                "VALUES (%s, %s, %s, 'announced', 1, 0, %s, %s, %s, %s, %s)",
                (candidate_id, run_key, actor_id, request.archive_sha256, request.declared_size,
                 now, expires_at, now))
            connection.execute(
                "INSERT INTO reservations (candidate_id, kind, reserved_bytes, created_at) "
                "VALUES (%s, 'candidate', %s, %s)", (candidate_id, request.declared_size, now))
            connection.execute(
                "INSERT INTO audit_events (candidate_id, event, to_state, fence, created_at) "
                "VALUES (%s, 'candidate-announced', 'announced', 0, %s)", (candidate_id, now))
            events.add("candidate-announced", candidate=str(candidate_id), to_state="announced", fence=0)
            return Announced(candidate_id, False, expires_at)

        return self._run(work)

    def candidate(self, scope, actor_id, candidate_id):
        """Return the caller's own candidate; any other run, actor or id is `not_found`."""
        if not isinstance(scope, RunScope):
            raise CoordinationRefusal("request_invalid")
        positive_int(actor_id)
        candidate_id = candidate_uuid(candidate_id)

        def work(connection, _events):
            row = self._lock_scoped(connection, scope, actor_id, candidate_id)
            return CandidateView(row["candidate_id"], State(row["state"]), row["archive_sha256"],
                                 row["declared_size"], row["expires_at"], row["retry_reason"],
                                 row["terminal_code"])

        return self._run(work)

    # Upload attempts --------------------------------------------------------

    def begin_upload(self, scope, actor_id, candidate_id, caller_evidence, now):
        """Grant one fenced upload lease after reserving a transfer stream.

        The caller names `RUN_GRANT` after checking it; the candidate's quota
        reservation and exact declared size and digest are checked here. A
        live lease makes a second begin `upload_in_progress`; an expired one is
        abandoned and its stream released before the next attempt. Expired
        leases of other candidates give their streams back first.
        """
        if not isinstance(scope, RunScope) or frozenset(caller_evidence) != UPLOAD_CALLER_EVIDENCE:
            raise CoordinationRefusal("transition-evidence")
        positive_int(actor_id)
        candidate_id = candidate_uuid(candidate_id)
        now = require_now(now)

        def work(connection, events):
            row = self._lock_scoped(connection, scope, actor_id, candidate_id)
            if row["state"] not in ("announced", "uploading"):
                raise CoordinationRefusal("state_conflict")
            if now >= row["expires_at"]:
                raise CoordinationRefusal("candidate_expired")
            current = connection.execute(
                "SELECT * FROM upload_attempts WHERE candidate_id = %s AND state = 'open' FOR UPDATE",
                (candidate_id,)).fetchone()
            if current is not None:
                if current["lease_expires_at"] > now:
                    raise CoordinationRefusal("upload_in_progress")
                connection.execute(
                    "UPDATE upload_attempts SET state = 'abandoned', updated_at = %s "
                    "WHERE candidate_id = %s AND attempt_number = %s",
                    (now, candidate_id, current["attempt_number"]))
                self._release(connection, events, row, now, kinds=("stream",), attempt=current["attempt_number"])
                events.add("lease-expired", logging.WARNING, candidate=str(candidate_id), kind="upload",
                           attempt=current["attempt_number"], fence=current["fence"])
            count = connection.execute("SELECT count(*) AS n FROM upload_attempts WHERE candidate_id = %s",
                                       (candidate_id,)).fetchone()["n"]
            if count >= MAX_UPLOAD_ATTEMPTS:
                raise CoordinationRefusal("attempt_limit")
            reserved = connection.execute(
                "SELECT 1 FROM reservations WHERE candidate_id = %s AND kind = 'candidate' "
                "AND released_at IS NULL", (candidate_id,)).fetchone()
            if reserved is None:
                raise CoordinationRefusal("state_conflict")
            self._reclaim_expired_streams(connection, events, now)
            refusal = self._reserve_stream(connection, events, row["actor_id"])
            if refusal is not None:
                raise refusal
            attempt, fence = count + 1, row["fence"] + 1
            expires_at = now + timedelta(seconds=self.leases.upload_seconds)
            connection.execute(
                "INSERT INTO upload_attempts (candidate_id, attempt_number, fence, state, lease_expires_at, "
                "created_at, updated_at) VALUES (%s, %s, %s, 'open', %s, %s, %s)",
                (candidate_id, attempt, fence, expires_at, now, now))
            connection.execute(
                "INSERT INTO reservations (candidate_id, kind, attempt_number, reserved_bytes, created_at) "
                "VALUES (%s, 'stream', %s, 0, %s)", (candidate_id, attempt, now))
            if row["state"] == "announced":
                evidence = UPLOAD_CALLER_EVIDENCE | {Evidence.QUOTA_RESERVED, Evidence.EXACT_SIZE_AND_DIGEST}
                self._transition(connection, events, row, State.UPLOADING, evidence, now,
                                 "upload-started", fence=fence)
            else:
                self._update(connection, row, now, fence=fence)
            events.add("lease-granted", candidate=str(candidate_id), kind="upload", attempt=attempt, fence=fence)
            return Lease(candidate_id, "upload", attempt, fence, expires_at)

        return self._run(work)

    def seal_upload(self, lease, sealed_size, sealed_sha256, caller_evidence, now):
        """Commit the exact attempt the current lease holder streamed.

        The caller names the end-of-stream count and hash match and the sealed
        read-back after checking both; the size and digest must equal the
        declared ones. Repeating a completed seal returns the same result.
        """
        if not isinstance(lease, Lease) or lease.kind != "upload":
            raise CoordinationRefusal("lease_stale")
        if frozenset(caller_evidence) != SEAL_CALLER_EVIDENCE:
            raise CoordinationRefusal("transition-evidence")
        positive_int(sealed_size)
        digest(sealed_sha256)
        now = require_now(now)

        def work(connection, events):
            row = self._lock_candidate(connection, lease.candidate_id)
            attempt = connection.execute(
                "SELECT * FROM upload_attempts WHERE candidate_id = %s AND attempt_number = %s FOR UPDATE",
                (lease.candidate_id, lease.attempt_number)).fetchone()
            if (row is not None and attempt is not None and attempt["state"] == "sealed"
                    and attempt["fence"] == lease.fence and row["sealed_attempt"] == lease.attempt_number
                    and attempt["sealed_sha256"] == sealed_sha256 and attempt["sealed_size"] == sealed_size):
                return lease.attempt_number
            if (row is None or attempt is None or attempt["state"] != "open" or attempt["fence"] != lease.fence
                    or row["fence"] != lease.fence or attempt["lease_expires_at"] <= now):
                events.add("lease-stale-refused", logging.WARNING, True, candidate=str(lease.candidate_id),
                           kind="upload", fence=lease.fence)
                return CoordinationRefusal("lease_stale")
            if now >= row["expires_at"]:
                return CoordinationRefusal("candidate_expired")
            if sealed_size != row["declared_size"] or sealed_sha256 != row["archive_sha256"]:
                connection.execute(
                    "UPDATE upload_attempts SET state = 'failed', updated_at = %s "
                    "WHERE candidate_id = %s AND attempt_number = %s",
                    (now, lease.candidate_id, lease.attempt_number))
                self._release(connection, events, row, now, kinds=("stream",), attempt=lease.attempt_number)
                events.add("upload-integrity-refused", logging.WARNING, candidate=str(lease.candidate_id),
                           attempt=lease.attempt_number, fence=lease.fence)
                return CoordinationRefusal("upload_integrity")
            connection.execute(
                "UPDATE upload_attempts SET state = 'sealed', sealed_size = %s, sealed_sha256 = %s, updated_at = %s "
                "WHERE candidate_id = %s AND attempt_number = %s",
                (sealed_size, sealed_sha256, now, lease.candidate_id, lease.attempt_number))
            self._release(connection, events, row, now, kinds=("stream",), attempt=lease.attempt_number)
            self._transition(connection, events, row, State.QUARANTINED, SEAL_CALLER_EVIDENCE, now,
                             "upload-sealed", sealed_attempt=lease.attempt_number, retry_reason=None)
            self._enqueue(connection, events, "validate-candidate", lease.candidate_id, now)
            return lease.attempt_number

        return self._run(work)

    # Outbox -----------------------------------------------------------------

    @staticmethod
    def _enqueue(connection, events, kind, candidate_id, now):
        job = connection.execute(
            "INSERT INTO outbox_jobs (kind, candidate_id, state, available_at, created_at, updated_at) "
            "VALUES (%s, %s, 'pending', %s, %s, %s) RETURNING job_id", (kind, candidate_id, now, now, now)).fetchone()
        events.add("job-enqueued", candidate=str(candidate_id), kind=kind, job=job["job_id"])

    @staticmethod
    def _next_job(connection, kind, now):
        """Lock the next ready job's candidate, then the job, or return None.

        Every other call locks a candidate before its job. A claim that locked
        the job first could wait on a completion or sweep holding the
        candidate while that call waited on the job, a deadlock. A candidate
        another call holds is skipped; the job is read again after its
        candidate is locked, because another claim may have leased it first.
        """
        # Validation is new work, which a passed deadline blocks; a hand-off
        # job after the intent is not, and its owner decides cancellation.
        deadline = now if kind == "validate-candidate" else None
        ready = ("j.kind = %(kind)s AND ((j.state = 'pending' AND j.available_at <= %(now)s) "
                 "OR (j.state = 'leased' AND j.lease_expires_at <= %(now)s))")
        for _ in range(MAX_CLAIM_PASSES):
            found = connection.execute(
                "SELECT j.job_id FROM outbox_jobs j JOIN candidates c USING (candidate_id) WHERE " + ready
                + " AND (%(deadline)s::timestamptz IS NULL OR c.expires_at > %(deadline)s) "
                "ORDER BY j.available_at, j.job_id LIMIT 1 FOR UPDATE OF c SKIP LOCKED",
                {"kind": kind, "now": now, "deadline": deadline}).fetchone()
            if found is None:
                return None
            job = connection.execute("SELECT j.* FROM outbox_jobs j WHERE j.job_id = %(job_id)s AND " + ready
                                     + " FOR UPDATE", {"kind": kind, "now": now, "job_id": found["job_id"]}).fetchone()
            if job is not None:
                return job
        return None

    def _schedule_retry(self, connection, events, job, row, reason, now):
        attempts = job["attempts"] + 1
        held = reason in TOOL_REASONS and attempts >= self.leases.tool_retry_limit
        with self._random_lock:
            fraction = self._random.random()
        delay = 0 if held else retry_delay_ms(attempts, fraction)
        connection.execute(
            "UPDATE outbox_jobs SET state = %s, attempts = %s, available_at = %s, lease_fence = NULL, "
            "lease_expires_at = NULL, retry_reason = %s, updated_at = %s WHERE job_id = %s",
            ("held" if held else "pending", attempts, now + timedelta(milliseconds=delay), reason, now,
             job["job_id"]))
        self._update(connection, row, now, retry_reason=reason)
        connection.execute(
            "INSERT INTO audit_events (candidate_id, event, from_state, to_state, fence, code, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (row["candidate_id"], "job-held" if held else "retry-scheduled", row["state"], row["state"],
             row["fence"], reason, now))
        events.add("job-held" if held else "retry-scheduled", logging.WARNING, candidate=str(row["candidate_id"]),
                   job=job["job_id"], kind=job["kind"], code=reason, delay_ms=delay, count=attempts)
        return RetryScheduled(delay, held)

    # Validation -------------------------------------------------------------

    def claim_validation(self, caller_evidence, now):
        """Lease the next ready validation job, or return None when none is ready.

        The caller names an available isolated worker; the candidate's deadline
        is checked here. A retry after an expired lease gets a higher fence and
        the same sealed input.
        """
        if frozenset(caller_evidence) != CLAIM_CALLER_EVIDENCE:
            raise CoordinationRefusal("transition-evidence")
        now = require_now(now)

        def work(connection, events):
            job = self._next_job(connection, "validate-candidate", now)
            if job is None:
                return None
            row = self._lock_candidate(connection, job["candidate_id"])
            if row["state"] not in ("quarantined", "validating") or row["sealed_attempt"] is None:
                connection.execute("UPDATE outbox_jobs SET state = 'cancelled', lease_fence = NULL, "
                                   "lease_expires_at = NULL, updated_at = %s WHERE job_id = %s",
                                   (now, job["job_id"]))
                events.add("job-cancelled", logging.WARNING, candidate=str(row["candidate_id"]),
                           job=job["job_id"], kind=job["kind"])
                return None
            if job["state"] == "leased":
                connection.execute(
                    "UPDATE validation_attempts SET state = 'abandoned', updated_at = %s "
                    "WHERE candidate_id = %s AND state = 'running'", (now, row["candidate_id"]))
                events.add("lease-expired", logging.WARNING, candidate=str(row["candidate_id"]),
                           kind="validation", job=job["job_id"], fence=job["lease_fence"])
            count = connection.execute("SELECT count(*) AS n FROM validation_attempts WHERE candidate_id = %s",
                                       (row["candidate_id"],)).fetchone()["n"]
            if count >= MAX_VALIDATION_ATTEMPTS:
                connection.execute("UPDATE outbox_jobs SET state = 'held', lease_fence = NULL, "
                                   "lease_expires_at = NULL, updated_at = %s WHERE job_id = %s",
                                   (now, job["job_id"]))
                events.add("job-held", logging.WARNING, candidate=str(row["candidate_id"]), job=job["job_id"],
                           kind=job["kind"], code="attempt_limit")
                return None
            attempt, fence = count + 1, row["fence"] + 1
            expires_at = now + timedelta(seconds=self.leases.validation_seconds)
            connection.execute(
                "INSERT INTO validation_attempts (candidate_id, attempt_number, fence, job_id, input_attempt, "
                "state, lease_expires_at, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, 'running', %s, %s, %s)",
                (row["candidate_id"], attempt, fence, job["job_id"], row["sealed_attempt"], expires_at, now, now))
            connection.execute(
                "UPDATE outbox_jobs SET state = 'leased', lease_fence = %s, lease_expires_at = %s, updated_at = %s "
                "WHERE job_id = %s", (fence, expires_at, now, job["job_id"]))
            if row["state"] == "quarantined":
                self._transition(connection, events, row, State.VALIDATING,
                                 CLAIM_CALLER_EVIDENCE | {Evidence.CANDIDATE_UNEXPIRED}, now,
                                 "validation-started", fence=fence)
            else:
                self._update(connection, row, now, fence=fence)
            events.add("lease-granted", candidate=str(row["candidate_id"]), kind="validation", attempt=attempt,
                       fence=fence, job=job["job_id"])
            return ValidationClaim(Lease(row["candidate_id"], "validation", attempt, fence, expires_at,
                                         job["job_id"]),
                                   row["archive_sha256"], row["declared_size"], row["sealed_attempt"])

        return self._run(work)

    def complete_validation(self, lease, outcome, now):
        """Record one validation outcome, only for the current unexpired lease.

        `Passed` persists the immutable publication intent and moves the
        candidate to `publishing`; `Refused` rejects it and releases its quota;
        `Unavailable` keeps the phase, records the fixed reason and schedules a
        retry. Repeating a recorded pass with the same lease and evidence
        returns the same intent.
        """
        if not isinstance(lease, Lease) or lease.kind != "validation" or lease.job_id is None:
            raise CoordinationRefusal("lease_stale")
        if isinstance(outcome, Passed):
            if (frozenset(outcome.caller_evidence) != PASS_CALLER_EVIDENCE
                    or not isinstance(outcome.identities, CheckpointIdentities)):
                raise CoordinationRefusal("transition-evidence")
            if type(outcome.evidence) is not bytes or not 1 <= len(outcome.evidence) <= MAX_EVIDENCE_BYTES:
                raise CoordinationRefusal("request_invalid")
            evidence_sha256 = hashlib.sha256(outcome.evidence).hexdigest()
        elif isinstance(outcome, Refused):
            if frozenset(outcome.caller_evidence) != REFUSE_CALLER_EVIDENCE:
                raise CoordinationRefusal("transition-evidence")
            fixed_code(outcome.code)
        elif isinstance(outcome, Unavailable):
            if outcome.reason not in DEPENDENCY_REASONS | TOOL_REASONS:
                raise CoordinationRefusal("request_invalid")
        else:
            raise CoordinationRefusal("request_invalid")
        now = require_now(now)

        def work(connection, events):
            row = self._lock_candidate(connection, lease.candidate_id)
            if row is None:
                return CoordinationRefusal("lease_stale")
            if isinstance(outcome, Passed):
                if outcome.identities.archive_sha256 != row["archive_sha256"]:
                    # Checked before the replay match and before any write: a pass for
                    # other bytes never reads as recorded, and the lease can still
                    # report a refusal or an outage.
                    return CoordinationRefusal("identity_mismatch")
                existing = connection.execute(
                    "SELECT intent_id, fence, validation_attempt, evidence_sha256, snapshot_id, "
                    "controller_manifest_sha256 FROM publication_intents WHERE candidate_id = %s",
                    (lease.candidate_id,)).fetchone()
                if (existing is not None and existing["fence"] == lease.fence
                        and existing["validation_attempt"] == lease.attempt_number
                        and existing["evidence_sha256"] == evidence_sha256
                        and existing["snapshot_id"] == outcome.identities.snapshot_id
                        and existing["controller_manifest_sha256"]
                        == outcome.identities.controller_manifest_sha256):
                    return IntentRecorded(existing["intent_id"], True)
            attempt = connection.execute(
                "SELECT * FROM validation_attempts WHERE candidate_id = %s AND attempt_number = %s FOR UPDATE",
                (lease.candidate_id, lease.attempt_number)).fetchone()
            job = connection.execute("SELECT * FROM outbox_jobs WHERE job_id = %s FOR UPDATE",
                                     (lease.job_id,)).fetchone()
            if (attempt is None or job is None or attempt["state"] != "running" or attempt["fence"] != lease.fence
                    or row["fence"] != lease.fence or row["state"] != "validating"
                    or job["state"] != "leased" or job["lease_fence"] != lease.fence
                    or job["candidate_id"] != lease.candidate_id or attempt["lease_expires_at"] <= now):
                events.add("lease-stale-refused", logging.WARNING, True, candidate=str(lease.candidate_id),
                           kind="validation", fence=lease.fence)
                return CoordinationRefusal("lease_stale")
            if now >= row["expires_at"]:
                return CoordinationRefusal("candidate_expired")
            if isinstance(outcome, Unavailable):
                connection.execute("UPDATE validation_attempts SET state = 'retry', updated_at = %s "
                                   "WHERE candidate_id = %s AND attempt_number = %s",
                                   (now, lease.candidate_id, lease.attempt_number))
                return self._schedule_retry(connection, events, job, row, outcome.reason, now)
            connection.execute("UPDATE outbox_jobs SET state = 'done', lease_fence = NULL, lease_expires_at = NULL, "
                               "retry_reason = NULL, updated_at = %s WHERE job_id = %s", (now, lease.job_id))
            if isinstance(outcome, Refused):
                connection.execute("UPDATE validation_attempts SET state = 'refused', updated_at = %s "
                                   "WHERE candidate_id = %s AND attempt_number = %s",
                                   (now, lease.candidate_id, lease.attempt_number))
                # Validation runs before any signer call, so no signer authorization exists.
                self._transition(connection, events, row, State.REJECTED,
                                 REFUSE_CALLER_EVIDENCE | {Evidence.NO_SIGNER_AUTHORIZATION}, now,
                                 "candidate-rejected", terminal_code=outcome.code, retry_reason=None)
                self._release(connection, events, row, now)
                return None
            intent_id = uuid.uuid4()
            connection.execute(
                "INSERT INTO publication_intents (intent_id, candidate_id, validation_attempt, fence, archive_sha256, "
                "snapshot_id, controller_manifest_sha256, evidence, evidence_sha256, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (intent_id, lease.candidate_id, lease.attempt_number, lease.fence, row["archive_sha256"],
                 outcome.identities.snapshot_id, outcome.identities.controller_manifest_sha256,
                 outcome.evidence, evidence_sha256, now))
            connection.execute("UPDATE validation_attempts SET state = 'passed', updated_at = %s "
                               "WHERE candidate_id = %s AND attempt_number = %s",
                               (now, lease.candidate_id, lease.attempt_number))
            self._transition(connection, events, row, State.PUBLISHING, PASS_CALLER_EVIDENCE, now,
                             "intent-recorded", retry_reason=None)
            self._enqueue(connection, events, "publish-intent", lease.candidate_id, now)
            return IntentRecorded(intent_id, False)

        return self._run(work)

    # Publication hand-off jobs ----------------------------------------------

    def claim_job(self, kind, now):
        """Lease the next ready hand-off job of `kind` with a new candidate fence."""
        if kind != "publish-intent":
            raise CoordinationRefusal("request_invalid")
        now = require_now(now)

        def work(connection, events):
            job = self._next_job(connection, kind, now)
            if job is None:
                return None
            row = self._lock_candidate(connection, job["candidate_id"])
            if job["state"] == "leased":
                events.add("lease-expired", logging.WARNING, candidate=str(row["candidate_id"]), kind=kind,
                           job=job["job_id"], fence=job["lease_fence"])
            fence = row["fence"] + 1
            expires_at = now + timedelta(seconds=self.leases.job_seconds)
            connection.execute(
                "UPDATE outbox_jobs SET state = 'leased', lease_fence = %s, lease_expires_at = %s, updated_at = %s "
                "WHERE job_id = %s", (fence, expires_at, now, job["job_id"]))
            self._update(connection, row, now, fence=fence)
            events.add("lease-granted", candidate=str(row["candidate_id"]), kind=kind, job=job["job_id"],
                       fence=fence)
            return Lease(row["candidate_id"], kind, job["attempts"] + 1, fence, expires_at, job["job_id"])

        return self._run(work)

    def _lock_job_lease(self, connection, events, lease, now):
        row = self._lock_candidate(connection, lease.candidate_id)
        job = connection.execute("SELECT * FROM outbox_jobs WHERE job_id = %s FOR UPDATE",
                                 (lease.job_id,)).fetchone()
        if (row is None or job is None or job["state"] != "leased" or job["lease_fence"] != lease.fence
                or row["fence"] != lease.fence or job["kind"] != lease.kind
                or job["candidate_id"] != lease.candidate_id or job["lease_expires_at"] <= now):
            events.add("lease-stale-refused", logging.WARNING, True, candidate=str(lease.candidate_id), kind=lease.kind,
                       fence=lease.fence)
            return None, None
        return row, job

    def complete_job(self, lease, now):
        """Mark a hand-off job done for the current unexpired lease only."""
        if not isinstance(lease, Lease) or lease.kind != "publish-intent" or lease.job_id is None:
            raise CoordinationRefusal("lease_stale")
        now = require_now(now)

        def work(connection, events):
            row, job = self._lock_job_lease(connection, events, lease, now)
            if row is None:
                return CoordinationRefusal("lease_stale")
            connection.execute("UPDATE outbox_jobs SET state = 'done', lease_fence = NULL, lease_expires_at = NULL, "
                               "retry_reason = NULL, updated_at = %s WHERE job_id = %s", (now, job["job_id"]))
            events.add("job-done", candidate=str(row["candidate_id"]), kind=job["kind"], job=job["job_id"],
                       fence=lease.fence)
            return None

        return self._run(work)

    def retry_job(self, lease, reason, now):
        """Return a hand-off job to the queue after a fixed dependency or tool reason."""
        if not isinstance(lease, Lease) or lease.kind != "publish-intent" or lease.job_id is None:
            raise CoordinationRefusal("lease_stale")
        if reason not in DEPENDENCY_REASONS | TOOL_REASONS:
            raise CoordinationRefusal("request_invalid")
        now = require_now(now)

        def work(connection, events):
            row, job = self._lock_job_lease(connection, events, lease, now)
            if row is None:
                return CoordinationRefusal("lease_stale")
            return self._schedule_retry(connection, events, job, row, reason, now)

        return self._run(work)

    # Expiry and retention ---------------------------------------------------

    def expire_due(self, now, limit=100):
        """Expire candidates past their deadline that no intent has reached.

        Their leases end, streams and quota are released and live jobs are
        cancelled. A candidate with a publication intent is left for the
        publication owner, whose journal decides cancellation (issue #2).
        """
        now = require_now(now)
        positive_int(limit, 1000)

        def work(connection, events):
            rows = connection.execute(
                "SELECT * FROM candidates WHERE state = ANY(%s) AND expires_at <= %s "
                "ORDER BY expires_at LIMIT %s FOR UPDATE SKIP LOCKED",
                (list(LOCALLY_EXPIRABLE), now, limit)).fetchall()
            for row in rows:
                connection.execute("UPDATE upload_attempts SET state = 'abandoned', updated_at = %s "
                                   "WHERE candidate_id = %s AND state = 'open'", (now, row["candidate_id"]))
                connection.execute("UPDATE validation_attempts SET state = 'abandoned', updated_at = %s "
                                   "WHERE candidate_id = %s AND state = 'running'", (now, row["candidate_id"]))
                connection.execute(
                    "UPDATE outbox_jobs SET state = 'cancelled', lease_fence = NULL, lease_expires_at = NULL, "
                    "updated_at = %s WHERE candidate_id = %s AND state IN ('pending', 'leased', 'held')",
                    (now, row["candidate_id"]))
                self._transition(connection, events, row, State.EXPIRED,
                                 {Evidence.DEADLINE_ELAPSED, Evidence.CANCELLATION_WON}, now,
                                 "candidate-expired", terminal_code="candidate_expired", retry_reason=None,
                                 fence=row["fence"] + 1)
                self._release(connection, events, row, now)
            return len(rows)

        return self._run(work)

    def sweep_idempotency(self, now, limit=1000):
        """Delete idempotency mappings whose retention has elapsed."""
        now = require_now(now)
        positive_int(limit, 10_000)

        def work(connection, events):
            removed = connection.execute(
                "DELETE FROM idempotency_keys WHERE ctid IN (SELECT ctid FROM idempotency_keys "
                "WHERE expires_at <= %s LIMIT %s FOR UPDATE SKIP LOCKED)", (now, limit)).rowcount
            if removed:
                events.add("idempotency-swept", count=removed)
            return removed

        return self._run(work)

    def usage(self):
        """Global outstanding candidates, reserved bytes and streams, with no actor or run labels."""
        def work(connection, _events):
            row = connection.execute("SELECT candidates, reserved_bytes, streams FROM quota_usage "
                                     "WHERE scope_kind = 'global' AND scope_key = 0").fetchone()
            return dict(row)

        return self._run(work)
