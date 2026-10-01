"""Upload capabilities, stream starts, seals and quarantine cleanup records.

A capability is issued from a candidate's bound endorsement and kept only as
its SHA-256. It names one fenced upload attempt, the declared size and carrier
digest, the endorsement and the environment, and it may start one stream
before its start expiry. Starting the stream stretches the attempt's lease to
the stream limit. The gateway seals the attempt only after it has read the
quarantine object back, and the same transaction seals that object's record.
A failed stream fails its attempt and returns the stream reservation at once.

Every call locks the candidate row first, then its attempt, then the
attempt's capability, the candidate's endorsements and the quarantine record,
as every other coordinator call locks the candidate before what belongs to it.
The sweeper's record updates lock quarantine and capability rows alone, never
a candidate or an attempt, and never a row a seal can be holding. A refusal is
a `CoordinationRefusal` with a fixed code and nothing else. See
adr/seal-uploads-in-bounded-quarantine.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
import hmac
import logging
import re
import uuid

from fiat_checkpoints.domain.coordination import (
    CANDIDATE_LIFETIME, CoordinationRefusal, Lease, RunScope, candidate_uuid, digest, positive_int, require_now,
)
from fiat_checkpoints.persistence.coordinator import MAX_UPLOAD_ATTEMPTS, Coordinator


LOGGER = logging.getLogger("fiat_checkpoints")
START_WINDOW = timedelta(minutes=15)
MAX_ISSUES = 1024
MAX_SWEEP = 1000
QUARANTINE_LIFETIME = CANDIDATE_LIFETIME
CAPABILITY_RETENTION = CANDIDATE_LIFETIME
OBJECT_KEY = re.compile(r"quarantine/([0-9a-f]{32})/([0-9]{2})-([0-9a-f]{32})")
ENVIRONMENT = re.compile(r"[a-z][a-z0-9-]{0,63}")
FAILURE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
TERMINAL = ("rejected", "expired", "revoked", "denied")


@dataclass(frozen=True)
class Issued:
    """A capability issued for one attempt; `renewed` when it replaced the attempt's earlier one."""
    lease: Lease
    start_expires_at: datetime
    declared_size: int
    archive_sha256: str
    renewed: bool


@dataclass(frozen=True)
class Completed:
    """A candidate whose attempt is already sealed: the recorded result, never a new capability."""
    candidate_id: uuid.UUID
    state: str
    attempt_number: int
    sealed_size: int
    sealed_sha256: str


@dataclass(frozen=True)
class CapabilityView:
    """What one stored capability names, read without a lock; `start` decides again under the lock."""
    capability_sha256: str
    candidate_id: uuid.UUID
    attempt_number: int
    actor_id: int
    scope: RunScope
    environment: str
    endorsement_sequence: int
    endorsement_sha256: str
    declared_size: int
    archive_sha256: str
    start_expires_at: datetime
    attempt_state: str
    stream_started: bool


@dataclass(frozen=True)
class Stream:
    """A started stream: its lease, the quarantine key it must write and what it must hash to."""
    lease: Lease
    object_key: str
    declared_size: int
    archive_sha256: str
    candidate_expires_at: datetime


@dataclass(frozen=True)
class SealedObject:
    """The recorded quarantine key, size and digest of one sealed attempt."""
    candidate_id: uuid.UUID
    attempt_number: int
    object_key: str
    sealed_size: int
    sealed_sha256: str


def object_key(candidate_id, attempt_number, token_hex):
    """The unique quarantine key of one attempt; the random part is 32 hex characters."""
    key = f"quarantine/{candidate_id.hex}/{attempt_number:02d}-{token_hex}"
    if OBJECT_KEY.fullmatch(key) is None:
        raise CoordinationRefusal("request_invalid")
    return key


def _view(row):
    return CapabilityView(
        row["capability_sha256"], row["candidate_id"], row["attempt_number"], row["actor_id"],
        RunScope(row["service_id"], row["repository_id"], row["run_id"]), row["environment"],
        row["endorsement_sequence"], row["endorsement_sha256"], row["declared_size"], row["archive_sha256"],
        row["start_expires_at"], row["attempt_state"], row["stream_started_at"] is not None)


def _completed(connection, row):
    attempt = connection.execute(
        "SELECT sealed_size, sealed_sha256 FROM upload_attempts WHERE candidate_id = %s AND attempt_number = %s",
        (row["candidate_id"], row["sealed_attempt"])).fetchone()
    return Completed(row["candidate_id"], row["state"], row["sealed_attempt"], attempt["sealed_size"],
                     attempt["sealed_sha256"])


def _environment(value):
    if type(value) is not str or ENVIRONMENT.fullmatch(value) is None:
        raise CoordinationRefusal("request_invalid")
    return value


class Transfers(Coordinator):
    """The coordinator calls the upload gateway, the capability issuer and the sweeper make."""

    @classmethod
    def from_coordinator(cls, coordinator):
        """A transfer view over the same database and the same quota and lease policy."""
        if isinstance(coordinator, Transfers):
            return coordinator
        if not isinstance(coordinator, Coordinator):
            raise CoordinationRefusal("request_invalid")
        return cls(coordinator.database, quotas=coordinator.quotas, leases=coordinator.leases)

    # Issue ------------------------------------------------------------------

    def issue(self, scope, actor_id, candidate_id, endorsement, capability_sha256, environment, start_expires_at,
              now):
        """Issue a capability for the candidate's open or next attempt, or return its sealed result.

        `endorsement` is the bound endorsement the caller read; it must still
        be the latest recorded one and unexpired. A stream that owns a live
        lease makes this `upload_in_progress`. An attempt whose stream never
        started takes the new capability in place of its earlier one, so a
        replayed issue neither opens a second attempt nor holds a second
        stream. Otherwise the next attempt opens and reserves a stream.
        """
        if not isinstance(scope, RunScope):
            raise CoordinationRefusal("request_invalid")
        positive_int(actor_id)
        candidate_id = candidate_uuid(candidate_id)
        digest(capability_sha256)
        _environment(environment)
        now = require_now(now)
        start_expires_at = require_now(start_expires_at)
        sequence = getattr(endorsement, "sequence", None)
        envelope_sha256 = getattr(endorsement, "envelope_sha256", None)
        positive_int(sequence, 288)
        digest(envelope_sha256)
        if not now < start_expires_at <= now + START_WINDOW:
            raise CoordinationRefusal("request_invalid")

        def work(connection, events):
            row = self._lock_scoped(connection, scope, actor_id, candidate_id)
            if row["sealed_attempt"] is not None:
                return _completed(connection, row)
            if row["state"] == "expired" or now >= row["expires_at"]:
                raise CoordinationRefusal("candidate_expired")
            if row["state"] not in ("announced", "uploading"):
                raise CoordinationRefusal("state_conflict")
            if start_expires_at > row["expires_at"]:
                raise CoordinationRefusal("request_invalid")
            current = connection.execute(
                "SELECT * FROM upload_attempts WHERE candidate_id = %s AND state = 'open' FOR UPDATE",
                (candidate_id,)).fetchone()
            self._require_bound(connection, candidate_id, sequence, envelope_sha256, now, start_expires_at)
            values = {"hash": capability_sha256, "actor": actor_id, "environment": environment,
                      "sequence": sequence, "envelope": envelope_sha256, "size": row["declared_size"],
                      "archive": row["archive_sha256"], "now": now, "until": start_expires_at,
                      "candidate": candidate_id}
            if current is not None and current["stream_started_at"] is None:
                values["attempt"] = current["attempt_number"]
                existing = connection.execute(
                    "SELECT issues FROM upload_capabilities WHERE candidate_id = %s AND attempt_number = %s "
                    "FOR UPDATE", (candidate_id, current["attempt_number"])).fetchone()
                if existing is not None and existing["issues"] >= MAX_ISSUES:
                    events.add("quota-refused", logging.WARNING, True, scope="attempt", kind="capability")
                    raise CoordinationRefusal("quota_exceeded")
                if existing is None:
                    self._insert_capability(connection, values)
                else:
                    connection.execute(
                        "UPDATE upload_capabilities SET capability_sha256 = %(hash)s, endorsement_sequence = "
                        "%(sequence)s, endorsement_sha256 = %(envelope)s, issued_at = %(now)s, start_expires_at = "
                        "%(until)s, issues = issues + 1 WHERE candidate_id = %(candidate)s "
                        "AND attempt_number = %(attempt)s", values)
                connection.execute(
                    "UPDATE upload_attempts SET lease_expires_at = %s, updated_at = %s "
                    "WHERE candidate_id = %s AND attempt_number = %s",
                    (start_expires_at, now, candidate_id, current["attempt_number"]))
                events.add("capability-issued", candidate=str(candidate_id), attempt=current["attempt_number"],
                           fence=current["fence"], kind="renewed")
                lease = Lease(candidate_id, "upload", current["attempt_number"], current["fence"], start_expires_at)
                return Issued(lease, start_expires_at, row["declared_size"], row["archive_sha256"], True)
            if current is not None:
                if current["lease_expires_at"] > now:
                    raise CoordinationRefusal("upload_in_progress")
                connection.execute(
                    "UPDATE upload_attempts SET state = 'abandoned', updated_at = %s "
                    "WHERE candidate_id = %s AND attempt_number = %s", (now, candidate_id, current["attempt_number"]))
                self._release(connection, events, row, now, kinds=("stream",), attempt=current["attempt_number"])
                events.add("lease-expired", logging.WARNING, candidate=str(candidate_id), kind="upload",
                           attempt=current["attempt_number"], fence=current["fence"])
            lease = self._open_attempt(connection, events, row, start_expires_at, now)
            values["attempt"] = lease.attempt_number
            self._insert_capability(connection, values)
            events.add("capability-issued", candidate=str(candidate_id), attempt=lease.attempt_number,
                       fence=lease.fence, kind="new")
            return Issued(lease, start_expires_at, row["declared_size"], row["archive_sha256"], False)

        return self._run(work)

    @staticmethod
    def _insert_capability(connection, values):
        connection.execute(
            "INSERT INTO upload_capabilities (candidate_id, attempt_number, capability_sha256, actor_id, environment, "
            "endorsement_sequence, endorsement_sha256, declared_size, archive_sha256, issued_at, start_expires_at, "
            "issues) VALUES (%(candidate)s, %(attempt)s, %(hash)s, %(actor)s, %(environment)s, %(sequence)s, "
            "%(envelope)s, %(size)s, %(archive)s, %(now)s, %(until)s, 1)", values)

    @staticmethod
    def _require_bound(connection, candidate_id, sequence, envelope_sha256, now, until):
        """The named endorsement must be the candidate's latest and valid through `until`."""
        latest = connection.execute(
            "SELECT sequence, envelope_sha256, expires_at FROM upload_endorsements WHERE candidate_id = %s "
            "ORDER BY sequence DESC LIMIT 1 FOR SHARE", (candidate_id,)).fetchone()
        if (latest is None or latest["sequence"] != sequence
                or not hmac.compare_digest(latest["envelope_sha256"], envelope_sha256)):
            raise CoordinationRefusal("endorsement_superseded")
        if now >= latest["expires_at"] or until > latest["expires_at"]:
            raise CoordinationRefusal("endorsement_expired")

    # Gateway ----------------------------------------------------------------

    def capability(self, capability_sha256):
        """The capability stored under this SHA-256, or None; read without a lock."""
        digest(capability_sha256)

        def work(connection, _events):
            return connection.execute(
                "SELECT k.*, a.state AS attempt_state, a.stream_started_at, r.service_id, r.repository_id, r.run_id "
                "FROM upload_capabilities k JOIN upload_attempts a USING (candidate_id, attempt_number) "
                "JOIN candidates c USING (candidate_id) JOIN run_registrations r ON r.run_key = c.run_key "
                "WHERE k.capability_sha256 = %s", (capability_sha256,)).fetchone()

        row = self._run(work)
        if row is None or not hmac.compare_digest(row["capability_sha256"], capability_sha256):
            return None
        return _view(row)

    def start(self, capability_sha256, object_key_value, environment, now):
        """Start the one stream a capability allows, or return its attempt's sealed result.

        Under the candidate lock the capability must be unexpired and its
        attempt open, current and unstarted, and the endorsement it names must
        still be the latest and unexpired. The attempt's lease then runs to the
        stream limit or the candidate deadline, whichever is first, and the
        quarantine key is recorded before a byte is written to it.
        """
        digest(capability_sha256)
        _environment(environment)
        now = require_now(now)
        match = OBJECT_KEY.fullmatch(object_key_value) if type(object_key_value) is str else None
        if match is None:
            raise CoordinationRefusal("request_invalid")

        def work(connection, events):
            found = connection.execute("SELECT candidate_id FROM upload_capabilities WHERE capability_sha256 = %s",
                                       (capability_sha256,)).fetchone()
            if found is None:
                raise CoordinationRefusal("capability_unknown")
            row = self._lock_candidate(connection, found["candidate_id"])
            held = connection.execute(
                "SELECT k.*, a.state AS attempt_state, a.fence AS attempt_fence, a.stream_started_at, "
                "a.lease_expires_at FROM upload_attempts a JOIN upload_capabilities k USING (candidate_id, "
                "attempt_number) WHERE k.capability_sha256 = %s FOR UPDATE OF a, k",
                (capability_sha256,)).fetchone()
            if (held is None or not hmac.compare_digest(held["capability_sha256"], capability_sha256)
                    or held["environment"] != environment or held["candidate_id"] != row["candidate_id"]):
                raise CoordinationRefusal("capability_unknown")
            if held["attempt_state"] == "sealed":
                return _completed(connection, row)
            if match.group(1) != row["candidate_id"].hex or int(match.group(2)) != held["attempt_number"]:
                raise CoordinationRefusal("request_invalid")
            if held["attempt_state"] != "open":
                raise CoordinationRefusal("capability_expired")
            if held["stream_started_at"] is not None:
                raise CoordinationRefusal("stream_active" if held["lease_expires_at"] > now
                                          else "capability_expired")
            if row["state"] == "expired" or now >= row["expires_at"]:
                raise CoordinationRefusal("candidate_expired")
            if (now >= held["start_expires_at"] or now >= held["lease_expires_at"]
                    or row["fence"] != held["attempt_fence"]):
                raise CoordinationRefusal("capability_expired")
            if (row["declared_size"], row["archive_sha256"]) != (held["declared_size"], held["archive_sha256"]):
                raise CoordinationRefusal("state_conflict")
            self._require_bound(connection, row["candidate_id"], held["endorsement_sequence"],
                                held["endorsement_sha256"], now, now)
            expires_at = min(now + timedelta(seconds=self.leases.upload_seconds), row["expires_at"])
            connection.execute(
                "UPDATE upload_attempts SET stream_started_at = %s, lease_expires_at = %s, updated_at = %s "
                "WHERE candidate_id = %s AND attempt_number = %s",
                (now, expires_at, now, row["candidate_id"], held["attempt_number"]))
            connection.execute(
                "INSERT INTO quarantine_objects (object_key, candidate_id, attempt_number, state, created_at, "
                "updated_at) VALUES (%s, %s, %s, 'writing', %s, %s)",
                (object_key_value, row["candidate_id"], held["attempt_number"], now, now))
            events.add("stream-started", candidate=str(row["candidate_id"]), attempt=held["attempt_number"],
                       fence=held["attempt_fence"])
            lease = Lease(row["candidate_id"], "upload", held["attempt_number"], held["attempt_fence"], expires_at)
            return Stream(lease, object_key_value, row["declared_size"], row["archive_sha256"], row["expires_at"])

        return self._run(work)

    def fail(self, lease, code, now, *, hold=False):
        """Fail the leased attempt and return its stream at once; a stale lease changes nothing.

        With `hold`, the attempt's quarantine record becomes `held`: its object
        failed the read-back and stays as evidence, out of every sweep, until
        an operator releases it. Returns True when this call failed the attempt.
        """
        if not isinstance(lease, Lease) or lease.kind != "upload":
            raise CoordinationRefusal("lease_stale")
        if type(code) is not str or FAILURE_CODE.fullmatch(code) is None:
            raise CoordinationRefusal("request_invalid")
        now = require_now(now)

        def work(connection, events):
            row = self._lock_candidate(connection, lease.candidate_id)
            if row is None:
                return False
            failed = connection.execute(
                "UPDATE upload_attempts SET state = 'failed', updated_at = %s WHERE candidate_id = %s "
                "AND attempt_number = %s AND state = 'open' AND fence = %s RETURNING attempt_number",
                (now, lease.candidate_id, lease.attempt_number, lease.fence)).fetchone()
            if failed is None:
                return False
            self._release(connection, events, row, now, kinds=("stream",), attempt=lease.attempt_number)
            if hold:
                held = connection.execute(
                    "UPDATE quarantine_objects SET state = 'held', updated_at = %s WHERE candidate_id = %s "
                    "AND attempt_number = %s AND state = 'writing' RETURNING object_key",
                    (now, lease.candidate_id, lease.attempt_number)).fetchone()
                if held is not None:
                    events.add("quarantine-object-held", logging.ERROR, candidate=str(lease.candidate_id),
                               attempt=lease.attempt_number, code=code)
            connection.execute(
                "INSERT INTO audit_events (candidate_id, event, from_state, to_state, fence, code, created_at) "
                "VALUES (%s, 'upload-failed', %s, %s, %s, %s, %s)",
                (lease.candidate_id, row["state"], row["state"], lease.fence, code, now))
            events.add("upload-failed", logging.WARNING, candidate=str(lease.candidate_id),
                       attempt=lease.attempt_number, fence=lease.fence, code=code)
            return True

        return self._run(work)

    def seal_stream(self, lease, sealed_size, sealed_sha256, object_key_value, endorsement_sequence,
                    endorsement_sha256, now):
        """Seal the streamed attempt and its quarantine record in one transaction.

        The caller has counted and hashed every byte on the way in and read the
        quarantine object back in full; both must equal the declared size and
        digest. A candidate past its deadline refuses as expired first. The
        endorsement the capability came from must still be the latest; it may
        have expired while the bytes streamed, since every endorsement of one
        candidate binds the same identities, length and parent. Repeating a
        completed seal returns the same attempt number.
        """
        if not isinstance(lease, Lease) or lease.kind != "upload":
            raise CoordinationRefusal("lease_stale")
        positive_int(sealed_size)
        digest(sealed_sha256)
        positive_int(endorsement_sequence, 288)
        digest(endorsement_sha256)
        if type(object_key_value) is not str or OBJECT_KEY.fullmatch(object_key_value) is None:
            raise CoordinationRefusal("request_invalid")
        now = require_now(now)

        def work(connection, events):
            candidate = self._lock_candidate(connection, lease.candidate_id)
            if candidate is not None and candidate["sealed_attempt"] is None and (
                    candidate["state"] == "expired" or now >= candidate["expires_at"]):
                return CoordinationRefusal("candidate_expired")
            row, checked = self._seal_check(connection, events, lease, sealed_size, sealed_sha256, now)
            if type(checked) is int:
                # A replay matches only the seal it repeats, quarantine key included.
                recorded = connection.execute(
                    "SELECT 1 FROM quarantine_objects WHERE object_key = %s AND candidate_id = %s "
                    "AND attempt_number = %s AND state = 'sealed' AND sealed_size = %s AND sealed_sha256 = %s",
                    (object_key_value, lease.candidate_id, lease.attempt_number, sealed_size,
                     sealed_sha256)).fetchone()
                return checked if recorded is not None else CoordinationRefusal("lease_stale")
            if checked is not None:
                return checked
            latest = connection.execute(
                "SELECT sequence, envelope_sha256 FROM upload_endorsements WHERE candidate_id = %s "
                "ORDER BY sequence DESC LIMIT 1 FOR SHARE", (lease.candidate_id,)).fetchone()
            if (latest is None or latest["sequence"] != endorsement_sequence
                    or not hmac.compare_digest(latest["envelope_sha256"], endorsement_sha256)):
                raise CoordinationRefusal("endorsement_superseded")
            recorded = connection.execute(
                "SELECT state FROM quarantine_objects WHERE object_key = %s AND candidate_id = %s "
                "AND attempt_number = %s FOR UPDATE",
                (object_key_value, lease.candidate_id, lease.attempt_number)).fetchone()
            if recorded is None or recorded["state"] != "writing":
                return CoordinationRefusal("lease_stale")
            connection.execute(
                "UPDATE quarantine_objects SET state = 'sealed', sealed_size = %s, sealed_sha256 = %s, updated_at = %s "
                "WHERE object_key = %s", (sealed_size, sealed_sha256, now, object_key_value))
            return self._seal_commit(connection, events, row, lease, sealed_size, sealed_sha256, now)

        return self._run(work)

    # Reads for the API, staging and signals ---------------------------------

    def attempt_state(self, scope, actor_id, candidate_id):
        """The caller's candidate state with its sealed attempt, or its open attempt's stream state."""
        if not isinstance(scope, RunScope):
            raise CoordinationRefusal("request_invalid")
        positive_int(actor_id)
        candidate_id = candidate_uuid(candidate_id)

        def work(connection, _events):
            row = self._lock_scoped(connection, scope, actor_id, candidate_id)
            if row["sealed_attempt"] is not None:
                return _completed(connection, row)
            current = connection.execute(
                "SELECT attempt_number, stream_started_at FROM upload_attempts WHERE candidate_id = %s "
                "AND state = 'open'", (candidate_id,)).fetchone()
            return row["state"], current

        return self._run(work)

    def attempts_spent(self, candidate_id, now):
        """Whether an unsealed uploading candidate can never open another attempt.

        True once all 16 attempts exist and none is still usable: no open
        attempt whose stream has not started, and none whose stream lease
        lives. Its quota stays reserved until the deadline; a new attempt
        refuses as `attempt_limit`.
        """
        candidate_id = candidate_uuid(candidate_id)
        now = require_now(now)

        def work(connection, _events):
            return connection.execute(
                "SELECT c.state = 'uploading' AND c.sealed_attempt IS NULL AND (SELECT count(*) FROM upload_attempts "
                "WHERE candidate_id = c.candidate_id) >= %s AND NOT EXISTS (SELECT 1 FROM upload_attempts "
                "WHERE candidate_id = c.candidate_id AND state = 'open' AND (stream_started_at IS NULL "
                "OR lease_expires_at > %s)) AS spent FROM candidates c WHERE c.candidate_id = %s",
                (MAX_UPLOAD_ATTEMPTS, now, candidate_id)).fetchone()

        row = self._run(work)
        return row is not None and row["spent"] is True

    def sealed_object(self, candidate_id, attempt_number):
        """The recorded quarantine key, size and digest of a sealed attempt, for the staging broker."""
        candidate_id = candidate_uuid(candidate_id)
        positive_int(attempt_number, 16)

        def work(connection, _events):
            return connection.execute(
                "SELECT q.object_key, q.sealed_size, q.sealed_sha256 FROM quarantine_objects q "
                "JOIN upload_attempts a USING (candidate_id, attempt_number) WHERE q.candidate_id = %s "
                "AND q.attempt_number = %s AND q.state = 'sealed' AND a.state = 'sealed' "
                "AND a.sealed_size = q.sealed_size AND a.sealed_sha256 = q.sealed_sha256",
                (candidate_id, attempt_number)).fetchone()

        row = self._run(work)
        if row is None:
            raise CoordinationRefusal("not_found")
        return SealedObject(candidate_id, attempt_number, row["object_key"], row["sealed_size"], row["sealed_sha256"])

    def quarantine_usage(self, now):
        """Live and held object counts, sealed bytes, and the count and oldest age of deletions still due."""
        now = require_now(now)

        def work(connection, _events):
            return connection.execute(
                "SELECT count(*) FILTER (WHERE state IN ('writing', 'sealed')) AS live, "
                "count(*) FILTER (WHERE state = 'held') AS held, "
                "coalesce(sum(sealed_size) FILTER (WHERE state = 'sealed'), 0) AS sealed_bytes, "
                "count(*) FILTER (WHERE state = 'deleting') AS deleting, "
                "min(updated_at) FILTER (WHERE state = 'deleting') AS oldest FROM quarantine_objects").fetchone()

        row = self._run(work)
        lag = 0 if row["oldest"] is None else max(0, int((now - row["oldest"]).total_seconds()))
        return {"live": row["live"], "held": row["held"], "sealed_bytes": int(row["sealed_bytes"]),
                "deleting": row["deleting"], "cleanup_lag_seconds": lag}

    # Sweeper ----------------------------------------------------------------

    def reclaim_streams(self, now):
        """Abandon upload attempts whose lease has expired and give back their streams."""
        now = require_now(now)
        return self._run(lambda connection, events: self._reclaim_expired_streams(connection, events, now))

    def claim_deletions(self, now, limit=MAX_SWEEP):
        """Mark every quarantine object that is due for deletion and return the keys still to delete.

        Due means its attempt failed or was abandoned, its candidate ended, or
        it has outlived the 24-hour quarantine lifetime. An object whose
        attempt is still open and unexpired is never due. Keys marked by an
        earlier sweep that did not finish are returned again.
        """
        now = require_now(now)
        positive_int(limit, MAX_SWEEP)

        def work(connection, events):
            # Being due only ever becomes true: a failed or abandoned attempt
            # never seals, an ended candidate never resumes and age only grows,
            # so the attempt and candidate rows need no lock here.
            marked = connection.execute(
                "UPDATE quarantine_objects SET state = 'deleting', updated_at = %(now)s WHERE object_key IN ("
                "SELECT q.object_key FROM quarantine_objects q JOIN upload_attempts a USING (candidate_id, "
                "attempt_number) JOIN candidates c USING (candidate_id) WHERE q.state IN ('writing', 'sealed') "
                "AND (a.state IN ('failed', 'abandoned') OR c.state = ANY(%(terminal)s) "
                "OR q.created_at <= %(cutoff)s) ORDER BY q.created_at LIMIT %(limit)s FOR UPDATE OF q SKIP LOCKED) "
                "RETURNING object_key",
                {"now": now, "limit": limit, "terminal": list(TERMINAL),
                 "cutoff": now - QUARANTINE_LIFETIME}).fetchall()
            if marked:
                events.add("quarantine-deletion-due", count=len(marked))
            return [row["object_key"] for row in connection.execute(
                "SELECT object_key FROM quarantine_objects WHERE state = 'deleting' ORDER BY updated_at LIMIT %s",
                (limit,)).fetchall()]

        return self._run(work)

    def release_held(self, object_key_value, now):
        """An operator's release of one held object to the next sweep, once its evidence is kept elsewhere."""
        now = require_now(now)
        if type(object_key_value) is not str or OBJECT_KEY.fullmatch(object_key_value) is None:
            raise CoordinationRefusal("request_invalid")

        def work(connection, events):
            released = connection.execute(
                "UPDATE quarantine_objects SET state = 'deleting', updated_at = %s WHERE object_key = %s "
                "AND state = 'held' RETURNING candidate_id", (now, object_key_value)).fetchone()
            if released is None:
                raise CoordinationRefusal("not_found")
            events.add("quarantine-object-released", candidate=str(released["candidate_id"]))
            return True

        return self._run(work)

    def mark_deleted(self, keys, now):
        """Record that the store no longer holds these keys; unknown or live keys are left alone."""
        now = require_now(now)
        keys = list(keys)
        if len(keys) > MAX_SWEEP or not all(type(key) is str and OBJECT_KEY.fullmatch(key) for key in keys):
            raise CoordinationRefusal("request_invalid")

        def work(connection, _events):
            return connection.execute(
                "UPDATE quarantine_objects SET state = 'deleted', updated_at = %s "
                "WHERE object_key = ANY(%s) AND state = 'deleting'", (now, keys)).rowcount

        return self._run(work) if keys else 0

    def claim_lifecycle(self, keys, now):
        """Of the keys the store reports as a day old, the ones the service clock also lets go.

        Records past the 24-hour lifetime are marked for deletion. A key whose
        record is still live and younger by the service clock is kept, so a
        store clock that runs ahead never deletes a sealed object early, and
        a held key waits for its operator; a key with no record at all was
        never sealed and may go.
        """
        now = require_now(now)
        keys = list(keys)
        if len(keys) > MAX_SWEEP or not all(type(key) is str and OBJECT_KEY.fullmatch(key) for key in keys):
            raise CoordinationRefusal("request_invalid")

        def work(connection, _events):
            connection.execute(
                "UPDATE quarantine_objects SET state = 'deleting', updated_at = %s WHERE object_key = ANY(%s) "
                "AND state IN ('writing', 'sealed') AND created_at <= %s", (now, keys, now - QUARANTINE_LIFETIME))
            kept = {row["object_key"] for row in connection.execute(
                "SELECT object_key FROM quarantine_objects WHERE object_key = ANY(%s) "
                "AND state IN ('writing', 'sealed', 'held')", (keys,)).fetchall()}
            return [key for key in keys if key not in kept]

        return self._run(work) if keys else []

    def sweep_capabilities(self, now, limit=MAX_SWEEP):
        """Delete capability records of attempts no longer open, a day after their last issue."""
        now = require_now(now)
        positive_int(limit, MAX_SWEEP)

        def work(connection, events):
            removed = connection.execute(
                "DELETE FROM upload_capabilities WHERE (candidate_id, attempt_number) IN ("
                "SELECT k.candidate_id, k.attempt_number FROM upload_capabilities k JOIN upload_attempts a "
                "USING (candidate_id, attempt_number) WHERE a.state <> 'open' AND k.issued_at <= %s "
                "LIMIT %s FOR UPDATE OF k SKIP LOCKED)", (now - CAPABILITY_RETENTION, limit)).rowcount
            if removed:
                events.add("capabilities-swept", count=removed)
            return removed

        return self._run(work)
