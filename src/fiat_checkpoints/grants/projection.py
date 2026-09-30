"""Each allowlisted run's authorization projection, verified from its operator-signed records.

An operator signs a run's authority policy, enrollment challenges, key
enrollments and rotations, revocations and run grants, each ordered by its own
sequence and predecessor. The service stores those envelopes byte for byte and,
before any use, verifies the whole prefix from the run's external roots through
the released `TrustPrefix`. PostgreSQL keeps the bytes and their order and
nothing else: a stored row that fails verification stops the run as
`authority_unavailable` rather than granting anything. Grants, enrollments and
revocations are read from the verified prefix on every request, at the service
clock, so a removal takes effect at the next request. A contributor's own key
never enrolls itself: only a record the policy's operator key signed can.
See adr/bind-uploads-to-enrolled-keys.
"""

import hashlib
import logging
import threading
import time

from fiat_checkpoints.auth.refusals import AuthRefusal, from_record
from fiat_checkpoints.domain.coordination import CoordinationRefusal, RunScope, require_now
from fiat_checkpoints.records.authority import AuthorityRecords
from fiat_checkpoints.records.refusals import PROTOCOL, RecordRefusal


LOGGER = logging.getLogger("fiat_checkpoints")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())
MAX_TRUST_RECORDS = 256
MAX_TRUST_ENVELOPE_BYTES = 65_536
PERMISSIONS = ("announce", "upload", "read_status", "read_receipt", "download")
ENROLLMENT_TYPES = ("key-enrollment", "key-rotation")
MAX_HISTORICAL_SIGNERS = 64
# Library codes meaning the signing key has no live enrollment in this run.
UNENROLLED = frozenset({"enrollment-required", "enrollment-inactive", "enrollment-expired"})
# Library codes meaning the pinned verifier itself could not run.
TOOL_CODES = frozenset({"tool-unavailable", "tool-timeout", "tool-output-limit", "tool-pin", "tool-required"})


def reference(kind, sha256):
    return {"type": kind, "sha256": sha256}


def _refused(event, level, refusal):
    """Log one refusal by its fixed code, reason and library code, then return it for raising."""
    fields = {"event": event, "code": refusal.code, "reason": refusal.reason}
    if refusal.protocol_code is not None:
        fields["protocol_code"] = refusal.protocol_code
    LOGGER.log(level, event, extra=fields)
    return refusal


def _library_code(error):
    return error.protocol_code if error.producer == PROTOCOL else None


def signature_refusal(error, refused, reason):
    """Map a library refusal of contributor-signed evidence to its public code."""
    if error.producer != PROTOCOL:
        return AuthRefusal("request_invalid" if error.code == "request_invalid" else "authority_unavailable",
                           reason)
    if error.protocol_code in UNENROLLED:
        return from_record("signer_not_enrolled", error, "signer-not-enrolled")
    if error.protocol_code in TOOL_CODES:
        return from_record("validation_failed", error, "verifier-unavailable")
    return from_record(refused, error, reason)


class RunAuthority:
    """One operator-allowlisted run: its protocol scope, external roots and pinned tools."""

    def __init__(self, records):
        if not isinstance(records, AuthorityRecords):
            raise AuthRefusal("authority_unavailable", "run-config-invalid")
        scope = records.scope
        try:
            self.scope = RunScope(scope.service, scope.repository_id, scope.run_id)
        except CoordinationRefusal:
            raise AuthRefusal("authority_unavailable", "run-config-invalid") from None
        self.records = records
        self.environment = scope.environment

    @property
    def key(self):
        return (self.scope.repository_id, self.scope.run_id)


class Projection:
    """A verified trust prefix at one head, with the indexes the service reads from it."""

    def __init__(self, run, prefix, accepted):
        self.run = run
        self.prefix = prefix
        self.accepted = tuple(accepted)
        self.count = len(self.accepted)
        self.tail = self.accepted[-1].envelope_sha256 if self.accepted else None
        self._grants, self._challenges, self._enrollments = {}, {}, {}
        for item in self.accepted:
            record = item.record
            if item.record_type == "run-grant":
                self._grants.setdefault(record["actor_id"], []).append(
                    (reference("run-grant", item.envelope_sha256), record))
            elif item.record_type == "enrollment-challenge":
                self._challenges[item.envelope_sha256] = record
            elif item.record_type in ENROLLMENT_TYPES:
                self._enrollments[item.envelope_sha256] = (item.record_type, record)

    @property
    def policy(self):
        return None if self.prefix is None else reference("authority-policy", self.prefix.policy.envelope_sha256)

    def _current(self, grant, actor_id, permission, now):
        self.run.records.grant_at(self.prefix, grant, actor_id, now, permission)
        return grant

    def grant(self, actor_id, permission, now):
        """The first of the actor's grants the released check holds current for `permission` now.

        No grant, a revoked enrollment, an expired grant and a missing
        permission all look the same to the caller: the run is `not_found`.
        """
        now = require_now(now)
        if permission not in PERMISSIONS:
            raise AuthRefusal("authority_unavailable", "permission-unknown")
        last = None
        for grant, _record in self._grants.get(actor_id, ()):
            try:
                return self._current(grant, actor_id, permission, now)
            except RecordRefusal as error:
                last = error
        raise AuthRefusal("not_found", "grant-absent" if last is None else "grant-refused",
                          protocol_code=None if last is None else _library_code(last))

    def named_grant(self, grant, actor_id, permission, now):
        """Hold the exact grant an endorsement names current for `permission` now."""
        now = require_now(now)
        try:
            return self._current(grant, actor_id, permission, now)
        except RecordRefusal as error:
            raise signature_refusal(error, "endorsement_invalid", "grant-not-current") from None

    def upload_terms(self, actor_id, now):
        """The grant and enrollment an upload endorsement would name now, if any."""
        try:
            grant = self.grant(actor_id, "upload", now)
        except AuthRefusal:
            return None
        record = next(record for candidate, record in self._grants[actor_id] if candidate == grant)
        return {"grant": grant, "enrollment": record["enrollment"]}

    def any_grant(self, actor_id, now):
        for permission in PERMISSIONS:
            try:
                self.grant(actor_id, permission, now)
                return True
            except AuthRefusal:
                continue
        return False

    def challenge(self, sha256):
        """An unconsumed operator-signed enrollment challenge in this run, or `not_found`."""
        record = self._challenges.get(sha256) if type(sha256) is str else None
        if record is None or sha256 in self.prefix.consumed_challenges:
            raise AuthRefusal("not_found", "challenge-unknown")
        return record

    def authenticate(self, envelope):
        """Authenticate an upload endorsement with the enrolled key, through the released check."""
        if self.prefix is None:
            raise AuthRefusal("signer_not_enrolled", "trust-empty")
        try:
            return self.run.records.authenticate(self.prefix, envelope)
        except RecordRefusal as error:
            raise signature_refusal(error, "endorsement_invalid", "endorsement-refused") from None

    def historical_signers(self, signers):
        """Refuse unless each `(enrollment reference, fingerprint)` is a key this run approved.

        The released key-history check resolves every reference in this run's
        verified prefix: a carried key, another run's enrollment or a key never
        enrolled has no reference there. Each approved enrollment must also hold
        the key whose fingerprint signed. Returns the ordered history.
        """
        if type(signers) not in (list, tuple) or not 1 <= len(signers) <= MAX_HISTORICAL_SIGNERS:
            raise AuthRefusal("request_invalid", "signers-malformed")
        references = []
        for item in signers:
            if type(item) is not tuple or len(item) != 2:
                raise AuthRefusal("request_invalid", "signers-malformed")
            named, fingerprint = item
            if (type(named) is not dict or set(named) != {"type", "sha256"} or named["type"] not in ENROLLMENT_TYPES
                    or type(named["sha256"]) is not str or type(fingerprint) is not str):
                raise AuthRefusal("request_invalid", "signers-malformed")
            references.append(reference(named["type"], named["sha256"]))
        if self.prefix is None:
            raise AuthRefusal("signer_not_enrolled", "historical-signer-unapproved")
        try:
            history = self.run.records.signing_history(self.prefix, references)
        except RecordRefusal as error:
            raise signature_refusal(error, "signer_not_enrolled", "historical-signer-unapproved") from None
        for named, (_item, fingerprint) in zip(references, signers):
            kind, record = self._enrollments.get(named["sha256"], (None, None))
            if record is None or kind != named["type"] or record["key"]["fingerprint"] != fingerprint:
                raise AuthRefusal("signer_not_enrolled", "historical-signer-binding")
        return history


class Projections:
    """The allowlisted runs of one service and a cache of each run's verified projection."""

    def __init__(self, database, runs):
        runs = tuple(runs)
        if not runs or not all(isinstance(run, RunAuthority) for run in runs):
            raise AuthRefusal("authority_unavailable", "run-config-invalid")
        if (len({run.key for run in runs}) != len(runs) or len({run.scope.service_id for run in runs}) != 1
                or len({run.environment for run in runs}) != 1):
            raise AuthRefusal("authority_unavailable", "run-config-invalid")
        self.database = database
        self.environment = runs[0].environment
        self.service_id = runs[0].scope.service_id
        self._runs = {run.key: run for run in runs}
        self._cache = {}
        self._lock = threading.Lock()

    def runs(self):
        return tuple(self._runs.values())

    def run(self, repository_id, run_id):
        """The allowlisted run with these numbers, or `not_found`; a caller's slug is never a key."""
        run = None
        if type(repository_id) is int and type(run_id) is str:
            run = self._runs.get((repository_id, run_id))
        if run is None:
            raise AuthRefusal("not_found", "run-unknown")
        return run

    def run_for(self, scope):
        run = self._runs.get((scope.repository_id, scope.run_id)) if isinstance(scope, RunScope) else None
        if run is None or run.scope != scope:
            raise AuthRefusal("not_found", "run-unknown")
        return run

    # Stored rows ------------------------------------------------------------

    @staticmethod
    def _run_key(connection, run):
        row = connection.execute(
            "SELECT run_key FROM run_registrations WHERE service_id = %s AND repository_id = %s AND run_id = %s",
            (run.scope.service_id, run.scope.repository_id, run.scope.run_id)).fetchone()
        return None if row is None else row["run_key"]

    @staticmethod
    def _head_of(connection, run_key):
        if run_key is None:
            return (0, None)
        row = connection.execute(
            "SELECT count(*) AS n, (SELECT envelope_sha256 FROM trust_records WHERE run_key = %s "
            "ORDER BY sequence DESC LIMIT 1) AS tail FROM trust_records WHERE run_key = %s",
            (run_key, run_key)).fetchone()
        return (row["n"], row["tail"])

    def run_key(self, run, now):
        """The run's coordination key, registering the run on first use."""
        now = require_now(now)

        def work(connection):
            connection.execute(
                "INSERT INTO run_registrations (service_id, repository_id, run_id, registered_at) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
                (run.scope.service_id, run.scope.repository_id, run.scope.run_id, now))
            return self._run_key(connection, run)

        return self.database.transaction(work)

    def _verify(self, run, rows):
        """Verify stored rows from the run's roots; any failure stops the run and is logged as an error."""
        started = time.monotonic_ns()
        try:
            projection = self._verified(run, rows)
        except AuthRefusal as refusal:
            raise _refused("trust-projection-refused", logging.ERROR, refusal) from None
        LOGGER.info("trust-projection-verified", extra={
            "event": "trust-projection-verified", "count": projection.count,
            "duration_us": max(0, (time.monotonic_ns() - started) // 1000)})
        return projection

    @staticmethod
    def _verified(run, rows):
        if not rows:
            return Projection(run, None, ())
        if len(rows) > MAX_TRUST_RECORDS or [row["sequence"] for row in rows] != list(range(1, len(rows) + 1)):
            raise AuthRefusal("authority_unavailable", "trust-record-drift")
        envelopes = []
        for row in rows:
            envelope = bytes(row["envelope"])
            if hashlib.sha256(envelope).hexdigest() != row["envelope_sha256"]:
                raise AuthRefusal("authority_unavailable", "trust-record-drift")
            envelopes.append(envelope)
        try:
            prefix, accepted = run.records.trust_prefix(envelopes)
        except RecordRefusal as error:
            raise from_record("authority_unavailable", error, "trust-prefix-refused") from None
        for row, item in zip(rows, accepted, strict=True):
            if (item.envelope_sha256, item.record_type) != (row["envelope_sha256"], row["record_type"]):
                raise AuthRefusal("authority_unavailable", "trust-record-drift")
        return Projection(run, prefix, accepted)

    def _remember(self, run, projection):
        with self._lock:
            known = self._cache.get(run.key)
            if known is None or known.count <= projection.count:
                self._cache[run.key] = projection

    def current(self, run):
        """The run's projection at its stored head, verified again whenever the head moved."""
        def head(connection):
            return self._head_of(connection, self._run_key(connection, run))

        observed = self.database.transaction(head)
        with self._lock:
            cached = self._cache.get(run.key)
        if cached is not None and (cached.count, cached.tail) == observed:
            return cached

        def rows(connection):
            run_key = self._run_key(connection, run)
            if run_key is None:
                return []
            return connection.execute(
                "SELECT sequence, record_type, envelope, envelope_sha256 FROM trust_records WHERE run_key = %s "
                "ORDER BY sequence LIMIT %s", (run_key, MAX_TRUST_RECORDS + 1)).fetchall()

        projection = self._verify(run, self.database.transaction(rows))
        self._remember(run, projection)
        return projection

    def ingest(self, run, envelope, now):
        """Append one operator-signed trust record after the released check accepts it in order.

        The stored prefix is verified first and the new envelope is verified at
        its end; only then is it written, and only if the head has not moved.
        A refused record writes nothing. Privileged callers only: the route
        that reaches this belongs to the operator deployment (Skills #863).
        """
        now = require_now(now)
        try:
            return self._ingest(run, envelope, now)
        except AuthRefusal as refusal:
            raise _refused("authority-record-refused", logging.WARNING, refusal) from None

    def _ingest(self, run, envelope, now):
        if type(envelope) is not bytes or not 0 < len(envelope) <= MAX_TRUST_ENVELOPE_BYTES:
            raise AuthRefusal("request_invalid", "trust-record-bounds")
        exact = bytes(envelope)
        before = self.current(run)
        if before.count >= MAX_TRUST_RECORDS:
            raise AuthRefusal("quota_exceeded", "trust-record-limit")
        try:
            prefix, accepted = run.records.trust_prefix([*(item.envelope for item in before.accepted), exact])
        except RecordRefusal as error:
            raise from_record("protocol_refused", error, "trust-record-refused") from None
        added = accepted[-1]
        run_key = self.run_key(run, now)

        def work(connection):
            connection.execute("SELECT 1 FROM run_registrations WHERE run_key = %s FOR NO KEY UPDATE", (run_key,))
            if self._head_of(connection, run_key) != (before.count, before.tail):
                return AuthRefusal("policy_unavailable", "trust-head-moved")
            connection.execute(
                "INSERT INTO trust_records (run_key, sequence, record_type, envelope, envelope_sha256, ingested_at) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (run_key, before.count + 1, added.record_type, exact, added.envelope_sha256, now))
            return None

        refusal = self.database.transaction(work)
        if refusal is not None:
            raise refusal
        self._remember(run, Projection(run, prefix, accepted))
        LOGGER.info("authority-record-ingested", extra={"event": "authority-record-ingested",
                                                        "kind": added.record_type, "count": before.count + 1})
        return added

    def any_grant(self, actor_id, now):
        """True when the actor holds a current grant of any permission in any allowlisted run."""
        return any(self.current(run).any_grant(actor_id, now) for run in self._runs.values())
