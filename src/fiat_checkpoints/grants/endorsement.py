"""Bind one signed upload endorsement to exactly the submission announce recorded.

The released library authenticates the endorsement with the actor's enrolled
key and checks its enrollment and grant at its own `issued_at`. The service
then compares every field it bound itself: the authenticated numeric actor,
the candidate, the nonce announce issued, the run, all three checkpoint
identities by role, the carrier length and the parent link. It also requires
the endorsement to have been signed after announce and not after now, and to
be unexpired now. Only after all of that, and with the trust head unchanged,
is the endorsement recorded, once per candidate. An exact replay of the
recorded envelope returns the recorded result; any other envelope for that
candidate refuses. See adr/bind-uploads-to-enrolled-keys.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hmac
import logging
import secrets
import uuid

from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.domain.coordination import RunScope, candidate_uuid, positive_int, require_now
from fiat_checkpoints.domain.identities import CheckpointIdentities, IdentityMismatch


LOGGER = logging.getLogger("fiat_checkpoints")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())
TERMINAL = ("rejected", "expired", "revoked", "denied", "accepted")


def challenge_nonce():
    """A fresh endorsement nonce.

    The released record schema requires an alphanumeric first character for a
    nonce. Base64url tokens start with `-` or `_` about one time in 32, which
    made every endorsement for that candidate fail as `schema-pattern`; hex
    always satisfies the pattern.
    """
    return secrets.token_hex(32)


@dataclass(frozen=True)
class Challenge:
    candidate_id: uuid.UUID
    nonce: str
    issued_at: datetime

    @property
    def not_before(self):
        # Records carry whole seconds; an endorsement signed in announce's second is after it.
        return self.issued_at.replace(microsecond=0)


@dataclass(frozen=True)
class CandidateBinding:
    """What announce bound for one candidate, read back for its own actor only."""
    candidate_id: uuid.UUID
    actor_id: int
    scope: RunScope
    state: str
    expires_at: datetime
    identities: CheckpointIdentities
    declared_size: int
    parent_sha256: str
    challenge: Challenge


@dataclass(frozen=True)
class Terms:
    """The references and times one bound endorsement names."""
    policy_sha256: str
    enrollment_sha256: str
    grant: dict
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class Endorsed:
    candidate_id: uuid.UUID
    envelope_sha256: str
    expires_at: datetime
    replayed: bool


def _instant(value):
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        raise AuthRefusal("endorsement_invalid", "endorsement-time") from None


def check_binding(record, binding, actor_id, now):
    """Refuse unless every field this service bound equals the endorsement's.

    `record` is the library-authenticated endorsement body. The order below
    fixes which refusal a caller sees when several fields are wrong.
    """
    if not isinstance(binding, CandidateBinding) or type(record) is not dict:
        raise AuthRefusal("authority_unavailable", "binding-input")
    now = require_now(now)
    if record.get("type") != "upload-endorsement":
        raise AuthRefusal("endorsement_invalid", "endorsement-type")
    if type(record.get("actor_id")) is not int or not record["actor_id"] == actor_id == binding.actor_id:
        raise AuthRefusal("identity_mismatch", "endorsement-actor")
    scope = binding.scope
    if (record.get("service"), record.get("scope")) != (
            scope.service_id, {"repository_id": scope.repository_id, "run_id": scope.run_id}):
        raise AuthRefusal("endorsement_invalid", "endorsement-run")
    if record.get("candidate_id") != str(binding.candidate_id):
        raise AuthRefusal("endorsement_invalid", "endorsement-candidate")
    nonce = record.get("nonce")
    if type(nonce) is not str or not hmac.compare_digest(nonce.encode(), binding.challenge.nonce.encode()):
        raise AuthRefusal("endorsement_invalid", "endorsement-nonce")
    try:
        CheckpointIdentities.from_protocol(record.get("identities")).require(binding.identities)
    except IdentityMismatch:
        raise AuthRefusal("identity_mismatch", "endorsement-identities") from None
    if type(record.get("carrier_length")) is not int or record["carrier_length"] != binding.declared_size:
        raise AuthRefusal("identity_mismatch", "endorsement-length")
    if record.get("parent") != {"type": "parent-link", "sha256": binding.parent_sha256}:
        raise AuthRefusal("endorsement_invalid", "endorsement-parent")
    issued, expires = _instant(record.get("issued_at")), _instant(record.get("expires_at"))
    if now >= binding.expires_at:
        raise AuthRefusal("candidate_expired", "candidate-expired")
    if not binding.challenge.not_before <= issued <= now:
        raise AuthRefusal("endorsement_invalid", "endorsement-issued")
    if now >= expires:
        raise AuthRefusal("endorsement_invalid", "endorsement-expired")
    try:
        return Terms(record["policy"]["sha256"], record["enrollment"]["sha256"], dict(record["grant"]),
                     issued, expires)
    except (KeyError, TypeError):
        raise AuthRefusal("endorsement_invalid", "endorsement-references") from None


class EndorsementStore:
    """Announce's challenge and the one verified endorsement of each candidate."""

    def __init__(self, database):
        self.database = database

    def _run(self, work):
        result = self.database.transaction(work)
        if isinstance(result, AuthRefusal):
            raise result
        return result

    def bind(self, candidate_id, identities, parent_sha256, now):
        """Create, or return unchanged, the candidate's challenge and announced binding.

        Announce's idempotency fingerprint already covers these values, so a
        replayed announce finds the same row. Any difference is a conflict.
        """
        now = require_now(now)
        nonce = challenge_nonce()

        def work(connection):
            candidate = connection.execute("SELECT archive_sha256 FROM candidates WHERE candidate_id = %s "
                                           "FOR UPDATE", (candidate_id,)).fetchone()
            if candidate is None or candidate["archive_sha256"] != identities.archive_sha256:
                return AuthRefusal("authority_unavailable", "binding-candidate")
            connection.execute(
                "INSERT INTO endorsement_challenges (candidate_id, nonce, snapshot_id, controller_manifest_sha256, "
                "parent_sha256, issued_at) VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (candidate_id) DO NOTHING",
                (candidate_id, nonce, identities.snapshot_id, identities.controller_manifest_sha256,
                 parent_sha256, now))
            row = connection.execute("SELECT * FROM endorsement_challenges WHERE candidate_id = %s",
                                     (candidate_id,)).fetchone()
            if ((row["snapshot_id"], row["controller_manifest_sha256"], row["parent_sha256"])
                    != (identities.snapshot_id, identities.controller_manifest_sha256, parent_sha256)):
                return AuthRefusal("idempotency_conflict", "binding-changed")
            return Challenge(row["candidate_id"], row["nonce"], row["issued_at"])

        return self._run(work)

    def binding(self, actor_id, candidate_id):
        """Read one candidate's binding for its own actor; any other id or actor is `not_found`."""
        positive_int(actor_id)
        candidate_id = candidate_uuid(candidate_id)

        def work(connection):
            return connection.execute(
                "SELECT c.candidate_id, c.actor_id, c.state, c.expires_at, c.archive_sha256, c.declared_size, "
                "r.service_id, r.repository_id, r.run_id, e.nonce, e.snapshot_id, e.controller_manifest_sha256, "
                "e.parent_sha256, e.issued_at FROM candidates c JOIN run_registrations r USING (run_key) "
                "JOIN endorsement_challenges e USING (candidate_id) WHERE c.candidate_id = %s AND c.actor_id = %s",
                (candidate_id, actor_id)).fetchone()

        row = self._run(work)
        if row is None:
            raise AuthRefusal("not_found", "candidate-unknown")
        return CandidateBinding(
            row["candidate_id"], row["actor_id"], RunScope(row["service_id"], row["repository_id"], row["run_id"]),
            row["state"], row["expires_at"],
            CheckpointIdentities(row["snapshot_id"], row["controller_manifest_sha256"], row["archive_sha256"]),
            row["declared_size"], row["parent_sha256"], Challenge(row["candidate_id"], row["nonce"], row["issued_at"]))

    def record(self, binding, verified, terms, head, now):
        """Record the endorsement once, if the candidate, challenge and trust head are unchanged.

        The candidate row is locked first, then its challenge and endorsement,
        then the run row in share mode, which an ingestion holds exclusively
        while it appends, so the grant just checked is still the current one.
        """
        now = require_now(now)
        count, tail = head

        def work(connection):
            row = connection.execute("SELECT * FROM candidates WHERE candidate_id = %s AND actor_id = %s FOR UPDATE",
                                     (binding.candidate_id, binding.actor_id)).fetchone()
            if row is None:
                return AuthRefusal("not_found", "candidate-unknown")
            if row["state"] in TERMINAL or now >= row["expires_at"]:
                return AuthRefusal("candidate_expired", "candidate-expired")
            challenge = connection.execute("SELECT nonce FROM endorsement_challenges WHERE candidate_id = %s "
                                           "FOR SHARE", (binding.candidate_id,)).fetchone()
            if challenge is None or challenge["nonce"] != binding.challenge.nonce:
                return AuthRefusal("authority_unavailable", "binding-changed")
            existing = connection.execute("SELECT envelope_sha256, expires_at FROM upload_endorsements "
                                          "WHERE candidate_id = %s FOR SHARE", (binding.candidate_id,)).fetchone()
            if existing is not None:
                if existing["envelope_sha256"] != verified.envelope_sha256:
                    return AuthRefusal("endorsement_invalid", "nonce-consumed")
                if now >= existing["expires_at"]:
                    return AuthRefusal("endorsement_invalid", "endorsement-expired")
                return Endorsed(binding.candidate_id, existing["envelope_sha256"], existing["expires_at"], True)
            if row["state"] != "announced":
                return AuthRefusal("idempotency_conflict", "candidate-state")
            run = connection.execute("SELECT run_key FROM run_registrations WHERE run_key = %s FOR SHARE",
                                     (row["run_key"],)).fetchone()
            observed = connection.execute(
                "SELECT count(*) AS n, (SELECT envelope_sha256 FROM trust_records WHERE run_key = %s "
                "ORDER BY sequence DESC LIMIT 1) AS tail FROM trust_records WHERE run_key = %s",
                (run["run_key"], run["run_key"])).fetchone()
            if (observed["n"], observed["tail"]) != (count, tail):
                return AuthRefusal("policy_unavailable", "trust-head-moved")
            connection.execute(
                "INSERT INTO upload_endorsements (candidate_id, envelope, envelope_sha256, policy_sha256, "
                "enrollment_sha256, grant_sha256, key_fingerprint, trust_count, trust_tail_sha256, issued_at, "
                "expires_at, verified_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (binding.candidate_id, verified.envelope, verified.envelope_sha256, terms.policy_sha256,
                 terms.enrollment_sha256, terms.grant["sha256"], verified.key_fingerprint, count, tail,
                 terms.issued_at, terms.expires_at, now))
            connection.execute(
                "INSERT INTO audit_events (candidate_id, event, from_state, to_state, fence, created_at) "
                "VALUES (%s, 'endorsement-verified', %s, %s, %s, %s)",
                (binding.candidate_id, row["state"], row["state"], row["fence"], now))
            return Endorsed(binding.candidate_id, verified.envelope_sha256, terms.expires_at, False)

        done = self._run(work)
        LOGGER.info("endorsement-verified", extra={"event": "endorsement-verified",
                                                   "candidate": str(done.candidate_id),
                                                   "kind": "replayed" if done.replayed else "recorded"})
        return done
