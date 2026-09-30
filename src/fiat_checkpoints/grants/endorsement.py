"""Bind one signed upload endorsement to exactly the submission announce recorded.

The released library authenticates the endorsement with the actor's enrolled
key and checks its enrollment and grant at its own `issued_at`. The service
then compares every field it bound itself: the authenticated numeric actor,
the candidate, the nonce announce issued, the run, all three checkpoint
identities by role, the carrier length and the parent link. It also requires
the endorsement to have been signed after its challenge was issued and not
after now, and to be unexpired now. Only then, with the trust head unchanged,
does it record the endorsement, once per challenge.

A candidate can take a fresh endorsement before signer authorization: once an
endorsement has spent the candidate's challenge, a replayed announce issues
the next one. The latest recorded endorsement is the bound one while it is
unexpired, and an earlier one is never bound again. An exact replay of the
bound envelope returns the recorded result; a second envelope for a spent
challenge, an older challenge or an older endorsement refuses. See
adr/bind-uploads-to-enrolled-keys.
"""

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hmac
import logging
import secrets
import uuid

from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.domain.coordination import RunScope, candidate_uuid, positive_int, require_now
from fiat_checkpoints.domain.identities import CheckpointIdentities, IdentityMismatch
from fiat_checkpoints.domain.transitions import PRE_AUTHORIZATION


LOGGER = logging.getLogger("fiat_checkpoints")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())
TERMINAL = ("rejected", "expired", "revoked", "denied", "accepted")
# States in which a candidate may still take a fresh endorsement: before the
# signer authorizes a decision for it.
ENDORSABLE = tuple(state.value for state in PRE_AUTHORIZATION)
# One 300-second endorsement after another across the 24-hour candidate
# lifetime; the migration's check holds the same ceiling.
MAX_CHALLENGES = 288


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
    sequence: int = 1

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


@dataclass(frozen=True)
class BoundEndorsement:
    """The endorsement a later step binds a candidate's upload and decision to."""
    candidate_id: uuid.UUID
    sequence: int
    envelope_sha256: str
    policy_sha256: str
    enrollment_sha256: str
    grant_sha256: str
    key_fingerprint: str
    issued_at: datetime
    expires_at: datetime


def _challenge(row):
    return Challenge(row["candidate_id"], row["nonce"], row["issued_at"], row["sequence"])


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
    """Each candidate's challenges and the verified endorsement of each challenge.

    Every call locks the candidate row before its challenges and endorsements.
    """

    def __init__(self, database):
        self.database = database

    def _run(self, work):
        result = self.database.transaction(work)
        if isinstance(result, AuthRefusal):
            raise result
        return result

    def bind(self, candidate_id, identities, parent_sha256, now):
        """Return the candidate's current challenge, issuing the next one if an endorsement spent it.

        Announce's idempotency fingerprint already covers the bound values, so
        a replayed announce reaches the same candidate; any difference is a
        conflict. A spent challenge is followed by a new one only while the
        candidate can still take an endorsement.
        """
        now = require_now(now)
        nonce = challenge_nonce()

        def work(connection):
            candidate = connection.execute("SELECT archive_sha256, state, expires_at FROM candidates "
                                           "WHERE candidate_id = %s FOR UPDATE", (candidate_id,)).fetchone()
            if candidate is None or candidate["archive_sha256"] != identities.archive_sha256:
                return AuthRefusal("authority_unavailable", "binding-candidate")
            latest = connection.execute("SELECT * FROM endorsement_challenges WHERE candidate_id = %s "
                                        "ORDER BY sequence DESC LIMIT 1", (candidate_id,)).fetchone()
            sequence = 1
            if latest is not None:
                if ((latest["snapshot_id"], latest["controller_manifest_sha256"], latest["parent_sha256"])
                        != (identities.snapshot_id, identities.controller_manifest_sha256, parent_sha256)):
                    return AuthRefusal("idempotency_conflict", "binding-changed")
                spent = connection.execute("SELECT 1 FROM upload_endorsements WHERE candidate_id = %s "
                                           "AND sequence = %s", (candidate_id, latest["sequence"])).fetchone()
                if spent is None or candidate["state"] not in ENDORSABLE or now >= candidate["expires_at"]:
                    return _challenge(latest)
                if latest["sequence"] >= MAX_CHALLENGES:
                    return AuthRefusal("quota_exceeded", "endorsement-limit")
                sequence = latest["sequence"] + 1
            row = connection.execute(
                "INSERT INTO endorsement_challenges (candidate_id, sequence, nonce, snapshot_id, "
                "controller_manifest_sha256, parent_sha256, issued_at) VALUES (%s, %s, %s, %s, %s, %s, %s) "
                "RETURNING *", (candidate_id, sequence, nonce, identities.snapshot_id,
                                identities.controller_manifest_sha256, parent_sha256, now)).fetchone()
            return _challenge(row)

        return self._run(work)

    def binding(self, actor_id, candidate_id):
        """Read one candidate's binding and latest challenge for its own actor; anything else is `not_found`."""
        positive_int(actor_id)
        candidate_id = candidate_uuid(candidate_id)

        def work(connection):
            return connection.execute(
                "SELECT c.candidate_id, c.actor_id, c.state, c.expires_at, c.archive_sha256, c.declared_size, "
                "r.service_id, r.repository_id, r.run_id, e.sequence, e.nonce, e.snapshot_id, "
                "e.controller_manifest_sha256, e.parent_sha256, e.issued_at "
                "FROM candidates c JOIN run_registrations r USING (run_key) "
                "JOIN LATERAL (SELECT * FROM endorsement_challenges x WHERE x.candidate_id = c.candidate_id "
                "ORDER BY x.sequence DESC LIMIT 1) e ON true WHERE c.candidate_id = %s AND c.actor_id = %s",
                (candidate_id, actor_id)).fetchone()

        row = self._run(work)
        if row is None:
            raise AuthRefusal("not_found", "candidate-unknown")
        return CandidateBinding(
            row["candidate_id"], row["actor_id"], RunScope(row["service_id"], row["repository_id"], row["run_id"]),
            row["state"], row["expires_at"],
            CheckpointIdentities(row["snapshot_id"], row["controller_manifest_sha256"], row["archive_sha256"]),
            row["declared_size"], row["parent_sha256"], _challenge(row))

    def named(self, binding, nonce):
        """The binding with the candidate's challenge that carries `nonce`, or unchanged when none does.

        An endorsement is compared with the challenge it names, so an exact
        replay of the bound endorsement still matches after the next challenge
        was issued; whether that challenge may still be spent is `record`'s
        decision.
        """
        if not isinstance(binding, CandidateBinding) or type(nonce) is not str:
            return binding

        def work(connection):
            return connection.execute("SELECT candidate_id, sequence, nonce, issued_at FROM endorsement_challenges "
                                      "WHERE candidate_id = %s AND nonce = %s", (binding.candidate_id, nonce)).fetchone()

        row = self._run(work)
        return binding if row is None else replace(binding, challenge=_challenge(row))

    def record(self, binding, verified, terms, head, now):
        """Record the endorsement once for its challenge, if that challenge is the latest and unspent.

        The candidate row is locked first, then its challenges and
        endorsements, then the run row in share mode, which an ingestion holds
        exclusively while it appends, so the grant just checked is still the
        current one.
        """
        now = require_now(now)
        count, tail = head
        sequence = binding.challenge.sequence

        def work(connection):
            row = connection.execute("SELECT * FROM candidates WHERE candidate_id = %s AND actor_id = %s FOR UPDATE",
                                     (binding.candidate_id, binding.actor_id)).fetchone()
            if row is None:
                return AuthRefusal("not_found", "candidate-unknown")
            if row["state"] in TERMINAL or now >= row["expires_at"]:
                return AuthRefusal("candidate_expired", "candidate-expired")
            named = connection.execute("SELECT nonce FROM endorsement_challenges WHERE candidate_id = %s "
                                       "AND sequence = %s FOR SHARE", (binding.candidate_id, sequence)).fetchone()
            if named is None or named["nonce"] != binding.challenge.nonce:
                return AuthRefusal("authority_unavailable", "binding-changed")
            latest = connection.execute("SELECT max(sequence) AS n FROM endorsement_challenges WHERE candidate_id = %s",
                                        (binding.candidate_id,)).fetchone()["n"]
            bound = connection.execute("SELECT sequence, envelope_sha256, expires_at FROM upload_endorsements "
                                       "WHERE candidate_id = %s ORDER BY sequence DESC LIMIT 1 FOR SHARE",
                                       (binding.candidate_id,)).fetchone()
            spent = connection.execute("SELECT envelope_sha256 FROM upload_endorsements WHERE candidate_id = %s "
                                       "AND sequence = %s", (binding.candidate_id, sequence)).fetchone()
            if spent is not None:
                if spent["envelope_sha256"] != verified.envelope_sha256:
                    return AuthRefusal("endorsement_invalid", "nonce-consumed")
                if bound["sequence"] != sequence:
                    return AuthRefusal("endorsement_invalid", "endorsement-superseded")
                if now >= bound["expires_at"]:
                    return AuthRefusal("endorsement_invalid", "endorsement-expired")
                return Endorsed(binding.candidate_id, bound["envelope_sha256"], bound["expires_at"], True)
            if sequence != latest:
                return AuthRefusal("endorsement_invalid", "challenge-superseded")
            if row["state"] not in ENDORSABLE:
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
                "INSERT INTO upload_endorsements (candidate_id, sequence, envelope, envelope_sha256, policy_sha256, "
                "enrollment_sha256, grant_sha256, key_fingerprint, trust_count, trust_tail_sha256, issued_at, "
                "expires_at, verified_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (binding.candidate_id, sequence, verified.envelope, verified.envelope_sha256, terms.policy_sha256,
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

    def bound(self, actor_id, candidate_id, now, until=None):
        """The candidate's bound endorsement: its latest recorded one, while it stays valid through `until`.

        A later step binds an upload or a decision to this and nothing older.
        `until` defaults to `now`; a caller that must finish inside the
        endorsement's validity, as the released replay requires of an
        acceptance, passes the latest instant it needs, so an endorsement
        that would expire first is refused rather than used and the
        contributor endorses again under a fresh challenge.
        """
        positive_int(actor_id)
        candidate_id = candidate_uuid(candidate_id)
        now = require_now(now)
        until = now if until is None else require_now(until)
        if until < now:
            raise AuthRefusal("authority_unavailable", "bound-window")

        def work(connection):
            return connection.execute(
                "SELECT u.* FROM candidates c JOIN upload_endorsements u USING (candidate_id) "
                "WHERE c.candidate_id = %s AND c.actor_id = %s ORDER BY u.sequence DESC LIMIT 1",
                (candidate_id, actor_id)).fetchone()

        row = self._run(work)
        if row is None:
            raise AuthRefusal("not_found", "endorsement-absent")
        if until >= row["expires_at"]:
            raise AuthRefusal("endorsement_invalid", "endorsement-expired")
        return BoundEndorsement(row["candidate_id"], row["sequence"], row["envelope_sha256"], row["policy_sha256"],
                                row["enrollment_sha256"], row["grant_sha256"], row["key_fingerprint"],
                                row["issued_at"], row["expires_at"])
