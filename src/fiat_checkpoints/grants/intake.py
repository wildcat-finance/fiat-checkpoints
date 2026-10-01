"""Announce, endorsement, status and proof of possession for one authenticated actor.

Each operation takes the numeric actor that `auth.sessions` authenticated and
the service clock's `now`, loads the run's verified projection, and checks the
permission it needs before touching anything else: `announce` to announce,
`upload` for the endorsement's own grant, `read_status` to read. A run the
actor holds no current grant in, a candidate of another actor and an id that
does not exist all refuse as `not_found`. See adr/bind-uploads-to-enrolled-keys.
"""

from dataclasses import dataclass
from datetime import datetime
import re
import uuid

from fiat_checkpoints.auth.refusals import RETRY_AFTER_SECONDS, AuthRefusal
from fiat_checkpoints.domain.coordination import GIB, AnnounceRequest, candidate_uuid, positive_int, require_now
from fiat_checkpoints.domain.identities import CheckpointIdentities, IdentityMismatch
from fiat_checkpoints.grants.endorsement import EndorsementStore, check_binding
from fiat_checkpoints.grants.projection import MAX_TRUST_ENVELOPE_BYTES, signature_refusal
from fiat_checkpoints.persistence.transfer import Transfers
from fiat_checkpoints.records.refusals import RecordRefusal


SHA256 = re.compile(r"[0-9a-f]{64}")
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
ANNOUNCE_FIELDS = frozenset({"run", "identities", "carrier_length", "parent"})
PROOF_FIELDS = frozenset({"challenge", "signature"})
MAX_SIGNATURE_TEXT = 21_848


@dataclass(frozen=True)
class Announcement:
    candidate_id: uuid.UUID
    replayed: bool
    state: str
    expires_at: datetime
    nonce: str
    not_before: datetime
    policy: dict
    upload: dict | None


@dataclass(frozen=True)
class Status:
    candidate_id: uuid.UUID
    state: str
    code: str | None
    retry_after_seconds: int | None = None


@dataclass(frozen=True)
class ProofRecorded:
    challenge_sha256: str
    replayed: bool


def _object(value, fields):
    if type(value) is not dict or set(value) != fields:
        raise AuthRefusal("request_invalid", "body-fields")
    return value


def _sha256_reference(value, kind):
    _object(value, {"type", "sha256"})
    if value["type"] != kind or type(value["sha256"]) is not str or SHA256.fullmatch(value["sha256"]) is None:
        raise AuthRefusal("request_invalid", "body-reference")
    return value["sha256"]


def _run_reference(value):
    _object(value, {"repository_id", "run_id"})
    if (type(value["repository_id"]) is not int or not 1 <= value["repository_id"] <= 2**63 - 1
            or type(value["run_id"]) is not str or RUN_ID.fullmatch(value["run_id"]) is None):
        raise AuthRefusal("request_invalid", "body-run")
    return value["repository_id"], value["run_id"]


class Intake:
    """The authenticated intake operations of Step 4, over Step 3's coordinator."""

    def __init__(self, database, coordinator, projections, *, carrier_max_bytes=GIB):
        positive_int(carrier_max_bytes, GIB)
        self.database = database
        self.coordinator = coordinator
        self.projections = projections
        self.endorsements = EndorsementStore(database)
        self.carrier_max_bytes = carrier_max_bytes

    def announce(self, actor_id, key, body, now):
        """Announce one exact submission under a current `announce` grant and bind its challenge.

        A replay of the same announce returns the candidate's current
        challenge, and the next one once an endorsement has spent it.
        """
        positive_int(actor_id)
        now = require_now(now)
        _object(body, ANNOUNCE_FIELDS)
        repository_id, run_id = _run_reference(body["run"])
        try:
            identities = CheckpointIdentities.from_protocol(body["identities"])
        except IdentityMismatch:
            raise AuthRefusal("request_invalid", "body-identities") from None
        length = body["carrier_length"]
        if type(length) is not int or not 1 <= length <= self.carrier_max_bytes:
            raise AuthRefusal("request_invalid", "body-length")
        parent = _sha256_reference(body["parent"], "parent-link")
        run = self.projections.run(repository_id, run_id)
        projection = self.projections.current(run)
        projection.grant(actor_id, "announce", now)
        request = AnnounceRequest(identities.archive_sha256, length, {
            "snapshot_id": identities.snapshot_id,
            "controller_manifest_sha256": identities.controller_manifest_sha256,
            "parent": {"type": "parent-link", "sha256": parent}})
        announced = self.coordinator.announce(run.scope, actor_id, key, request, now)
        challenge = self.endorsements.bind(announced.candidate_id, identities, parent, now)
        view = self.coordinator.candidate(run.scope, actor_id, announced.candidate_id)
        return Announcement(announced.candidate_id, announced.replayed, view.state.value, announced.expires_at,
                            challenge.nonce, challenge.not_before, projection.policy,
                            projection.upload_terms(actor_id, now))

    def endorse(self, actor_id, candidate_id, envelope, now):
        """Authenticate, bind and record one upload endorsement for the actor's own candidate."""
        positive_int(actor_id)
        now = require_now(now)
        if type(envelope) is not bytes or not 0 < len(envelope) <= MAX_TRUST_ENVELOPE_BYTES:
            raise AuthRefusal("request_invalid", "endorsement-bounds")
        binding = self.endorsements.binding(actor_id, candidate_id)
        run = self.projections.run_for(binding.scope)
        projection = self.projections.current(run)
        verified = projection.authenticate(envelope)
        record = verified.record
        binding = self.endorsements.named(binding, record.get("nonce") if type(record) is dict else None)
        terms = check_binding(record, binding, actor_id, now)
        projection.named_grant(terms.grant, actor_id, "upload", now)
        return self.endorsements.record(binding, verified, terms, (projection.count, projection.tail), now)

    def status(self, actor_id, candidate_id, now):
        """The actor's own candidate state under a current `read_status` grant."""
        positive_int(actor_id)
        now = require_now(now)
        binding = self.endorsements.binding(actor_id, candidate_uuid(candidate_id))
        run = self.projections.run_for(binding.scope)
        self.projections.current(run).grant(actor_id, "read_status", now)
        view = self.coordinator.candidate(run.scope, actor_id, binding.candidate_id)
        # A candidate the service is retrying after a dependency failure gives
        # the same bounded wait as a 503 refusal (sections 13 and 16).
        retry = RETRY_AFTER_SECONDS[503] if view.retry_reason is not None and view.terminal_code is None else None
        code = view.terminal_code
        # One whose 16 upload attempts have all failed can only be reannounced,
        # as a new attempt's 410 says; it stays uploading until its deadline.
        if code is None and Transfers.from_coordinator(self.coordinator).attempts_spent(binding.candidate_id, now):
            code = "candidate_expired"
        return Status(view.candidate_id, view.state.value, code, retry)

    def prove_enrollment(self, actor_id, repository_id, run_id, body, now):
        """Record the authenticated actor's proof of possession for its own operator challenge.

        The proof is the signature the operator will embed in the key
        enrollment; the released check verifies it again then. Recording it
        grants nothing: only the operator's signed enrollment and grant do.
        """
        positive_int(actor_id)
        now = require_now(now)
        _object(body, PROOF_FIELDS)
        challenge_sha256 = _sha256_reference(body["challenge"], "enrollment-challenge")
        signature = body["signature"]
        if type(signature) is not str or not 0 < len(signature) <= MAX_SIGNATURE_TEXT:
            raise AuthRefusal("request_invalid", "body-signature")
        run = self.projections.run(repository_id, run_id)
        projection = self.projections.current(run)
        challenge = projection.challenge(challenge_sha256)
        if challenge["actor_id"] != actor_id:
            raise AuthRefusal("not_found", "challenge-unknown")
        issued = datetime.fromisoformat(challenge["issued_at"])
        expires = datetime.fromisoformat(challenge["expires_at"])
        if not issued <= now < expires:
            raise AuthRefusal("signer_not_enrolled", "challenge-expired")
        try:
            run.records.verify_proof(challenge, signature)
        except RecordRefusal as error:
            raise signature_refusal(error, "signer_not_enrolled", "proof-refused") from None
        run_key = self.projections.run_key(run, now)

        def work(connection):
            connection.execute("INSERT INTO actors (actor_id, first_seen_at) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                               (actor_id, now))
            inserted = connection.execute(
                "INSERT INTO enrollment_proofs (run_key, challenge_sha256, actor_id, signature, recorded_at) "
                "VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING RETURNING challenge_sha256",
                (run_key, challenge_sha256, actor_id, signature, now)).fetchone()
            if inserted is not None:
                return ProofRecorded(challenge_sha256, False)
            existing = connection.execute(
                "SELECT actor_id, signature FROM enrollment_proofs WHERE run_key = %s AND challenge_sha256 = %s",
                (run_key, challenge_sha256)).fetchone()
            if existing is None or (existing["actor_id"], existing["signature"]) != (actor_id, signature):
                return AuthRefusal("idempotency_conflict", "proof-conflict")
            return ProofRecorded(challenge_sha256, True)

        result = self.database.transaction(work)
        if isinstance(result, AuthRefusal):
            raise result
        return result
