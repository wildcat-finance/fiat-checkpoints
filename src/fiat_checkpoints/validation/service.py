"""One validation job: claim, stage, sandbox, bind, check current trust, record.

The validator never decides from a worker's word. It derives the request from
its own records, stages the sealed quarantine bytes through their descriptor,
runs the released native sequence in a fresh sandbox, reads the bounded
result against that request, then checks what the archive cannot: the run's
registered root anchor and base, approved historical signers, the uploader's
grant at this moment and an unchanged trust head across the whole job. Only
then does it record the immutable publication intent. Every unexpected
exception becomes `validation_failed`; a deterministic refusal rejects the
candidate; an outage keeps it for a retry.
"""

from dataclasses import dataclass
from datetime import timedelta
import hashlib
import logging
import os
from pathlib import Path
import shutil
import tempfile
import uuid

from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.domain.coordination import CoordinationRefusal
from fiat_checkpoints.domain.identities import CheckpointIdentities
from fiat_checkpoints.domain.transitions import Evidence
from fiat_checkpoints.persistence.coordinator import Passed, Refused, Unavailable
from fiat_checkpoints.upload.staging import StagingRefusal, stage_sealed
from fiat_checkpoints.validation import outputs, pins
from fiat_checkpoints.validation.refusals import RETRY_REASON, ValidationRefusal, stage_codes
from fiat_checkpoints.validation.sandbox import SandboxJob
from fiat_checkpoints.validation.trust import canonical, job_document


LOGGER = logging.getLogger("fiat_checkpoints")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())
SCHEMA_EVIDENCE = "fiat-checkpoints-validation-evidence/v1"
EVIDENCE_LIMIT = 65_536
LEASE_MARGIN_SECONDS = 60
CAPABILITIES = "plugins/hexaemeron/skills/fiat/checkpoint-authority/native-capabilities.json"
# What this packet proves and what it leaves to its owners; recorded in every intent.
COVERAGE = {
    "inspect": True, "fresh_restore": True, "verify_observations": True, "identity_reminted": True,
    "commit_signature_coverage": True, "historical_signers_approved": True, "run_and_key_scope": True,
    "registered_root_anchor": True, "trust_head_unchanged": True, "gvisor_isolation": True,
    "parent_link_record_verified": False, "external_freshness_head": False,
    "decompressed_git_object_secret_scan": False, "accepted": False,
}


@dataclass(frozen=True)
class Context:
    """Everything the job binds to, read from the service's own records."""
    candidate_id: uuid.UUID
    actor_id: int
    run: object
    identities: CheckpointIdentities
    declared_size: int
    parent_sha256: str
    endorsement: dict
    sealed: object
    projection: object
    registration: dict
    registration_sha256: str


@dataclass(frozen=True)
class Outcome:
    """What one job did; `refusal` is None only when an intent was recorded."""
    candidate_id: uuid.UUID
    job_id: str | None
    refusal: ValidationRefusal | None
    intent_id: uuid.UUID | None
    resources: dict | None


def _latest_registration(projection):
    found = [item for item in projection.accepted if item.record_type == "run-registration"]
    return found[-1] if found else None


class Validator:
    def __init__(self, transfers, store, sandbox, release, projections, trust, endorsements_database=None, *,
                 staging_root, clock, service_binds=()):
        self.transfers, self.store, self.sandbox = transfers, store, sandbox
        self.release, self.projections, self.trust = release, projections, trust
        self.database = transfers.database if endorsements_database is None else endorsements_database
        self.staging_root, self.clock = Path(staging_root), clock
        self.service_binds = tuple(service_binds)
        library = release.library
        capabilities = library.canonical.decode(
            library.native_io.read(release.authority_root / CAPABILITIES, 1_048_576))
        self.stage_codes = stage_codes(capabilities)

    # Entry points -----------------------------------------------------------

    def run_once(self):
        """Claim one ready job only while an isolated worker is available."""
        try:
            self.sandbox.check()
        except ValidationRefusal as refusal:
            LOGGER.warning("validation-worker-unavailable", extra={"event": "validation-worker-unavailable",
                                                                   "reason": refusal.reason})
            return None
        claim = self.transfers.claim_validation({Evidence.ISOLATED_WORKER}, self.clock())
        return None if claim is None else self.validate(claim)

    def validate(self, claim):
        job_id = resources = None
        try:
            evidence, identities, job_id, resources = self._validate(claim)
            refusal, outcome = None, Passed(identities, evidence, frozenset({
                Evidence.PROTOCOL_CHECKS, Evidence.RECONSTRUCTION, Evidence.IDENTITY,
                Evidence.AUTHORIZATION, Evidence.DENIAL_CHECK}))
        except ValidationRefusal as error:
            refusal = error
            job_id = getattr(error, "job_id", job_id)
            resources = getattr(error, "resources", resources)
        except Exception:
            refusal = ValidationRefusal("validation_failed", "validator-exception")
        if refusal is not None:
            if refusal.deterministic:
                outcome = Refused(refusal.code, frozenset({Evidence.DETERMINISTIC_REFUSAL}))
            else:
                outcome = Unavailable(RETRY_REASON.get(refusal.code, "validation_failed"))
        intent_id = None
        try:
            recorded = self.transfers.complete_validation(claim.lease, outcome, self.clock())
            intent_id = getattr(recorded, "intent_id", None)
        except CoordinationRefusal as error:
            if refusal is None:
                refusal = ValidationRefusal("validation_failed", "completion-" + str(error.code).replace("_", "-"))
        LOGGER.info("validation-finished", extra={
            "event": "validation-finished", "candidate": str(claim.lease.candidate_id),
            "attempt": claim.lease.attempt_number, "fence": claim.lease.fence, "job": job_id,
            "code": None if refusal is None else refusal.code,
            "reason": "intent-recorded" if refusal is None else refusal.reason,
            "protocol_code": None if refusal is None else refusal.protocol_code})
        return Outcome(claim.lease.candidate_id, job_id, refusal, intent_id, resources)

    # One job ---------------------------------------------------------------

    def _validate(self, claim):
        now = self.clock()
        context = self._context(claim, now)
        head = (context.projection.count, context.projection.tail)
        run_trust = self.trust.for_candidate(context)
        request = {"attempt_id": "attempt-%d-%d" % (claim.lease.attempt_number, claim.lease.fence),
                   "lease_id": "lease-%d" % claim.lease.fence, "candidate_id": context.candidate_id.hex,
                   "outer_sha256": context.identities.archive_sha256,
                   "snapshot_id": context.identities.snapshot_id,
                   "controller_manifest_sha256": context.identities.controller_manifest_sha256,
                   "carrier_length": context.declared_size}
        lease_left = int((claim.lease.expires_at - now).total_seconds()) - LEASE_MARGIN_SECONDS
        if lease_left < 1:
            raise ValidationRefusal("validation_failed", "lease-too-short")
        evidence, job_id, resources = self._sandboxed(context, request, run_trust, lease_left)
        signers = self.trust.approve(context, evidence.signers)
        self._root(context, evidence)
        later = self.clock()
        current = self.projections.current(context.run)
        if (current.count, current.tail) != head:
            raise ValidationRefusal("policy_unavailable", "trust-head-moved")
        self._scope(current, context, later)
        record = {
            "schema": SCHEMA_EVIDENCE, "candidate_id": context.candidate_id.hex,
            "validation_attempt": claim.lease.attempt_number, "fence": claim.lease.fence, "job_id": job_id,
            "input": {"archive_sha256": context.identities.archive_sha256, "length": context.declared_size,
                      "upload_attempt": claim.input_attempt},
            "identities": {"snapshot_id": context.identities.snapshot_id,
                           "controller_manifest_sha256": context.identities.controller_manifest_sha256,
                           "archive_sha256": context.identities.archive_sha256},
            "native_result": evidence.record, "native_result_sha256": evidence.sha256,
            "trust": {"public_trust_sha256": run_trust.public_trust_sha256(),
                      "approval_sha256": hashlib.sha256(canonical(run_trust.approval())).hexdigest(),
                      "historical_signers": signers},
            "endorsement": context.endorsement, "registration_sha256": context.registration_sha256,
            "parent": {"type": "parent-link", "sha256": context.parent_sha256},
            "trust_head": {"count": head[0], "tail": head[1]},
            "release": {"lock_sha256": self.release.lock_sha256, "trees_sha256": self.release.trees_sha256},
            "pins": pins.record(), "resources": resources, "coverage": COVERAGE,
            "started_at": now.isoformat(), "finished_at": later.isoformat(),
        }
        payload = canonical(record)
        if len(payload) > EVIDENCE_LIMIT:
            raise ValidationRefusal("validation_failed", "evidence-limit")
        return payload, context.identities, job_id, resources

    def _context(self, claim, now):
        candidate_id = claim.lease.candidate_id

        def read(connection):
            return connection.execute(
                "SELECT c.actor_id, c.archive_sha256, c.declared_size, r.service_id, r.repository_id, r.run_id, "
                "u.sequence, u.envelope_sha256, u.enrollment_sha256, u.grant_sha256, u.key_fingerprint, "
                "e.snapshot_id, e.controller_manifest_sha256, e.parent_sha256 "
                "FROM candidates c JOIN run_registrations r USING (run_key) "
                "JOIN upload_endorsements u ON u.candidate_id = c.candidate_id "
                "JOIN endorsement_challenges e ON e.candidate_id = u.candidate_id AND e.sequence = u.sequence "
                "WHERE c.candidate_id = %s ORDER BY u.sequence DESC LIMIT 1", (candidate_id,)).fetchone()

        try:
            row = self.database.transaction(read)
        except CoordinationRefusal:
            raise ValidationRefusal("policy_unavailable", "context-unavailable") from None
        if row is None:
            raise ValidationRefusal("endorsement_invalid", "endorsement-absent")
        if row["archive_sha256"] != claim.archive_sha256 or row["declared_size"] != claim.declared_size:
            raise ValidationRefusal("authority_unavailable", "candidate-binding-changed")
        try:
            run = self.projections.run(row["repository_id"], row["run_id"])
            projection = self.projections.current(run)
        except AuthRefusal:
            raise ValidationRefusal("policy_unavailable", "projection-unavailable") from None
        if run.scope.service_id != row["service_id"]:
            raise ValidationRefusal("authority_unavailable", "run-scope-changed")
        registration = _latest_registration(projection)
        if registration is None:
            raise ValidationRefusal("checkpoint_ineligible", "run-unregistered")
        record = registration.record
        if record.get("root_authorized") is not True or record.get("initial_parent") is not None:
            raise ValidationRefusal("capability_not_enabled", "parent-semantics-unsupported")
        endorsement = {"sequence": row["sequence"], "envelope_sha256": row["envelope_sha256"],
                       "enrollment_sha256": row["enrollment_sha256"], "grant_sha256": row["grant_sha256"]}
        context = Context(candidate_id, row["actor_id"], run,
                          CheckpointIdentities(row["snapshot_id"], row["controller_manifest_sha256"],
                                               row["archive_sha256"]),
                          row["declared_size"], row["parent_sha256"], endorsement, None, projection, record,
                          registration.envelope_sha256)
        self._scope(projection, context, now)
        try:
            sealed = self.transfers.sealed_object(candidate_id, claim.input_attempt)
        except CoordinationRefusal:
            raise ValidationRefusal("storage_unavailable", "sealed-input-missing") from None
        if sealed.sealed_size != claim.declared_size or sealed.sealed_sha256 != claim.archive_sha256:
            raise ValidationRefusal("authority_unavailable", "sealed-input-binding")
        return Context(**{**context.__dict__, "sealed": sealed})

    @staticmethod
    def _scope(projection, context, now):
        """The uploader's own grant, and so its enrollment, must be current now."""
        try:
            projection.named_grant({"type": "run-grant", "sha256": context.endorsement["grant_sha256"]},
                                   context.actor_id, "upload", now)
        except AuthRefusal:
            raise ValidationRefusal("endorsement_invalid", "grant-not-current") from None

    def _sandboxed(self, context, request, run_trust, lease_left):
        directory = tempfile.mkdtemp(prefix="job-", dir=self.staging_root)
        staged = None
        try:
            try:
                staged = stage_sealed(self.store, context.sealed, directory)
            except StagingRefusal as error:
                if error.code == "staging_mismatch":
                    raise ValidationRefusal("authority_unavailable", "staging-mismatch") from None
                raise ValidationRefusal("storage_unavailable", "staging-unavailable") from None
            job_id = os.urandom(16).hex()
            trust_bytes = job_document(job_id, request, run_trust)
            run = self.sandbox.run(SandboxJob(
                owner=context.candidate_id.hex, argv=sandbox_argv(), trust=trust_bytes,
                input_fd=staged.descriptor, input_sha256=staged.sha256, input_length=staged.size,
                binds=self.service_binds, wall_seconds=lease_left))
        finally:
            if staged is not None:
                staged.close()
            shutil.rmtree(directory, ignore_errors=True)
        expected = outputs.Expected(job_id, request, tuple(pins.tool(name) for name in pins.NATIVE_TOOLS),
                                    run_trust.public_trust_sha256(), self.stage_codes)
        try:
            evidence = outputs.read(run, expected, self.release.library)
        except ValidationRefusal as refusal:
            refusal.job_id, refusal.resources = job_id, run.resources
            raise
        return evidence, job_id, run.resources

    def _root(self, context, evidence):
        """Root-anchor profile: the native run anchor and base are the registered ones."""
        identity = evidence.record["identity"]["identity"]
        anchor = hashlib.sha256(canonical(identity["run"])).hexdigest()
        if (anchor != context.registration["native_anchor_sha256"]
                or identity["run"]["initial_base_sha"] != context.registration["initial_base"]):
            raise ValidationRefusal("checkpoint_ineligible", "registration-anchor")


def sandbox_argv():
    """The fixed argv a validation job runs; no field of any record enters it."""
    return (pins.SANDBOX_PYTHON, "-I", "-B", pins.SANDBOX_SERVICE + "/src/fiat_checkpoints/validation/runner.py",
            pins.SANDBOX_SERVICE, pins.SANDBOX_TREES, pins.SANDBOX_TRUST, pins.SANDBOX_JOB)


def service_binds(repository):
    """Bind a checkout's service code and pins over the image copy, for checks only."""
    repository = Path(repository)
    return ((repository / "src", pins.SANDBOX_SERVICE + "/src"),
            (repository / "protocol.lock.json", pins.SANDBOX_SERVICE + "/protocol.lock.json"),
            (repository / "protocol.trees.json", pins.SANDBOX_SERVICE + "/protocol.trees.json"))
