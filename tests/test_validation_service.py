"""One validation job from a sealed quarantine object to an immutable intent.

The database, gateway, staging broker and quarantine store are real; the
sandbox is replaced by a stand-in that answers as the runner would, so this
group starts no process. A pass records exactly one intent bound to the exact
input; a deterministic refusal rejects; a tool failure, an outage, a moved
trust head or a missing sandbox keeps the candidate for a retry with no intent.
"""

from datetime import timedelta
import hashlib
from types import SimpleNamespace
import unittest

from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.domain.identities import CheckpointIdentities
from fiat_checkpoints.domain.transitions import Evidence
from fiat_checkpoints.validation import fixture
from fiat_checkpoints.validation.refusals import ValidationRefusal
from fiat_checkpoints.validation.sandbox import Sandbox, SandboxRun
from fiat_checkpoints.validation.service import Validator
from fiat_checkpoints.validation.trust import canonical
from tests.persistence_support import key, request as announce_request
from tests.upload_support import ACTOR, PARENT, SCOPE, UploadCase, sha256
from tests.validation_support import library, native_record, release, result_line


class FakeProjection:
    def __init__(self, registration, *, count=5, tail="4" * 64):
        self.registration = registration
        self.count, self.tail = count, tail
        self.refusal = None
        self.accepted = (SimpleNamespace(record_type="run-registration", record=registration,
                                         envelope_sha256="3" * 64),)

    def named_grant(self, grant, actor_id, permission, now):
        if self.refusal is not None:
            raise self.refusal
        return grant

    def historical_signers(self, signers):
        return [named for named, _ in signers]


class FakeProjections:
    def __init__(self, projection):
        self.projection = projection
        self.later = None
        self.calls = 0

    def run(self, repository_id, run_id):
        if (repository_id, run_id) != (SCOPE.repository_id, SCOPE.run_id):
            raise AuthRefusal("not_found", "run-unknown")
        return SimpleNamespace(scope=SCOPE, key=(repository_id, run_id))

    def current(self, run):
        self.calls += 1
        if self.later is not None and self.calls > 1:
            return self.later
        return self.projection


class FakeSandbox:
    """Answers like the runner: reads the job document and replies for that job."""

    def __init__(self):
        self.jobs, self.reply, self.unavailable = [], "complete", None

    def check(self):
        if self.unavailable:
            raise ValidationRefusal("sandbox_unavailable", "sandbox-runtime-missing")
        return True

    def run(self, job):
        self.check()
        document = library().canonical.decode(job.trust, require_canonical=True)
        self.jobs.append((job, document))
        job_id, job_request = document["job_id"], document["request"]
        if callable(self.reply):
            return self.reply(job_id, job_request)
        if self.reply == "complete":
            stdout = result_line(job_id, record=native_record(job_request))
        elif self.reply == "refused":
            stdout = result_line(job_id, status="refused", refusal={
                "code": "native-command-failed", "stage": "inspect", "protocol_code": "entry-name-policy"})
        elif self.reply == "killed":
            return SandboxRun(job_id, None, b"", "0" * 64, 0, "memory-limit", {"wall_ms": 1})
        else:
            stdout = b"Traceback (most recent call last)\n"
        return SandboxRun(job_id, 0, stdout, "0" * 64, 0, None, {"wall_ms": 1})


class ValidationServiceTests(UploadCase):
    def setUp(self):
        super().setUp()
        self.release = release()
        self.value, _ = fixture.released(self.release)
        self.archive = fixture.valid_archive(self.release)
        anchor = hashlib.sha256(canonical(self.value["original_outputs"]["identity"]["identity"]["run"])).hexdigest()
        self.registration = {"native_anchor_sha256": anchor, "initial_base": self.value["initial_base"],
                             "root_authorized": True, "initial_parent": None}
        self.projection = FakeProjection(self.registration)
        self.projections = FakeProjections(self.projection)
        self.sandbox = FakeSandbox()
        (self.root / "jobs").mkdir(mode=0o700)
        self.validator = Validator(self.transfers, self.quarantine, self.sandbox, self.release, self.projections,
                                   fixture.fixed_trust(self.release), staging_root=self.root / "jobs",
                                   clock=self.clock)

    def sealed_fixture(self, label="fixture"):
        """Announce, endorse (as Step 4 records it), upload and seal the released fixture."""
        identities = CheckpointIdentities(self.value["snapshot_id"], self.value["controller_manifest_sha256"],
                                          sha256(self.archive))
        announced = self.coordinator.announce(SCOPE, ACTOR, key(label),
                                              announce_request(sha256(self.archive), len(self.archive)),
                                              self.clock_now)
        candidate = announced.candidate_id
        challenge = self.endorsements.bind(candidate, identities, PARENT, self.clock_now)
        envelope = b'{"synthetic-endorsement":"' + label.encode() + b'"}'
        connection = self.database.connect()
        try:
            connection.execute(
                "INSERT INTO upload_endorsements (candidate_id, sequence, envelope, envelope_sha256, policy_sha256, "
                "enrollment_sha256, grant_sha256, key_fingerprint, trust_count, trust_tail_sha256, issued_at, "
                "expires_at, verified_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1, %s, %s, %s, %s)",
                (candidate, challenge.sequence, envelope, sha256(envelope), "7" * 64, "8" * 64, "6" * 64,
                 "9" * 64, "4" * 64, self.clock_now, self.clock_now + timedelta(seconds=120), self.clock_now))
        finally:
            connection.close()
        capability = self.issuer.issue(ACTOR, candidate, self.clock_now)
        response = self.upload(candidate, capability, self.archive)
        self.assertEqual(202, response.status, response.body)
        self.assertEqual("quarantined", self.state(candidate))
        return candidate

    def intents(self, candidate):
        return self.query("SELECT * FROM publication_intents WHERE candidate_id = %s", (candidate,))

    def test_pass_records_one_intent_bound_to_the_exact_input(self):
        candidate = self.sealed_fixture()
        outcome = self.validator.run_once()
        self.assertIsNone(outcome.refusal, outcome.refusal)
        self.assertEqual("publishing", self.state(candidate))
        [intent] = self.intents(candidate)
        self.assertEqual((sha256(self.archive), self.value["snapshot_id"], self.value["controller_manifest_sha256"]),
                         (intent["archive_sha256"], intent["snapshot_id"], intent["controller_manifest_sha256"]))
        evidence = library().canonical.decode(bytes(intent["evidence"]), require_canonical=True)
        self.assertEqual("fiat-checkpoints-validation-evidence/v1", evidence["schema"])
        self.assertEqual(outcome.job_id, evidence["job_id"])
        self.assertEqual({"type": "parent-link", "sha256": PARENT}, evidence["parent"])
        self.assertFalse(evidence["coverage"]["accepted"])
        self.assertFalse(evidence["coverage"]["parent_link_record_verified"])
        job, document = self.sandbox.jobs[0]
        self.assertEqual(sha256(self.archive), job.input_sha256)
        self.assertEqual(len(self.archive), document["request"]["carrier_length"])
        self.assertEqual(candidate.hex, job.owner)
        self.assertEqual([], [entry for entry in (self.root / "jobs").iterdir()])

    def test_protocol_refusal_rejects_without_an_intent(self):
        candidate = self.sealed_fixture()
        self.sandbox.reply = "refused"
        outcome = self.validator.run_once()
        self.assertEqual(("protocol_refused", "entry-name-policy"), (outcome.refusal.code, outcome.refusal.protocol_code))
        self.assertEqual("rejected", self.state(candidate))
        self.assertEqual([], self.intents(candidate))

    def test_tool_failures_and_kills_retry_without_an_intent(self):
        for reply in ("garbage", "killed"):
            with self.subTest(reply=reply):
                candidate = self.sealed_fixture() if reply == "garbage" else candidate
                self.sandbox.reply = reply
                outcome = self.validator.validate(self.transfers.claim_validation(
                    {Evidence.ISOLATED_WORKER},
                    self.advance(600)))
                self.assertEqual("validation_failed", outcome.refusal.code)
                self.assertEqual("validating", self.state(candidate))
                self.assertEqual([], self.intents(candidate))

    def test_missing_sandbox_claims_nothing_and_never_falls_back(self):
        candidate = self.sealed_fixture()
        self.sandbox.unavailable = True
        self.assertIsNone(self.validator.run_once())
        self.assertEqual("quarantined", self.state(candidate))
        real = Validator(self.transfers, self.quarantine, Sandbox(runsc=self.root / "no-runsc"), self.release,
                         self.projections, fixture.fixed_trust(self.release), staging_root=self.root / "jobs",
                         clock=self.clock)
        self.assertIsNone(real.run_once())
        self.assertEqual("quarantined", self.state(candidate))

    def test_trust_head_moving_during_the_job_retries(self):
        candidate = self.sealed_fixture()
        self.projections.later = FakeProjection(self.registration, count=6, tail="5" * 64)
        outcome = self.validator.run_once()
        self.assertEqual(("policy_unavailable", "trust-head-moved"), (outcome.refusal.code, outcome.refusal.reason))
        self.assertEqual("validating", self.state(candidate))
        self.assertEqual([], self.intents(candidate))

    def test_revoked_grant_rejects(self):
        candidate = self.sealed_fixture()
        self.projection.refusal = AuthRefusal("endorsement_invalid", "grant-not-current")
        outcome = self.validator.run_once()
        self.assertEqual(("endorsement_invalid", "grant-not-current"), (outcome.refusal.code, outcome.refusal.reason))
        self.assertEqual("rejected", self.state(candidate))
        self.assertEqual([], self.sandbox.jobs)

    def test_unregistered_or_non_root_run_refuses_before_the_sandbox(self):
        candidate = self.sealed_fixture()
        self.projection.accepted = ()
        outcome = self.validator.run_once()
        self.assertEqual("checkpoint_ineligible", outcome.refusal.code)
        self.assertEqual([], self.sandbox.jobs)
        self.assertEqual("rejected", self.state(candidate))
        other = self.sealed_fixture("other")
        self.projection.accepted = (SimpleNamespace(record_type="run-registration", envelope_sha256="3" * 64,
                                                    record={**self.registration, "root_authorized": False}),)
        outcome = self.validator.run_once()
        self.assertEqual("capability_not_enabled", outcome.refusal.code)
        self.assertEqual("rejected", self.state(other))


    def test_registered_anchor_must_match_the_reminted_run(self):
        candidate = self.sealed_fixture()
        self.registration["native_anchor_sha256"] = "0" * 64
        outcome = self.validator.run_once()
        self.assertEqual(("checkpoint_ineligible", "registration-anchor"), (outcome.refusal.code, outcome.refusal.reason))
        self.assertEqual([], self.intents(candidate))

    def test_stale_result_for_another_request_retries(self):
        candidate = self.sealed_fixture()
        self.sandbox.reply = lambda job_id, job_request: SandboxRun(
            job_id, 0, result_line(job_id, record=native_record({**job_request, "attempt_id": "old"})),
            "0" * 64, 0, None, {"wall_ms": 1})
        outcome = self.validator.run_once()
        self.assertEqual(("validation_failed", "native-result-stale"), (outcome.refusal.code, outcome.refusal.reason))
        self.assertEqual([], self.intents(candidate))


if __name__ == "__main__":
    unittest.main()
