"""The real pinned native sequence on the released valid fixture, inside gVisor.

Inspect, a fresh restore, verify with observations and identity run on one
exact input with current-attempt exits, complete commit-signature coverage and
the injected public trust. A false identity, a stale result and a signer the
approved history does not cover each refuse with no evidence.
"""

import unittest

from fiat_checkpoints.validation import fixture, outputs, pins
from fiat_checkpoints.validation.outputs import NativeEvidence
from fiat_checkpoints.validation.refusals import ValidationRefusal
from fiat_checkpoints.validation.trust import RunTrust
from tests.validation_support import SandboxCase, expected, library, request, trust, unenrolled_trust


class NativeSequenceTests(SandboxCase):
    def test_valid_fixture_passes_every_stage_with_complete_coverage(self):
        outcome, run = self.valid_job()
        self.assertIsInstance(outcome, NativeEvidence, getattr(outcome, "reason", None))
        record = outcome.record
        value, _ = fixture.released(self.release)
        self.assertEqual(["inspect", "restore", "verify", "identity"], [row["stage"] for row in record["native_results"]])
        self.assertTrue(all(row["exit"] == 0 for row in record["native_results"]))
        self.assertEqual(value["snapshot_id"], record["identity"]["snapshot_id"])
        self.assertEqual(sorted(value["required"]), record["coverage"]["required"])
        self.assertEqual(sorted(value["historical_required"]), record["coverage"]["historical_required"])
        self.assertEqual(4, len(record["coverage"]["verified"]))
        self.assertEqual(trust().public_trust_sha256(), record["public_trust_sha256"])
        self.assertEqual([{"name": item.name, "sha256": item.sha256}
                          for item in (pins.tool(name) for name in pins.NATIVE_TOOLS)], record["tools"])
        self.assertEqual(((("key-enrollment", fixture.TEST_ENROLLMENT), value["fingerprint"]),), outcome.signers)
        self.assertLess(run.resources["wall_ms"], 900_000)
        self.assertLessEqual(len(run.stdout), 65_536)

    def test_false_announced_identity_refuses_before_restore(self):
        outcome, _ = self.valid_job(snapshot_id="0" * 64)
        self.assertIsInstance(outcome, ValidationRefusal)
        self.assertEqual(("identity_mismatch", "native-inspect-input"), (outcome.code, outcome.protocol_code))
        outcome, _ = self.valid_job(controller_manifest_sha256="0" * 64)
        self.assertEqual(("identity_mismatch", "native-controller-manifest"), (outcome.code, outcome.protocol_code))

    def test_signer_outside_the_approved_history_refuses(self):
        narrow = fixture.run_trust(self.release, first_step=2, last_step=2)
        outcome, _ = fixture.run(self.sandbox, self.release, fixture.valid_archive(self.release), request(),
                                 narrow, binds=self.binds)
        self.assertIsInstance(outcome, ValidationRefusal)
        self.assertEqual("signer_not_enrolled", outcome.code)

    def test_a_signer_absent_from_the_injected_keys_is_signer_not_enrolled(self):
        # S6-R1-02: git cannot verify the fixture's commits with only the synthetic key in
        # the keyring, so the coverage stage fails; that rejects instead of retrying.
        outcome, run = fixture.run(self.sandbox, self.release, fixture.valid_archive(self.release), request(),
                                   unenrolled_trust(), binds=self.binds)
        self.assertIsInstance(outcome, ValidationRefusal)
        self.assertEqual(("signer_not_enrolled", "coverage-signer-unapproved", None),
                         (outcome.code, outcome.reason, outcome.protocol_code))
        self.assertIsNone(run.killed)

    def test_a_previous_jobs_output_is_stale_for_the_next(self):
        _, first = self.valid_job(attempt="first-attempt")
        with self.assertRaises(ValidationRefusal) as caught:
            outputs.read(first, expected("f" * 32, request(attempt="second-attempt")), library())
        self.assertEqual("sandbox-output-stale", caught.exception.reason)
        with self.assertRaises(ValidationRefusal) as caught:
            outputs.read(first, expected(first.job_id, request(attempt="second-attempt")), library())
        self.assertIn(caught.exception.reason, ("sandbox-output-stale", "native-result-stale"))

    def test_malformed_trust_document_is_validation_failed(self):
        from fiat_checkpoints.validation.sandbox import SandboxJob
        from fiat_checkpoints.validation.service import sandbox_argv
        run = self.sandbox.run(SandboxJob(owner="malformed", argv=sandbox_argv(), trust=b'{"schema":"other"}',
                                          binds=self.binds))
        with self.assertRaises(ValidationRefusal) as caught:
            outputs.read(run, expected("0" * 32), library())
        self.assertEqual("validation_failed", caught.exception.code)


if __name__ == "__main__":
    unittest.main()
