"""Trust enters a job only as approved public keys the supervisor chose.

These checks start no process: the job document, the approved history and
the projection seam that resolves signers through Step 4's records.
"""

import base64
from types import SimpleNamespace
import unittest

from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.validation import fixture, pins
from fiat_checkpoints.validation.refusals import ValidationRefusal
from fiat_checkpoints.validation.trust import (
    FixedTrust, HistoricalKey, ProjectionTrust, RunTrust, canonical, job_document, tool_rows)
from tests.validation_support import JOB_ID, library, release, request, trust


def item(record_type, record, sha256):
    return SimpleNamespace(record_type=record_type, record=record, envelope_sha256=sha256)


class FakeProjection:
    def __init__(self, items, signer_error=None):
        self.accepted = tuple(items)
        self.signer_error, self.asked = signer_error, None

    def historical_signers(self, signers):
        self.asked = signers
        if self.signer_error:
            raise self.signer_error
        return [{"type": named["type"], "sha256": named["sha256"]} for named, _ in signers]


class TrustInjectionTests(unittest.TestCase):
    def test_job_document_is_canonical_and_holds_only_public_trust(self):
        document = job_document(JOB_ID, request(), trust())
        value = library().canonical.decode(document, require_canonical=True)
        self.assertEqual({"schema", "job_id", "mode", "request", "approval", "tools", "case"}, set(value))
        self.assertEqual(request(), value["request"])
        self.assertEqual(["python", "git", "gpg", "gpgconf"], [row["name"] for row in value["tools"]])
        for row in value["approval"]["history"]:
            self.assertEqual("openpgp-v4", row["key"]["format"])
        self.assertNotIn(b"PRIVATE", document)
        self.assertNotIn(b"secret", document.lower())

    def test_the_library_accepts_the_injected_approval(self):
        approval = trust().approval()
        coverage = __import__(library().native.__package__ + ".coverage", fromlist=["ApprovedRun"])
        approved = coverage.ApprovedRun(approval["anchor_sha256"], approval["initial_base"], approval["start_commit"],
                                        tuple(library().canonical.canonical(row) for row in approval["history"]))
        self.assertEqual(1, len(approved.keys()))

    def test_public_trust_digest_matches_the_native_keyring_construction(self):
        _, public = fixture.released(release())
        self.assertEqual(library().canonical.digest(public), trust().public_trust_sha256())

    def test_job_identifier_mode_and_case_are_checked(self):
        for job_id in ("", "X" * 32, "0" * 31, None):
            with self.subTest(job_id=job_id), self.assertRaises(ValidationRefusal):
                job_document(job_id, request(), trust())
        with self.assertRaises(ValidationRefusal):
            job_document(JOB_ID, request(), trust(), mode="shell")
        with self.assertRaises(ValidationRefusal):
            job_document(JOB_ID, request(), trust(), mode="inspect-case")
        with self.assertRaises(ValidationRefusal):
            job_document(JOB_ID, request(), trust(), case={"sha256": "0" * 64, "sidecar": None})

    def test_empty_history_refuses_before_any_job(self):
        empty = RunTrust("a" * 64, "b" * 40, "c" * 40, ())
        with self.assertRaises(ValidationRefusal) as caught:
            empty.approval()
        self.assertEqual("signer_not_enrolled", caught.exception.code)

    def test_malformed_keys_and_run_values_refuse(self):
        good = trust().keys[0]
        for change in ({"fingerprint": "0f" * 20}, {"public": b""}, {"enrollment_type": "run-grant"},
                       {"enrollment_sha256": "A" * 64}, {"actor_id": 0}, {"first_step": 3, "last_step": 2},
                       {"last_step": 4097}):
            values = {**good.__dict__, **change}
            with self.subTest(change=sorted(change)), self.assertRaises(ValidationRefusal):
                RunTrust("a" * 64, "b" * 40, "c" * 40, (HistoricalKey(**values),)).approval()
        with self.assertRaises(ValidationRefusal):
            RunTrust("a" * 64, "b" * 40, "c" * 39, (good,)).approval()
        with self.assertRaises(ValidationRefusal):
            RunTrust("a" * 64, "b" * 40, "c" * 40, (good,) * 129).approval()

    def test_one_fingerprint_with_two_public_keys_refuses(self):
        good = trust().keys[0]
        other = HistoricalKey(good.fingerprint, good.public + b"x", "key-rotation", "b" * 64, 17)
        with self.assertRaises(ValidationRefusal):
            RunTrust("a" * 64, "b" * 40, "c" * 40, (good, other)).public_trust_sha256()

    def test_fixed_trust_approves_only_its_own_pairs(self):
        fixed = FixedTrust(trust())
        pair = (("key-enrollment", fixture.TEST_ENROLLMENT), trust().keys[0].fingerprint)
        self.assertEqual([{"type": "key-enrollment", "sha256": fixture.TEST_ENROLLMENT}], fixed.approve(None, [pair]))
        for signers in ([], [(("key-enrollment", "b" * 64), pair[1])], [(pair[0], "0" * 40)]):
            with self.subTest(signers=signers), self.assertRaises(ValidationRefusal) as caught:
                fixed.approve(None, signers)
            self.assertEqual("signer_not_enrolled", caught.exception.code)

    def test_projection_trust_takes_only_enrolled_openpgp_keys(self):
        public = base64.b64encode(fixture.released(release())[1]).decode()
        fingerprint = trust().keys[0].fingerprint
        projection = FakeProjection([
            item("key-enrollment", {"actor_id": 41, "key": {"format": "openpgp-v4", "public": public,
                                                             "fingerprint": fingerprint}}, "1" * 64),
            item("key-enrollment", {"actor_id": 42, "key": {"format": "spki-p256", "public": "AA==",
                                                             "fingerprint": "f" * 64}}, "2" * 64),
            item("run-grant", {"actor_id": 41}, "3" * 64),
        ])
        context = SimpleNamespace(projection=projection, run=SimpleNamespace(key=(7, "run")),
                                  registration={"native_anchor_sha256": "a" * 64, "initial_base": "b" * 40})
        source = ProjectionTrust(None, {(7, "run"): "c" * 40})
        run_trust = source.for_candidate(context)
        self.assertEqual([("key-enrollment", "1" * 64, 41)],
                         [(key.enrollment_type, key.enrollment_sha256, key.actor_id) for key in run_trust.keys])
        self.assertEqual(("a" * 64, "b" * 40, "c" * 40),
                         (run_trust.anchor_sha256, run_trust.initial_base, run_trust.start_commit))
        signers = [(("key-enrollment", "1" * 64), fingerprint)]
        self.assertEqual([{"type": "key-enrollment", "sha256": "1" * 64}], source.approve(context, signers))
        self.assertEqual([({"type": "key-enrollment", "sha256": "1" * 64}, fingerprint)], projection.asked)

    def test_projection_trust_refusals_are_fixed(self):
        context = SimpleNamespace(projection=FakeProjection([]), run=SimpleNamespace(key=(7, "run")),
                                  registration={"native_anchor_sha256": "a" * 64, "initial_base": "b" * 40})
        with self.assertRaises(ValidationRefusal) as caught:
            ProjectionTrust(None, {}).for_candidate(context)
        self.assertEqual("checkpoint_ineligible", caught.exception.code)
        with self.assertRaises(ValidationRefusal) as caught:
            ProjectionTrust(None, {(7, "run"): "c" * 40}).for_candidate(context).approval()
        self.assertEqual("signer_not_enrolled", caught.exception.code)
        for error, code in ((AuthRefusal("signer_not_enrolled", "historical-signer-binding"), "signer_not_enrolled"),
                            (AuthRefusal("authority_unavailable", "trust-empty"), "policy_unavailable")):
            context.projection = FakeProjection([], signer_error=error)
            with self.subTest(code=code), self.assertRaises(ValidationRefusal) as caught:
                ProjectionTrust(None, {}).approve(context, [(("key-enrollment", "1" * 64), "A" * 40)])
            self.assertEqual(code, caught.exception.code)

    def test_tool_rows_name_the_pinned_image_executables(self):
        self.assertEqual([(item.path, item.sha256) for item in (pins.tool(name) for name in pins.NATIVE_TOOLS)],
                         [(row["path"], row["sha256"]) for row in tool_rows()])
        self.assertEqual(canonical({"b": 1, "a": "é"}), b'{"a":"\\u00e9","b":1}')


if __name__ == "__main__":
    unittest.main()
