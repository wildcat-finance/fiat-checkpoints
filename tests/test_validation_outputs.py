"""A sandbox run is a claim: every malformed, stale or mismatched one refuses.

These checks start no process. They cover the `native-local-errors` carry
(any malformed native output maps to fixed `validation_failed`), stale
output, a failed restore followed by a successful verify, a false identity
and the stage allowlist that keeps raw diagnostics private (Skills #1647).
"""

import copy
import unittest

from fiat_checkpoints.validation import outputs
from fiat_checkpoints.validation.refusals import ValidationRefusal
from tests.validation_support import JOB_ID, expected, library, native_record, request, result_line, run_of


class ValidationOutputTests(unittest.TestCase):
    def read(self, stdout, **run):
        return outputs.read(run_of(stdout, **run), expected(), library())

    def refused(self, stdout, code="validation_failed", reason=None, **run):
        with self.assertRaises(ValidationRefusal) as caught:
            self.read(stdout, **run)
        self.assertEqual(code, caught.exception.code)
        if reason is not None:
            self.assertEqual(reason, caught.exception.reason)
        return caught.exception

    def test_complete_result_binds_signers_and_payload_digest(self):
        record = native_record()
        evidence = self.read(result_line(record=record))
        self.assertIsInstance(evidence, outputs.NativeEvidence)
        self.assertEqual(library().canonical.canonical(record), evidence.payload)
        self.assertEqual(4, len(evidence.record["coverage"]["verified"]))
        self.assertEqual(1, len(evidence.signers))
        self.assertNotIn("0F4C", repr(evidence))

    def test_resource_kills_and_nonzero_exit_are_validation_failed(self):
        for killed in ("memory-limit", "cpu-limit", "wall-limit", "stdout-limit", "stderr-limit"):
            with self.subTest(killed=killed):
                self.refused(result_line(record=native_record()), reason="sandbox-" + killed, killed=killed)
        self.refused(result_line(record=native_record()), reason="sandbox-exit", exit=1)
        self.refused(result_line(record=native_record()), reason="sandbox-exit", exit=None)

    def test_malformed_output_is_validation_failed(self):
        good = result_line(record=native_record())
        cases = {
            "empty": b"", "no-newline": good[:-1], "two-lines": good + good, "not-json": b"Traceback\n",
            "invalid-utf8": b"\xff\xfe\n", "noncanonical": b'{ "schema": 1 }\n', "array": b"[]\n",
            "float": b'{"a":1.5}\n', "duplicate": b'{"a":1,"a":2}\n',
            "nan": b'{"a":NaN}\n', "deep": b"[" * 64 + b"]" * 64 + b"\n",
        }
        for name, stdout in cases.items():
            with self.subTest(case=name):
                self.refused(stdout, "validation_failed")

    def test_missing_extra_and_wrong_top_level_fields_refuse(self):
        record = native_record()
        line = library().canonical.decode(result_line(record=record)[:-1])
        for change in ({"extra": 1}, {"schema": "other/v1"}, {"status": "passed"}):
            value = {**line, **change}
            with self.subTest(change=change):
                self.refused(library().canonical.canonical(value) + b"\n")
        trimmed = dict(line)
        del trimmed["refusal"]
        self.refused(library().canonical.canonical(trimmed) + b"\n")

    def test_runner_error_is_validation_failed(self):
        self.refused(result_line(status="error"), reason="sandbox-runner-error")

    def test_stale_output_from_another_job_refuses(self):
        self.refused(result_line(job_id="f" * 32, record=native_record()), reason="sandbox-output-stale")
        stale = native_record(request(attempt="previous-attempt"))
        self.refused(result_line(record=stale), reason="native-result-stale")

    def test_digest_and_pin_mismatches_refuse(self):
        self.refused(result_line(record=native_record(), digest="0" * 64), reason="native-result-digest")
        for field, value in (("source_commit", "0" * 40), ("profile", "other"),
                             ("executable_sha256", "0" * 64), ("source_profile_sha256", "0" * 64)):
            record = native_record()
            record[field] = value
            with self.subTest(field=field):
                self.refused(result_line(record=record), reason="native-result-pins")
        record = native_record()
        record["tools"][1]["sha256"] = "0" * 64
        self.refused(result_line(record=record), reason="native-result-pins")
        record = native_record()
        record["public_trust_sha256"] = "0" * 64
        self.refused(result_line(record=record), reason="native-result-trust")

    def test_failed_restore_is_never_rescued_by_a_later_verify(self):
        record = native_record()
        record["native_results"][1]["exit"] = 1
        self.refused(result_line(record=record), reason="native-result-stages")
        for index in range(4):
            record = native_record()
            record["native_results"][index]["exit"] = 2
            with self.subTest(stage=index):
                self.refused(result_line(record=record), reason="native-result-stages")
        record = native_record()
        record["native_results"] = record["native_results"][1:]
        self.refused(result_line(record=record), reason="native-result-stages")
        record = native_record()
        record["native_results"][0], record["native_results"][1] = record["native_results"][1], record["native_results"][0]
        self.refused(result_line(record=record), reason="native-result-stages")

    def test_false_carried_identity_refuses(self):
        # The announced identity is false: the reminted one is the archive's own.
        announced = request(snapshot_id="0" * 64)
        record = native_record(announced)
        with self.assertRaises(ValidationRefusal) as caught:
            outputs.read(run_of(result_line(record=record)), expected(job_request=announced), library())
        self.assertEqual(("identity_mismatch", "native-result-identity"),
                         (caught.exception.code, caught.exception.reason))
        record = native_record()
        record["identity"]["snapshot_id"] = "0" * 64
        self.refused(result_line(record=record), "validation_failed", "native-result-malformed")

    def test_claims_that_grant_more_than_execution_refuse(self):
        for field, value in (("complete", False), ("operation_ran", False), ("historical_commands_executed", True),
                             ("current_eligibility", "eligible"), ("service_acceptance", "accepted")):
            record = native_record()
            record[field] = value
            with self.subTest(field=field):
                self.refused(result_line(record=record), reason="native-result-malformed")

    def test_incomplete_or_malformed_coverage_refuses(self):
        record = native_record()
        record["coverage"]["complete"] = False
        self.refused(result_line(record=record), "signer_not_enrolled")
        record = native_record()
        record["coverage"]["verified"] = record["coverage"]["verified"][1:]
        self.refused(result_line(record=record), "signer_not_enrolled")
        record = native_record()
        record["coverage"]["verified"][0]["fingerprint"] = "not-a-fingerprint"
        self.refused(result_line(record=record), "validation_failed")
        record = native_record()
        record["coverage"]["verified"].append(copy.deepcopy(record["coverage"]["verified"][0]))
        self.refused(result_line(record=record), "validation_failed")

    def test_listed_protocol_code_passes_only_at_its_stage(self):
        refusal = self.refused(result_line(status="refused", refusal={
            "code": "native-command-failed", "stage": "inspect", "protocol_code": "entry-name-policy"}),
            "protocol_refused")
        self.assertEqual(("entry-name-policy", "inspect"), (refusal.protocol_code, refusal.stage))
        self.refused(result_line(status="refused", refusal={
            "code": "native-command-failed", "stage": "verify", "protocol_code": "entry-name-policy"}),
            reason="sandbox-protocol-code-unlisted")
        self.refused(result_line(status="refused", refusal={
            "code": "native-input-digest", "stage": "native", "protocol_code": "entry-name-policy"}),
            reason="sandbox-protocol-code-unlisted")

    def test_raw_diagnostics_never_become_a_protocol_code(self):
        # Skills #1647: a signing-key id in a native diagnostic must not leave the job.
        diagnostic = "gpg: key 8CF45B322E7748BF: signature-unverified"
        refusal = self.refused(result_line(status="refused", refusal={
            "code": "native-command-failed", "stage": "restore", "protocol_code": diagnostic}))
        self.assertNotIn("8CF45B322E7748BF", repr(refusal) + str(refusal.record()))
        unmapped = self.refused(result_line(status="refused", refusal={
            "code": "native-command-failed", "stage": "restore", "protocol_code": None}))
        self.assertEqual(("validation_failed", "native-command-unmapped", None),
                         (unmapped.code, unmapped.reason, unmapped.protocol_code))

    def test_adapter_refusals_map_to_fixed_service_codes(self):
        cases = {"native-inspect-input": "identity_mismatch", "native-signer-unapproved": "signer_not_enrolled",
                 "native-immediate-restore-tail": "protocol_refused", "native-tool-pin": "validation_failed",
                 "native-output-shape": "validation_failed", "native-deadline": "validation_failed",
                 "not a code at all": "validation_failed"}
        for code, service in cases.items():
            with self.subTest(code=code):
                self.refused(result_line(status="refused", refusal={"code": code, "stage": "native",
                                                                    "protocol_code": None}), service)

    def test_refused_line_carrying_a_result_refuses(self):
        self.refused(result_line(status="refused", record=native_record(), refusal={
            "code": "native-input-digest", "stage": "native", "protocol_code": None}),
            reason="sandbox-output-malformed")

    def test_inspect_case_success_needs_an_empty_result(self):
        passed = outputs.read(run_of(result_line()), expected(), library(), mode="inspect-case")
        self.assertEqual(JOB_ID, passed.job_id)
        with self.assertRaises(ValidationRefusal):
            outputs.read(run_of(result_line(record=native_record())), expected(), library(), mode="inspect-case")


if __name__ == "__main__":
    unittest.main()
