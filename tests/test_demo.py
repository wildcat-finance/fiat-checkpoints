"""The issue #1 intake-to-validation demonstration and the intent handoff to issue #2.

`IntakeValidationDemoTests` runs the scenario once over real HTTP, the
PostgreSQL 16 test server and the pinned gVisor validator, so it needs
`scripts/sandbox-env.sh run` and starts processes. The other classes start
none: they check production startup refusals, hold the handoff document to
the code's own refusal tables, evidence fields and coverage, and check the
demo's argument refusals.
"""

import contextlib
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from fiat_checkpoints.api.app import StartupRefusal, production_refusals
from fiat_checkpoints.api.gateway import create_gateway_app
from fiat_checkpoints.api.intake import create_intake_app
from fiat_checkpoints.auth.refusals import PROTOCOL_CODE_PUBLIC, PUBLIC_STATUS, RETRY_AFTER_SECONDS
from fiat_checkpoints.conformance import PROTOCOL_CODES, production_settings
from fiat_checkpoints.validation import pins
from fiat_checkpoints.validation.refusals import DETERMINISTIC, SERVICE_CODES
from fiat_checkpoints.validation.sandbox import leftovers
from fiat_checkpoints.validation.service import COVERAGE, SCHEMA_EVIDENCE
from fiat_checkpoints.validation.trust import canonical
from tests import authority_fixtures as fixtures
from tests.auth_support import SETTINGS
from tests.test_demo_scenario import IMAGE_ENVIRONMENT, SCHEMA, DemoRefusal, images, main, run_scenario


ROOT = Path(__file__).resolve().parents[1]
HANDOFF = ROOT / "docs/intent-handoff.md"


class IntakeValidationDemoTests(unittest.TestCase):
    """One authorized upload yields one exact intent; five hostile cases yield none."""

    spawns_child_process = True

    @classmethod
    def setUpClass(cls):
        cls.report = run_scenario()
        cls.cases = cls.report["cases"]

    def tearDown(self):
        self.assertEqual({"jobs": [], "cgroups": []}, leftovers())

    def routes(self, case):
        return [(item["route"], item["status"], item["code"]) for item in self.cases[case]["steps"]]

    def test_every_expectation_holds(self):
        self.assertEqual(self.report["schema"], SCHEMA)
        self.assertTrue(self.report["passed"], self.report["expectations"])

    def test_one_authorized_upload_records_one_exact_intent(self):
        case = self.cases["valid"]
        self.assertEqual(self.routes("valid"), [("announce", 201, None), ("endorsement", 200, None),
                                                ("upload", 202, None), ("complete", 200, None),
                                                ("status", 200, None), ("status", 200, None)])
        self.assertEqual((case["state_before"], case["state"], case["intents"]), ("quarantined", "publishing", 1))
        validation = case["validation"]
        self.assertEqual((validation["claimed"], validation["intent_recorded"], validation["code"]),
                         (True, True, None))
        self.assertLessEqual(validation["wall_ms"], 900_000)
        evidence = self.report["intent"]["evidence"]
        fixture = self.report["fixture"]
        self.assertEqual(evidence["schema"], SCHEMA_EVIDENCE)
        self.assertEqual(evidence["job_id"], validation["job_id"])
        self.assertEqual(evidence["candidate_id"], case["candidate_id"].replace("-", ""))
        self.assertEqual((evidence["input"]["archive_sha256"], evidence["input"]["length"]),
                         (fixture["outer_sha256"], fixture["bytes"]))
        self.assertEqual(evidence["identities"]["snapshot_id"], fixture["snapshot_id"])
        self.assertEqual([row["stage"] for row in evidence["native_result"]["native_results"]],
                         ["inspect", "restore", "verify", "identity"])
        self.assertTrue(evidence["native_result"]["coverage"]["complete"])
        self.assertEqual(evidence["coverage"], COVERAGE)
        self.assertEqual(evidence["pins"], pins.record())

    def test_wrong_actor_gets_no_endorsement_status_or_intent(self):
        self.assertEqual(self.routes("wrong-actor"), [("announce", 201, None), ("endorsement", 404, "not_found"),
                                                      ("status", 404, "not_found"),
                                                      ("endorsement", 422, "identity_mismatch"),
                                                      ("status", 200, None)])
        self.assertEqual((self.cases["wrong-actor"]["state"], self.cases["wrong-actor"]["intents"]), ("announced", 0))

    def test_changed_bytes_never_seal(self):
        self.assertEqual(self.routes("changed-bytes"), [("announce", 201, None), ("endorsement", 200, None),
                                                        ("upload", 422, "upload_integrity"), ("status", 200, None)])
        self.assertEqual((self.cases["changed-bytes"]["state"], self.cases["changed-bytes"]["intents"]),
                         ("uploading", 0))

    def test_forged_carried_identity_is_refused_in_the_sandbox(self):
        case = self.cases["forged-identity"]
        validation = case["validation"]
        self.assertIsNotNone(validation["job_id"])
        self.assertIn(validation["code"], DETERMINISTIC)
        self.assertFalse(validation["intent_recorded"])
        self.assertEqual((case["state"], case["intents"]), ("rejected", 0))
        self.assertEqual(self.routes("forged-identity")[-1], ("status", 200, validation["code"]))

    def test_an_endorsement_for_another_protocol_version_refuses(self):
        self.assertEqual(self.routes("protocol-mismatch"), [("announce", 201, None),
                                                            ("endorsement", 422, "endorsement_invalid"),
                                                            ("status", 200, None)])
        self.assertEqual((self.cases["protocol-mismatch"]["state"], self.cases["protocol-mismatch"]["intents"]),
                         ("announced", 0))

    def test_revoked_scope_is_rejected_before_the_sandbox(self):
        case = self.cases["revoked-scope"]
        self.assertEqual((case["validation"]["code"], case["validation"]["reason"], case["validation"]["job_id"]),
                         ("endorsement_invalid", "grant-not-current", None))
        self.assertEqual((case["state"], case["intents"]), ("rejected", 0))

    def test_unavailable_isolation_claims_nothing(self):
        case = self.cases["unavailable-isolation"]
        self.assertEqual(case["validation"], {"claimed": False})
        self.assertEqual((case["state"], case["intents"]), ("quarantined", 0))

    def test_no_authority_object_or_signature(self):
        authority = self.report["authority"]
        self.assertEqual(authority["trust_records"], authority["operator_records"])
        self.assertEqual((authority["intents"], authority["accepted"], authority["publish_jobs"]), (1, 0, 1))
        evidence = self.report["intent"]["evidence"]
        self.assertFalse({"signature", "signatures", "payloadType", "envelope", "receipt"} & set(evidence))
        self.assertFalse(evidence["coverage"]["accepted"])

    def test_the_report_carries_the_three_image_ids_the_launcher_passed(self):
        self.assertEqual(self.report["images"], {name: os.environ[variable] for name, variable in IMAGE_ENVIRONMENT})

    def test_a_restarted_service_serves_the_same_intent(self):
        restart = self.report["restart"]
        self.assertEqual(restart["state"], "publishing")
        self.assertEqual(restart["evidence_sha256"], self.report["intent"]["evidence_sha256"])

    def test_every_reply_carries_a_request_id_for_correlation(self):
        for name, case in self.cases.items():
            for item in case["steps"]:
                with self.subTest(case=name, route=item["route"]):
                    self.assertRegex(item["request_id"] or "", r"^[0-9a-f]{32}$")


class ProductionStartupTests(unittest.TestCase):
    """The apps the demonstration serves refuse production, and a mismatched protocol lock refuses by its code."""

    def test_production_intake_and_gateway_refuse_to_start(self):
        production = replace(SETTINGS, profile="production")
        expected = production_refusals(production, ROOT)
        self.assertEqual(expected[-2:], ("isolation-unavailable", "scaffold-only"))
        for create in (create_intake_app, create_gateway_app):
            with self.subTest(app=create.__name__), self.assertRaises(StartupRefusal) as caught:
                create(production, object())
            self.assertEqual(caught.exception.codes, expected)

    def test_a_lock_for_another_protocol_release_refuses_startup(self):
        production = production_settings()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copyfile(ROOT / "protocol.trees.json", root / "protocol.trees.json")
            lock = json.loads((ROOT / "protocol.lock.json").read_bytes())
            lock["authority"]["source_commit"] = "0" * 40
            (root / "protocol.lock.json").write_text(json.dumps(lock))
            codes = production_refusals(production, root)
            with self.assertRaises(StartupRefusal) as caught:
                create_intake_app(production, object(), root)
        self.assertIn(codes[0], PROTOCOL_CODES)
        self.assertEqual(caught.exception.codes, codes)
        self.assertEqual(codes[-2:], ("isolation-unavailable", "scaffold-only"))


class DemoArgumentTests(unittest.TestCase):
    """Refusals that happen before any server, database or sandbox starts."""

    def refused(self, argv):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(argv)
        return code, stderr.getvalue().strip()

    def test_only_the_local_intake_validation_scenario_exists(self):
        self.assertEqual(self.refused(["--scenario", "end-to-end", "--profile", "local"]),
                         (2, "demo-refused: scenario-not-enabled"))
        self.assertEqual(self.refused(["--scenario", "intake-validation", "--profile", "production"]),
                         (2, "demo-refused: profile-not-enabled"))

    def test_missing_options_refuse(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(main(["--scenario", "intake-validation"]), 2)


class DemoImageTests(unittest.TestCase):
    """S7-R1-05: the report names the validator, test and PostgreSQL images, or the demonstration refuses."""

    IDS = {"FIAT_IMAGE_VALIDATOR": "sha256:" + "a" * 64, "FIAT_IMAGE_TEST": "sha256:" + "b" * 64,
           "FIAT_IMAGE_POSTGRES": "sha256:" + "c" * 64}

    def test_all_three_ids_are_recorded(self):
        self.assertEqual(images(self.IDS), {"validator": "sha256:" + "a" * 64, "test": "sha256:" + "b" * 64,
                                            "postgres": "sha256:" + "c" * 64})

    def test_a_missing_or_malformed_id_refuses(self):
        for variable in self.IDS:
            for value in (None, "", "sha256:" + "A" * 64, "fiat-checkpoints-test:local", "sha256:" + "a" * 63):
                environ = {name: item for name, item in self.IDS.items() if name != variable}
                if value is not None:
                    environ[variable] = value
                with self.subTest(variable=variable, value=value), self.assertRaises(DemoRefusal) as caught:
                    images(environ)
                self.assertEqual(str(caught.exception), "image-digest-missing")

    def test_the_demonstration_refuses_before_starting_anything(self):
        environ = {name: item for name, item in self.IDS.items() if name != "FIAT_IMAGE_POSTGRES"}
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, environ, clear=True), contextlib.redirect_stderr(stderr), \
                mock.patch("fiat_checkpoints.telemetry.logging.configure_logging"):
            code = main(["--scenario", "intake-validation", "--profile", "local"])
        self.assertEqual((code, stderr.getvalue().strip()), (2, "demo-refused: image-digest-missing"))


class DemoScriptTests(unittest.TestCase):
    spawns_child_process = True

    def test_the_wrapper_runs_the_entry_point_and_keeps_its_refusals(self):
        run = subprocess.run([str(ROOT / "scripts/demo.sh"), "--scenario", "end-to-end", "--profile", "local"],
                             capture_output=True, text=True, timeout=120, check=False,
                             env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp"})
        self.assertEqual((run.returncode, run.stderr.strip(), run.stdout), (2, "demo-refused: scenario-not-enabled", ""))


# The handoff document ---------------------------------------------------------


def section(text, heading):
    """The body under one exact heading, up to the next heading of the same or a higher level."""
    level = len(heading) - len(heading.lstrip("#"))
    lines = text.splitlines()
    start = lines.index(heading) + 1
    for index in range(start, len(lines)):
        match = re.match(r"(#+) ", lines[index])
        if match and len(match.group(1)) <= level:
            return "\n".join(lines[start:index])
    return "\n".join(lines[start:])


def table(body):
    """The data rows of the first Markdown table in `body`, cells stripped of code marks."""
    rows = [line for line in body.splitlines() if line.startswith("|")]
    cells = [[cell.strip().strip("`") for cell in row.strip("|").split("|")] for row in rows]
    return [row for row in cells[2:]]


class HandoffDocumentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = HANDOFF.read_text(encoding="utf-8")
        block = re.search(r"```json\n(.*?)\n```", section(cls.text, "## Example intent"), re.S)
        cls.example = json.loads(block.group(1))

    def test_http_refusals_are_the_codes_statuses_and_waits_the_service_answers(self):
        rows = table(section(self.text, "### HTTP refusals"))
        self.assertEqual({row[0]: int(row[1]) for row in rows}, PUBLIC_STATUS)
        for row in rows:
            with self.subTest(code=row[0]):
                wait = RETRY_AFTER_SECONDS.get(PUBLIC_STATUS[row[0]])
                self.assertEqual(row[2], "none" if wait is None else str(wait))
                self.assertEqual(row[3] == "yes", row[0] in PROTOCOL_CODE_PUBLIC)

    def test_validation_outcomes_are_the_validators_codes_and_classes(self):
        rows = table(section(self.text, "### Validation outcomes"))
        self.assertEqual({row[0] for row in rows}, set(SERVICE_CODES))
        for row in rows:
            with self.subTest(code=row[0]):
                self.assertEqual(row[1], "rejected" if row[0] in DETERMINISTIC else "retried")

    def test_example_intent_is_the_released_schema_built_from_the_released_fixture(self):
        example = self.example
        self.assertEqual(example["schema"], SCHEMA_EVIDENCE)
        self.assertEqual(example["coverage"], COVERAGE)
        self.assertEqual(example["pins"], pins.record())
        release = fixtures.release()
        self.assertEqual(example["release"], {"lock_sha256": release.lock_sha256, "trees_sha256": release.trees_sha256})
        value = json.loads((release.authority_root / fixtures.RELEASED / "native-fixture/fixture.json").read_bytes())
        self.assertEqual(example["input"]["archive_sha256"], value["outer_sha256"])
        self.assertEqual(example["input"]["length"], value["carrier_length"])
        self.assertEqual(example["identities"]["snapshot_id"], value["snapshot_id"])
        digest = re.search(r"evidence_sha256` is\s+`([0-9a-f]{64})`", self.text).group(1)
        self.assertEqual(hashlib.sha256(canonical(example)).hexdigest(), digest)

    def test_a_validation_protocol_code_is_placed_where_the_service_emits_it(self):
        # S7-R1-04: the status route returns `code` alone; only the event carries `protocol_code`.
        rows = {row[0]: row for row in table(section(self.text, "### Validation outcomes"))}
        self.assertIn("the `validation-finished` event names it as `protocol_code`", rows["protocol_refused"][2])
        self.assertIn("the status route does not", rows["protocol_refused"][2])

    def test_every_evidence_field_and_coverage_flag_is_described(self):
        fields = table(section(self.text, "### Evidence fields"))
        self.assertEqual([row[0] for row in fields], sorted(self.example))
        flags = table(section(self.text, "### Coverage"))
        self.assertEqual({row[0]: row[1] == "true" for row in flags}, COVERAGE)

    def test_the_document_names_what_others_still_own(self):
        for needle in ("fiat-checkpoints/issues/2", "skills/issues/863", "skills/issues/2161",
                       "scripts/sandbox-env.sh run scripts/demo.sh --scenario intake-validation --profile local",
                       "scripts/linux-env.sh db-start"):
            with self.subTest(needle=needle):
                self.assertIn(needle, self.text)


if __name__ == "__main__":
    unittest.main()
