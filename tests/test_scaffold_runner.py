"""Run the public reporter against isolated synthetic suites."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PASSING = "import unittest\nclass Example(unittest.TestCase):\n    def test_case(self): self.assertEqual(2+2, 4)\n"


class ReporterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        (self.root / "tests").mkdir()
        (self.root / "tests/__init__.py").touch()
        shutil.copyfile(ROOT / "scripts/check.py", self.root / "scripts/check.py")

    def run_reporter(self, *arguments):
        return subprocess.run([sys.executable, "-I", str(self.root / "scripts/check.py"), *arguments],
                              cwd="/", capture_output=True, text=True, timeout=15, check=False)

    def fixture(self, content, group="example"):
        (self.root / ("tests/test_" + group + ".py")).write_text(content)

    def test_pass_emits_observed_counters_case_ids_and_artifact_digest(self):
        self.fixture(PASSING)
        run = self.run_reporter("--group", "example", "--report", ".reports/result.json")
        self.assertEqual(run.returncode, 0, run.stderr)
        output = json.loads(run.stdout)
        report = self.root / ".reports/result.json"
        counters = json.loads(report.read_bytes())
        self.assertEqual(counters, {"schema": "elenchus.unittest.v1", "complete": True,
                                   "testsRun": 1, "failures": 0, "errors": 0, "skipped": 0,
                                   "expectedFailures": 0, "unexpectedSuccesses": 0})
        self.assertEqual(output["case_ids"], ["tests.test_example.Example.test_case"])
        self.assertEqual(output["artifact_sha256"][".reports/result.json"], hashlib.sha256(report.read_bytes()).hexdigest())

    def test_assertion_failure_has_no_diagnostic_body(self):
        self.fixture(PASSING.replace("self.assertEqual(2+2, 4)", "self.fail('private-test-marker')"))
        run = self.run_reporter("--group", "example", "--report", ".reports/result.json")
        self.assertEqual(run.returncode, 1)
        self.assertEqual(json.loads(run.stdout)["counters"]["failures"], 1)
        self.assertNotIn("private-test-marker", run.stdout + run.stderr)

    def test_skip_and_both_expected_failure_outcomes_refuse(self):
        cases = (
            ("    @unittest.skip('synthetic')\n", "self.assertEqual(2+2, 4)", "skipped"),
            ("    @unittest.expectedFailure\n", "self.fail('synthetic')", "expectedFailures"),
            ("    @unittest.expectedFailure\n", "self.assertEqual(2+2, 4)", "unexpectedSuccesses"),
        )
        for decorator, body, key in cases:
            with self.subTest(counter=key):
                self.fixture("import unittest\nclass Example(unittest.TestCase):\n" + decorator +
                             "    def test_case(self): " + body + "\n")
                run = self.run_reporter("--group", "example")
                self.assertEqual(run.returncode, 1)
                self.assertEqual(json.loads(run.stdout)["counters"][key], 1)

    def test_import_error_is_not_success(self):
        self.fixture("raise RuntimeError('private-import-marker')\n")
        run = self.run_reporter("--group", "example")
        self.assertEqual(run.returncode, 1)
        self.assertEqual(json.loads(run.stdout)["counters"]["errors"], 1)
        self.assertNotIn("private-import-marker", run.stdout + run.stderr)

    def test_absent_and_zero_test_groups_refuse_without_report(self):
        for content in (None, "# no TestCase is defined\n"):
            with self.subTest(content=content):
                if content is not None:
                    self.fixture(content)
                run = self.run_reporter("--group", "example", "--report", ".reports/result.json")
                self.assertEqual(run.returncode, 2)
                self.assertIn("test-group-empty", run.stderr)
                self.assertFalse((self.root / ".reports/result.json").exists())

    def test_invalid_duplicate_and_partial_group_selection_refuse(self):
        self.fixture(PASSING)
        for selection in ("", "example,example", "../example", "all,example", "example,absent"):
            with self.subTest(selection=selection):
                self.assertEqual(self.run_reporter("--group", selection).returncode, 2)

    def test_group_prefix_does_not_satisfy_a_missing_group(self):
        self.fixture(PASSING, "examplelookalike")
        self.assertEqual(self.run_reporter("--group", "example").returncode, 2)

    def test_design_report_requires_exact_binding_and_suite(self):
        self.fixture(PASSING)
        for arguments in (("--design-report", ".reports/design.json"),
                          ("--candidate", "mediated-isolated", "--criterion", "released-protocol"),
                          ("--design-report", ".reports/design.json", "--candidate", "mediated-isolated", "--criterion", "released-protocol")):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.run_reporter("--group", "example", *arguments).returncode, 2)
        self.assertFalse((self.root / ".reports/design.json").exists())

    def test_report_cannot_escape_or_follow_a_symlink(self):
        self.fixture(PASSING)
        with tempfile.TemporaryDirectory() as outside:
            victim = Path(outside) / "report.json"
            victim.write_bytes(b"preserve")
            (self.root / "linked").symlink_to(outside, target_is_directory=True)
            for target in (str(victim), "../escaped.json", "linked/report.json"):
                with self.subTest(target=target):
                    self.assertEqual(self.run_reporter("--group", "example", "--report", target).returncode, 2)
            self.assertEqual(victim.read_bytes(), b"preserve")

    def test_deadline_exits_without_a_success_report(self):
        self.fixture("import os, signal, unittest\nclass Example(unittest.TestCase):\n"
                     "    def test_case(self): os.kill(os.getpid(), signal.SIGALRM)\n")
        run = self.run_reporter("--group", "example", "--report", ".reports/result.json")
        self.assertEqual(run.returncode, 2)
        self.assertIn("test-budget-exhausted", run.stderr)
        self.assertFalse((self.root / ".reports/result.json").exists())


class WrapperTests(unittest.TestCase):
    def test_real_wrapper_uses_repository_root_from_another_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = subprocess.run([str(ROOT / "scripts/check.sh"), "--group", "absent"],
                                 cwd=temporary, capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(run.returncode, 2)
        self.assertIn("test-group-empty", run.stderr)

    def test_wrapper_refuses_an_unpinned_uv(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "uv"
            binary.write_text("#!/bin/sh\nprintf '%s\\n' 'uv 0.0.0'\n")
            binary.chmod(0o755)
            environment = dict(os.environ, PATH=temporary + os.pathsep + os.environ["PATH"])
            run = subprocess.run([str(ROOT / "scripts/check.sh"), "--help"], env=environment,
                                 capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(run.returncode, 2)
        self.assertIn("uv-version-mismatch", run.stderr)
