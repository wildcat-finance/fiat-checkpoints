"""Run the public check runner and its wrapper against synthetic suites."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.test_scaffold_repository import tracked_entries


ROOT = Path(__file__).resolve().parents[1]
PASSING = "import unittest\nclass Example(unittest.TestCase):\n    def test_case(self): self.assertEqual(2 + 2, 4)\n"
COUNTERS = {"schema": "elenchus.unittest.v1", "complete": True, "testsRun": 1, "failures": 0,
            "errors": 0, "skipped": 0, "expectedFailures": 0, "unexpectedSuccesses": 0}
DESIGN_OUT = ".hexaemeron/design/reports/isolated-pinned-runtime-protocol-lock-shipped.json"
SYNTHETIC_RESOLVERS = '''
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class DesignContext:
    root: Path
    candidate: str
    criterion: str
    run_groups: Callable


RESOLVERS = {
    "protocol-lock-shipped": lambda context: context.run_groups(("example",)),
    "restart-recovery": lambda context: "true",
    "validation-wall-time": lambda context: 1234,
}
'''


def load_runner():
    """Import scripts/check.py as a module without running its entry point."""
    spec = importlib.util.spec_from_file_location("fiat_checkpoints_check_runner", ROOT / "scripts/check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InProcessRunnerTests(unittest.TestCase):
    """Runner guarantees checked without a child process, so report mode keeps them."""

    def setUp(self):
        self.runner = load_runner()

    def test_hook_refuses_the_multiprocessing_spawn_primitive(self):
        # multiprocessing's spawn and forkserver starts call _posixsubprocess.fork_exec
        # without passing through subprocess.Popen.
        for event in ("_posixsubprocess.fork_exec", "subprocess.Popen", "os.fork", "os.posix_spawn"):
            with self.subTest(event=event), self.assertRaises(RuntimeError):
                self.runner.forbid_child_processes(event, ())

    def test_report_path_through_a_symlinked_ancestor_of_the_root_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            real = Path(temporary).resolve() / "real"
            (real / "tests").mkdir(parents=True)
            alias = Path(temporary).resolve() / "alias"
            alias.symlink_to(real, target_is_directory=True)
            (real / "linked").symlink_to(real, target_is_directory=True)
            self.runner.ROOT = real
            try:
                path, relative = self.runner.root_path(str(alias / ".reports/result.json"), "report-path")
            except self.runner.Refusal as refusal:
                self.fail("aliased root refused: " + str(refusal))
            self.assertEqual((path, relative), (real / ".reports/result.json", Path(".reports/result.json")))
            for target, code in ((alias / "linked/result.json", "report-path-symlink"),
                                 (alias / "tests/../../escaped.json", "report-path-invalid"),
                                 (Path(temporary).resolve() / "escaped.json", "report-path-outside-root")):
                with self.subTest(target=str(target)), self.assertRaisesRegex(self.runner.Refusal, "^" + code + "$"):
                    self.runner.root_path(str(target), "report-path")


class SyntheticRoot(unittest.TestCase):
    """A disposable repository holding a copy of the runner; no tests of its own."""

    spawns_child_process = True

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        for directory in ("scripts", "tests", "src/fiat_checkpoints"):
            (self.root / directory).mkdir(parents=True)
        (self.root / "tests/__init__.py").touch()
        (self.root / "src/fiat_checkpoints/__init__.py").touch()
        shutil.copyfile(ROOT / "scripts/check.py", self.root / "scripts/check.py")
        shutil.copyfile(ROOT / "src/fiat_checkpoints/conformance.py",
                        self.root / "src/fiat_checkpoints/conformance.py")

    def run_runner(self, *arguments):
        return subprocess.run([sys.executable, "-I", str(self.root / "scripts/check.py"), *arguments],
                              cwd="/", capture_output=True, text=True, timeout=120, check=False)

    def fixture(self, content, name="test_example.py"):
        (self.root / "tests" / name).write_text(content)


class RunnerTests(SyntheticRoot):
    def test_pass_emits_counters_case_ids_environment_and_artifact_digest(self):
        self.fixture(PASSING)
        run = self.run_runner("--group", "example", "--report", ".reports/result.json")
        self.assertEqual(run.returncode, 0, run.stderr)
        output = json.loads(run.stdout)
        report = self.root / ".reports/result.json"
        self.assertEqual(json.loads(report.read_bytes()), COUNTERS)
        self.assertEqual(output["case_ids"], ["tests.test_example.Example.test_case"])
        self.assertEqual(output["artifact_sha256"][".reports/result.json"],
                         hashlib.sha256(report.read_bytes()).hexdigest())
        self.assertEqual(output["environment"]["python"], "3.14.6")
        self.assertEqual(set(output["environment"]), {"kernel", "machine", "system", "python", "python_sha256"})

    def test_group_collects_every_module_of_the_group_and_all_collects_every_group(self):
        self.fixture(PASSING)
        self.fixture(PASSING, "test_example_more.py")
        self.fixture(PASSING, "test_other.py")
        run = self.run_runner("--group", "example")
        self.assertEqual(json.loads(run.stdout)["counters"]["testsRun"], 2)
        run = self.run_runner("--group", "all")
        self.assertEqual(json.loads(run.stdout)["counters"]["testsRun"], 3)
        run = self.run_runner("--group", "example,other")
        self.assertEqual(json.loads(run.stdout)["counters"]["testsRun"], 3)

    def test_assertion_failure_has_no_diagnostic_body(self):
        self.fixture(PASSING.replace("self.assertEqual(2 + 2, 4)", "self.fail('private-test-marker')"))
        run = self.run_runner("--group", "example", "--report", ".reports/result.json")
        self.assertEqual(run.returncode, 1)
        self.assertEqual(json.loads(run.stdout)["counters"]["failures"], 1)
        self.assertEqual(json.loads((self.root / ".reports/result.json").read_bytes())["failures"], 1)
        self.assertNotIn("private-test-marker", run.stdout + run.stderr)
        shown = self.run_runner("--group", "example", "--show-failures")
        self.assertIn("private-test-marker", shown.stderr)

    def test_skip_and_both_expected_failure_outcomes_refuse(self):
        cases = (
            ("    @unittest.skip('synthetic')\n", "self.assertEqual(2 + 2, 4)", "skipped"),
            ("    @unittest.expectedFailure\n", "self.fail('synthetic')", "expectedFailures"),
            ("    @unittest.expectedFailure\n", "self.assertEqual(2 + 2, 4)", "unexpectedSuccesses"),
        )
        for decorator, body, key in cases:
            with self.subTest(counter=key):
                self.fixture("import unittest\nclass Example(unittest.TestCase):\n" + decorator +
                             "    def test_case(self): " + body + "\n")
                run = self.run_runner("--group", "example")
                self.assertEqual(run.returncode, 1)
                self.assertEqual(json.loads(run.stdout)["counters"][key], 1)

    def test_import_error_is_an_error_without_its_text(self):
        self.fixture("raise RuntimeError('private-import-marker')\n")
        run = self.run_runner("--group", "example")
        self.assertEqual(run.returncode, 1)
        self.assertEqual(json.loads(run.stdout)["counters"]["errors"], 1)
        self.assertNotIn("private-import-marker", run.stdout + run.stderr)

    def test_absent_group_refuses_without_report(self):
        run = self.run_runner("--group", "example", "--report", ".reports/result.json")
        self.assertEqual(run.returncode, 2)
        self.assertIn("checks-refused: test-group-absent", run.stderr)
        self.assertFalse((self.root / ".reports/result.json").exists())

    def test_zero_test_group_refuses_without_report(self):
        self.fixture("# no TestCase is defined\n")
        run = self.run_runner("--group", "example", "--report", ".reports/result.json")
        self.assertEqual(run.returncode, 2)
        self.assertIn("checks-refused: test-group-empty", run.stderr)
        self.assertFalse((self.root / ".reports/result.json").exists())

    def test_invalid_duplicate_partial_and_missing_group_selection_refuse(self):
        self.fixture(PASSING)
        for arguments in ((), ("--group", ""), ("--group", "example,example"), ("--group", "../example"),
                          ("--group", "all,example"), ("--group", "example,absent"),
                          ("--group", "Example"), ("--group", "exam_ple")):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.run_runner(*arguments).returncode, 2)

    def test_group_prefix_does_not_satisfy_a_missing_group(self):
        self.fixture(PASSING, "test_examplelookalike.py")
        self.assertEqual(self.run_runner("--group", "example").returncode, 2)

    def test_abbreviated_and_unknown_options_refuse(self):
        self.fixture(PASSING)
        for arguments in (("--gr", "example"), ("--group", "example", "--rep", "x.json"),
                          ("--group", "example", "--unknown")):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.run_runner(*arguments).returncode, 2)

    def test_report_cannot_escape_or_follow_a_symlink(self):
        self.fixture(PASSING)
        with tempfile.TemporaryDirectory() as outside:
            victim = Path(outside) / "report.json"
            victim.write_bytes(b"preserve")
            (self.root / "linked").symlink_to(outside, target_is_directory=True)
            for target in (str(victim), "../escaped.json", "linked/report.json", ".git/report.json", "tests"):
                with self.subTest(target=target):
                    self.assertEqual(self.run_runner("--group", "example", "--report", target).returncode, 2)
            self.assertEqual(victim.read_bytes(), b"preserve")

    def test_report_mode_leaves_out_declared_child_process_tests(self):
        self.fixture(PASSING + "\nclass Spawning(unittest.TestCase):\n    spawns_child_process = True\n"
                     "    def test_spawn(self): self.fail('must not run')\n")
        run = self.run_runner("--group", "example", "--report", ".reports/result.json")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)["case_ids"], ["tests.test_example.Example.test_case"])
        full = self.run_runner("--group", "example")
        self.assertEqual(json.loads(full.stdout)["counters"]["failures"], 1)

    def test_report_mode_refuses_an_undeclared_child_process(self):
        self.fixture("import subprocess, sys, unittest\nclass Example(unittest.TestCase):\n"
                     "    def test_case(self): subprocess.run([sys.executable, '-c', 'pass'], check=True)\n")
        run = self.run_runner("--group", "example", "--report", ".reports/result.json")
        self.assertEqual(run.returncode, 1)
        self.assertEqual(json.loads((self.root / ".reports/result.json").read_bytes())["errors"], 1)
        self.assertEqual(self.run_runner("--group", "example").returncode, 0)

    def test_report_mode_refuses_a_multiprocessing_spawn_child(self):
        self.fixture("import multiprocessing, os, unittest\nclass Example(unittest.TestCase):\n"
                     "    def test_case(self):\n"
                     "        process = multiprocessing.get_context('spawn').Process(target=os.getpid)\n"
                     "        process.start()\n        process.join()\n")
        run = self.run_runner("--group", "example", "--report", ".reports/result.json")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(json.loads((self.root / ".reports/result.json").read_bytes())["errors"], 1)

    def test_report_mode_with_only_child_process_tests_is_empty(self):
        self.fixture("import unittest\nclass Spawning(unittest.TestCase):\n    spawns_child_process = True\n"
                     "    def test_spawn(self): pass\n")
        run = self.run_runner("--group", "example", "--report", ".reports/result.json")
        self.assertEqual(run.returncode, 2)
        self.assertIn("test-group-empty", run.stderr)

    def test_deadline_exits_without_a_success_report(self):
        self.fixture("import os, signal, unittest\nclass Example(unittest.TestCase):\n"
                     "    def test_case(self): os.kill(os.getpid(), signal.SIGALRM)\n")
        run = self.run_runner("--group", "example", "--report", ".reports/result.json")
        self.assertEqual(run.returncode, 2)
        self.assertIn("test-budget-exhausted", run.stderr)
        self.assertFalse((self.root / ".reports/result.json").exists())


class DesignModeTests(SyntheticRoot):
    def design(self, candidate, criterion, out=None):
        out = out or ".hexaemeron/design/reports/" + candidate + "-" + criterion + ".json"
        return self.run_runner("design", "--candidate", candidate, "--criterion", criterion, "--out", out)

    def test_unknown_candidate_or_criterion_refuses(self):
        for candidate, criterion, code in (
            ("unknown-candidate", "protocol-lock-shipped", "design-candidate-unknown"),
            ("isolated-pinned-runtime", "unknown-criterion", "design-criterion-unknown"),
            ("isolated-pinned-runtime", "validator-isolated", "design-criterion-selection-only"),
            ("in-process-validation", "protocol-lock-shipped", "design-candidate-not-selected"),
            ("isolated-pinned-runtime", "protocol-lock-shipped", "design-criterion-unavailable"),
        ):
            with self.subTest(code=code):
                run = self.design(candidate, criterion)
                self.assertEqual(run.returncode, 2)
                self.assertIn("checks-refused: " + code, run.stderr)
        self.assertFalse((self.root / ".hexaemeron").exists())

    def test_design_mode_refuses_mixed_or_missing_options(self):
        for arguments in (("design", "--candidate", "isolated-pinned-runtime", "--criterion", "protocol-lock-shipped"),
                          ("design", "--candidate", "isolated-pinned-runtime", "--criterion", "protocol-lock-shipped",
                           "--out", DESIGN_OUT, "--group", "example"),
                          ("--group", "example", "--candidate", "isolated-pinned-runtime"),
                          ("other",)):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.run_runner(*arguments).returncode, 2)

    def test_registered_resolver_writes_a_closed_design_report(self):
        (self.root / "src/fiat_checkpoints/conformance.py").write_text(SYNTHETIC_RESOLVERS)
        self.fixture(PASSING)
        run = self.design("isolated-pinned-runtime", "protocol-lock-shipped")
        self.assertEqual(run.returncode, 0, run.stderr)
        raw = (self.root / DESIGN_OUT).read_bytes()
        self.assertEqual(json.loads(raw), {
            "schema": "protasis-design-report/v1", "candidate": "isolated-pinned-runtime",
            "criterion": "protocol-lock-shipped", "value": True, "unit": "boolean",
            "command": "python3 scripts/check.py design --candidate isolated-pinned-runtime "
                       "--criterion protocol-lock-shipped --out " + DESIGN_OUT,
            "exit": 0,
        })
        self.assertEqual(json.loads(run.stdout)["sha256"], hashlib.sha256(raw).hexdigest())
        timed = self.design("isolated-pinned-runtime", "validation-wall-time")
        self.assertEqual(timed.returncode, 0, timed.stderr)
        report = self.root / ".hexaemeron/design/reports/isolated-pinned-runtime-validation-wall-time.json"
        self.assertEqual(json.loads(report.read_bytes())["value"], 1234)

    def test_resolver_value_type_and_report_path_are_checked(self):
        (self.root / "src/fiat_checkpoints/conformance.py").write_text(SYNTHETIC_RESOLVERS)
        run = self.design("isolated-pinned-runtime", "restart-recovery")
        self.assertEqual(run.returncode, 2)
        self.assertIn("design-value-type", run.stderr)
        run = self.design("isolated-pinned-runtime", "protocol-lock-shipped", ".reports/elsewhere.json")
        self.assertEqual(run.returncode, 2)
        self.assertIn("design-out-unexpected", run.stderr)


class WrapperTests(unittest.TestCase):
    spawns_child_process = True

    def test_real_wrapper_uses_repository_root_from_another_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = subprocess.run([str(ROOT / "scripts/check.sh"), "--group", "absent"],
                                 cwd=temporary, capture_output=True, text=True, timeout=300, check=False)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertIn("checks-refused: test-group-absent", run.stderr)

    def test_wrapper_refuses_an_unpinned_or_missing_uv(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "uv"
            binary.write_text("#!/bin/sh\nprintf '%s\\n' 'uv 0.0.0'\n")
            binary.chmod(0o755)
            for path in (temporary + os.pathsep + os.environ["PATH"], temporary):
                environment = dict(os.environ, PATH=path)
                if path == temporary:
                    binary.unlink()
                with self.subTest(uv="missing" if path == temporary else "unpinned"):
                    run = subprocess.run(["/bin/sh", str(ROOT / "scripts/check.sh"), "--help"], env=environment,
                                         capture_output=True, text=True, timeout=60, check=False)
                    self.assertEqual(run.returncode, 2)
                    self.assertIn("uv-version-mismatch", run.stderr)

    def test_public_scripts_are_tracked_executable(self):
        modes = dict(tracked_entries(ROOT))
        for name in ("scripts/check.py", "scripts/check.sh", "scripts/serve.py", "scripts/linux-env.sh"):
            with self.subTest(script=name):
                self.assertEqual(modes.get(name), 0o100755)
