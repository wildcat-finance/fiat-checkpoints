"""The integration design resolvers: what each one measures or checks, and when it refuses.

These checks start no process. Each resolver's measurement is replaced by a
recorded shape so the rule that turns it into a value can be checked in
isolation; the measurements themselves run in `tests/test_performance.py`,
the `sandbox` group and the design commands.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from fiat_checkpoints import conformance
from fiat_checkpoints.validation import outputs
from fiat_checkpoints.validation.policy import ResourcePolicy
from fiat_checkpoints.validation.refusals import ValidationRefusal
from fiat_checkpoints.validation.sandbox import SandboxRun
from tests.validation_support import expected, library, native_record, release, result_line, run_of


ROOT = Path(__file__).resolve().parents[1]


def check_module():
    spec = importlib.util.spec_from_file_location("fiat_checkpoints_check_runner", ROOT / "scripts/check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Groups:
    """A `DesignContext.run_groups` stand-in that records each call and answers `passes`."""

    def __init__(self, passes=True):
        self.passes, self.calls = passes, []

    def __call__(self, groups):
        self.calls.append(tuple(groups))
        return self.passes


def context(criterion, groups):
    return conformance.DesignContext(ROOT, "isolated-pinned-runtime", criterion, groups)


def evidence(record=None):
    record = native_record() if record is None else record
    return outputs.read(run_of(result_line(record=record)), expected(), library())


class RegistryTests(unittest.TestCase):
    def test_every_conformance_criterion_has_a_resolver(self):
        units = check_module().CONFORMANCE_UNITS
        self.assertEqual(set(conformance.RESOLVERS), set(units))
        for criterion in ("native-sequence-linux", "intake-hostile-suites", "validation-wall-time",
                          "gateway-stream-memory"):
            self.assertTrue(callable(conformance.RESOLVERS[criterion]))


def clean_summary(**changes):
    """The driver's summary of a complete passing criterion run, with `changes` applied."""
    execution = {"complete": True, "passed": True, "tests_run": 74, "subtests_run": 38, "failures": 0,
                 "errors": 0, "skips": 0, "expected_failures": 0, "unexpected_successes": 0}
    summary = {"corpus_exit": 0, "criterion_exit": 0, "code": "cases-passed", "complete": True,
               "runner_exit": 0, "executed": 74, "native": True, "report_sha256": "0" * 64,
               "report": {"schema": "protasis-design-report/v1", "candidate": "ordered-replay",
                          "criterion": "native-boundary-coverage", "value": True, "unit": "boolean", "exit": 0},
               "execution": execution}
    for key, value in changes.items():
        if key in execution:
            execution[key] = value
        else:
            summary[key] = value
    return summary


def sandbox_run(exit=0, killed=None):
    return SandboxRun("0" * 32, exit, b"", "0" * 64, 0, killed, {"wall_ms": 1, "cpu_us": 1})


class NativeCriterionTests(unittest.TestCase):
    """S7-R1-01: the resolver runs the released criterion, never a substitute."""

    def helper(self, name):
        # A missing helper fails as an assertion, so the substitute resolver fails here too.
        self.assertTrue(hasattr(conformance, name), name)
        return getattr(conformance, name)

    def test_absent_criterion_files_refuse_even_where_the_substitute_passed(self):
        # The pre-round-3 resolver returned true here from one valid-fixture job
        # and the sandbox group; the released criterion was never in the image.
        groups = Groups()
        run = SandboxRun("0" * 32, 0, b"", "0" * 64, 0, None, {"wall_ms": 1})
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(conformance, "_linux_x86_64", return_value=True), \
                mock.patch.object(conformance, "CRITERION_LIST", Path(temporary) / "absent.sha256", create=True), \
                mock.patch.object(conformance, "_native_valid_fixture", create=True,
                                  return_value=(release(), (evidence(), run))), \
                mock.patch.object(conformance, "_criterion_run", create=True,
                                  side_effect=AssertionError("no job without the criterion")):
            self.assertIs(conformance.native_sequence_linux(context("native-sequence-linux", groups)), False)
        self.assertEqual(groups.calls, [])

    def tree(self, root):
        base = root / "criterion"
        rows = []
        for name, data in (("root/a.py", b"a\n"), ("native-source/b/c.json", b"{}")):
            (base / name).parent.mkdir(parents=True, exist_ok=True)
            (base / name).write_bytes(data)
            rows.append(hashlib.sha256(data).hexdigest() + "  " + name)
        listing = root / "criterion.sha256"
        listing.write_text("\n".join(sorted(rows, key=lambda row: row[66:])) + "\n")
        return listing, base

    def test_the_listed_files_must_be_present_exact_and_alone(self):
        changes = {
            "missing": lambda base, listing: (base / "root/a.py").unlink(),
            "changed": lambda base, listing: (base / "root/a.py").write_bytes(b"b\n"),
            "extra": lambda base, listing: (base / "root/extra.py").write_bytes(b""),
            "symlink": lambda base, listing: (base / "root/link.py").symlink_to(base / "root/a.py"),
            "empty list": lambda base, listing: listing.write_text(""),
            "bad row": lambda base, listing: listing.write_text("zz  root/a.py\n"),
            "no list": lambda base, listing: listing.unlink(),
            "no tree": lambda base, listing: shutil.rmtree(base),
        }
        with tempfile.TemporaryDirectory() as temporary:
            listing, base = self.tree(Path(temporary))
            self.assertIs(self.helper("_criterion_files")(listing, base), True)
        for name, change in changes.items():
            with self.subTest(change=name), tempfile.TemporaryDirectory() as temporary:
                listing, base = self.tree(Path(temporary))
                change(base, listing)
                self.assertIs(self.helper("_criterion_files")(listing, base), False)

    def test_only_a_complete_clean_run_passes(self):
        self.assertIs(self.helper("_criterion_passed")(sandbox_run(), clean_summary()), True)
        for name, run, summary in (
                ("skips", sandbox_run(), clean_summary(skips=35)),
                ("failure", sandbox_run(), clean_summary(failures=1)),
                ("error", sandbox_run(), clean_summary(errors=1)),
                ("not passed", sandbox_run(), clean_summary(passed=False)),
                ("incomplete", sandbox_run(), clean_summary(complete=False)),
                ("short", sandbox_run(), clean_summary(tests_run=73)),
                ("nothing executed", sandbox_run(), clean_summary(executed=0, tests_run=0)),
                ("no native result", sandbox_run(), clean_summary(native=False)),
                ("cases failed", sandbox_run(), clean_summary(code="cases-failed")),
                ("criterion exit", sandbox_run(), clean_summary(criterion_exit=1)),
                ("manifest drift", sandbox_run(), clean_summary(corpus_exit=1)),
                ("report false", sandbox_run(), clean_summary(report={"schema": "protasis-design-report/v1",
                                                                      "criterion": "native-boundary-coverage",
                                                                      "value": False, "exit": 1})),
                ("cpu kill", sandbox_run(137, "cpu-limit"), clean_summary()),
                ("job exit", sandbox_run(1), clean_summary()),
                ("no summary", sandbox_run(), None)):
            with self.subTest(case=name):
                self.assertIs(self.helper("_criterion_passed")(run, summary), False)

    def resolve(self, outcome, *, linux=True, files=True):
        patches = [mock.patch.object(conformance, "_linux_x86_64", return_value=linux),
                   mock.patch.object(conformance, "_criterion_files", return_value=files, create=True)]
        if isinstance(outcome, Exception):
            patches.append(mock.patch.object(conformance, "_criterion_run", side_effect=outcome, create=True))
        else:
            patches.append(mock.patch.object(conformance, "_criterion_run", return_value=outcome, create=True))
        groups = Groups()
        with patches[0], patches[1], patches[2] as started, mock.patch("sys.stderr"):
            value = conformance.native_sequence_linux(context("native-sequence-linux", groups))
        self.assertEqual(groups.calls, [])
        return value, started.call_count

    def test_the_resolver_runs_the_criterion_and_reads_only_its_result(self):
        self.assertEqual(self.resolve((sandbox_run(), clean_summary())), (True, 1))
        self.assertEqual(self.resolve((sandbox_run(), clean_summary(skips=35))), (False, 1))
        self.assertEqual(self.resolve(ValidationRefusal("sandbox_unavailable", "sandbox-runtime-missing")), (False, 1))
        self.assertEqual(self.resolve((sandbox_run(), clean_summary()), linux=False), (False, 0))
        self.assertEqual(self.resolve((sandbox_run(), clean_summary()), files=False), (False, 0))

    def test_a_false_run_reports_why(self):
        summary = {"corpus_exit": 0, "criterion_exit": 2,
                   "criterion_event": {"event": "checkpoint_authority_conformance_refused", "stage": "invocation",
                                       "code": "native-execution-unavailable", "exit": 2},
                   "criterion_stderr": {"sha256": "0" * 64, "bytes": 0},
                   "read_error": {"file": "report", "type": "FileNotFoundError"}}
        stderr = io.StringIO()
        with mock.patch.object(conformance, "_linux_x86_64", return_value=True), \
                mock.patch.object(conformance, "_criterion_files", return_value=True, create=True), \
                mock.patch.object(conformance, "_criterion_run", return_value=(sandbox_run(), summary), create=True), \
                contextlib.redirect_stderr(stderr):
            value = conformance.native_sequence_linux(context("native-sequence-linux", Groups()))
        self.assertIs(value, False)
        event = json.loads(stderr.getvalue().strip().splitlines()[-1])
        self.assertEqual((event["event"], event["criterion_exit"], event["criterion_event"]["code"],
                          event["read_error"]), ("native-criterion-finished", 2, "native-execution-unavailable",
                                                 {"file": "report", "type": "FileNotFoundError"}))
        self.assertIs(event["summary_parsed"], True)

    def specs(self):
        from fiat_checkpoints.validation.sandbox import Sandbox, SandboxJob
        job = SandboxJob(owner="spec", argv=("/usr/local/bin/python3.14", "-I", "-c", "pass"), trust=b"{}",
                         binds=((Path("/host/service"), "/opt/fiat-checkpoints/service/src"),))
        production = Sandbox().oci_config(job, "a" * 32, Path("/state/job"))
        criterion = self.helper("_criterion_sandbox")(
            self.helper("_criterion_policy")()).oci_config(job, "a" * 32, Path("/state/job"))
        return production, criterion

    def test_validation_jobs_keep_noexec_scratch_and_noexec_input_and_trust(self):
        production, _criterion = self.specs()
        mounts = {mount["destination"]: mount for mount in production["mounts"]}
        for destination in ("/job", "/tmp", "/input/checkpoint.zip", "/trust/job.json"):
            with self.subTest(destination=destination):
                self.assertIn("noexec", mounts[destination]["options"])
                self.assertIn("nosuid", mounts[destination]["options"])
        self.assertEqual(mounts["/opt/fiat-checkpoints/service/src"]["options"], ["rbind", "ro", "nosuid", "nodev"])

    def test_the_criterion_job_differs_only_by_exec_on_its_scratch(self):
        # Ruled by the driver under Laurence's delegation of 2026-11-08.
        production, criterion = self.specs()
        # The only other difference is the criterion policy's CPU limit (wall time is not in the spec).
        for spec, limits in ((production, ResourcePolicy()), (criterion, self.helper("_criterion_policy")())):
            [cpu] = [row for row in spec["process"]["rlimits"] if row["type"] == "RLIMIT_CPU"]
            self.assertEqual((cpu["soft"], cpu["hard"]), (limits.cpu_seconds, limits.cpu_seconds))
            spec["process"]["rlimits"].remove(cpu)
        changed = []
        for before, after in zip(production["mounts"], criterion["mounts"]):
            if before != after:
                changed.append(after["destination"])
                self.assertEqual([option for option in before["options"] if option != "noexec"], after["options"])
                self.assertEqual({key: value for key, value in before.items() if key != "options"},
                                 {key: value for key, value in after.items() if key != "options"})
        self.assertEqual(changed, ["/job", "/tmp"])
        for spec in (production, criterion):
            spec.pop("mounts")
        self.assertEqual(production, criterion)

    def test_the_criterion_policy_raises_only_cpu_and_wall_for_this_job(self):
        from fiat_checkpoints.validation.policy import SPECIFICATION, ResourcePolicy
        policy = self.helper("_criterion_policy")()
        self.assertIsInstance(policy, ResourcePolicy)
        expected = ResourcePolicy().record() | {"cpu_seconds": self.helper("CRITERION_CPU_SECONDS"),
                                                 "wall_seconds": self.helper("CRITERION_WALL_SECONDS")}
        self.assertEqual(policy.record(), expected)
        self.assertGreater(self.helper("CRITERION_CPU_SECONDS"), SPECIFICATION.cpu_seconds)
        self.assertEqual((ResourcePolicy().cpu_seconds, ResourcePolicy().wall_seconds), (300, 900))
        with self.assertRaises(ValueError):
            ResourcePolicy(cpu_seconds=self.helper("CRITERION_CPU_SECONDS"))

    def test_the_driver_runs_both_released_commands(self):
        driver = self.helper("CRITERION_DRIVER")
        compile(driver, "criterion-driver", "exec")
        for needle in ("plugins/hexaemeron/tests/checkpoint_authority_native_corpus.py", '"--check"',
                       "plugins/hexaemeron/tests/checkpoint_authority_conformance.py",
                       '"--criterion", "native-boundary-coverage"', "CHECKPOINT_AUTHORITY_NATIVE_SOURCE"):
            with self.subTest(needle=needle):
                self.assertIn(needle, driver)
        self.assertEqual(self.helper("CRITERION_REPORT"),
                         ".hexaemeron/reports/ordered-replay-native-boundary-coverage.json")


class HostileSuitesTests(unittest.TestCase):
    def rows(self, count=35, failed=()):
        ids = ["case-%02d" % index for index in range(count)]
        declared = {item: ("refusal", "inspect") for item in ids}
        return declared, [{"id": item, "passed": item not in failed} for item in ids]

    def resolve(self, shape, groups):
        with mock.patch.object(conformance, "_rejection_rows", return_value=shape):
            return conformance.intake_hostile_suites(context("intake-hostile-suites", groups))

    def test_every_declared_id_refused_and_the_seven_groups_hold(self):
        groups = Groups()
        self.assertIs(self.resolve(self.rows(), groups), True)
        self.assertEqual(groups.calls, [("protocol", "domain", "auth", "upload", "quarantine", "validation",
                                         "sandbox")])

    def test_a_row_that_did_not_refuse_as_declared_refuses(self):
        groups = Groups()
        self.assertIs(self.resolve(self.rows(failed={"case-07"}), groups), False)
        self.assertEqual(groups.calls, [])

    def test_a_short_corpus_or_a_missing_row_refuses(self):
        self.assertIs(self.resolve(self.rows(count=34), Groups()), False)
        declared, rows = self.rows()
        self.assertIs(self.resolve((declared, rows[:-1]), Groups()), False)

    def test_failing_groups_refuse(self):
        self.assertIs(self.resolve(self.rows(), Groups(False)), False)


class ValidationWallTimeTests(unittest.TestCase):
    def resolve(self, samples):
        with mock.patch.object(conformance, "_validation_samples", return_value=samples):
            return conformance.validation_wall_time(context("validation-wall-time", Groups()))

    def test_the_value_is_the_largest_measured_wall_time(self):
        self.assertEqual(self.resolve([{"completed": True, "wall_ms": value} for value in (127935, 129552, 128674)]),
                         129552)
        self.assertEqual(self.resolve([{"completed": True, "wall_ms": value} for value in (10, 30, 20)]), 30)

    def test_an_incomplete_or_short_measurement_refuses(self):
        for samples in ([{"completed": True, "wall_ms": 1}, {"completed": False, "wall_ms": 2},
                         {"completed": True, "wall_ms": 3}],
                        [{"completed": True, "wall_ms": 1}],
                        [{"completed": True, "wall_ms": 1.5}] * 3):
            with self.subTest(samples=samples), self.assertRaises(ValueError):
                self.resolve(samples)

    def test_an_unavailable_sandbox_refuses_without_a_value(self):
        with mock.patch.object(conformance, "_validation_samples",
                               side_effect=ValidationRefusal("sandbox_unavailable", "sandbox-runtime-missing")):
            with self.assertRaises(ValueError) as caught:
                conformance.validation_wall_time(context("validation-wall-time", Groups()))
        self.assertEqual(str(caught.exception), "validation-unavailable")


class GatewayStreamMemoryTests(unittest.TestCase):
    def row(self, incremental, status=202, staged_after=0):
        return {"incremental_python_bytes": incremental, "status": status, "staged_after_bytes": staged_after}

    def resolve(self, rows):
        with mock.patch.object(conformance, "_stream_memory", return_value=rows):
            return conformance.gateway_stream_memory(context("gateway-stream-memory", Groups()))

    def test_the_value_is_the_largest_measured_increment(self):
        self.assertEqual(self.resolve([self.row(2_205_653), self.row(2_140_684)]), 2_205_653)
        self.assertEqual(self.resolve([self.row(7), self.row(9)]), 9)

    def test_an_unsealed_or_leftover_stream_refuses(self):
        for rows in ([self.row(1, status=422)], [self.row(1, staged_after=10)], []):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.resolve(rows)


if __name__ == "__main__":
    unittest.main()
