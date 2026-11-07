"""The integration design resolvers: what each one measures or checks, and when it refuses.

These checks start no process. Each resolver's measurement is replaced by a
recorded shape so the rule that turns it into a value can be checked in
isolation; the measurements themselves run in `tests/test_performance.py`,
the `sandbox` group and the design commands.
"""

import importlib.util
from pathlib import Path
import unittest
from unittest import mock

from fiat_checkpoints import conformance
from fiat_checkpoints.validation import fixture, outputs
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


class NativeSequenceTests(unittest.TestCase):
    def resolve(self, outcome, groups, *, linux=True, killed=None):
        run = SandboxRun("0" * 32, 0, b"", "0" * 64, 0, killed, {"wall_ms": 1})
        with mock.patch.object(conformance, "_linux_x86_64", return_value=linux), \
                mock.patch.object(conformance, "_native_valid_fixture", return_value=(release(), (outcome, run))):
            return conformance.native_sequence_linux(context("native-sequence-linux", groups))

    def test_a_complete_sequence_and_a_passing_sandbox_group_hold(self):
        groups = Groups()
        self.assertIs(self.resolve(evidence(), groups), True)
        self.assertEqual(groups.calls, [("sandbox",)])

    def test_the_sandbox_group_failing_refuses(self):
        self.assertIs(self.resolve(evidence(), Groups(False)), False)

    def test_a_refused_job_a_kill_or_another_host_refuses_before_the_groups(self):
        for outcome, options in ((ValidationRefusal("validation_failed", "sandbox-memory-limit"), {}),
                                 (evidence(), {"killed": "memory-limit"}),
                                 (evidence(), {"linux": False})):
            with self.subTest(options=options, outcome=type(outcome).__name__):
                groups = Groups()
                self.assertIs(self.resolve(outcome, groups, **options), False)
                self.assertEqual(groups.calls, [])

    def test_an_unavailable_sandbox_refuses(self):
        groups = Groups()
        with mock.patch.object(conformance, "_linux_x86_64", return_value=True), \
                mock.patch.object(conformance, "_native_valid_fixture",
                                  side_effect=ValidationRefusal("sandbox_unavailable", "sandbox-runtime-missing")):
            self.assertIs(conformance.native_sequence_linux(context("native-sequence-linux", groups)), False)
        self.assertEqual(groups.calls, [])

    def test_a_result_that_is_not_the_released_fixtures_refuses(self):
        # The reader binds the result to its request; the resolver also binds it to the fixture.
        value, public = fixture.released(release())
        outcome = evidence()
        for change in ({"snapshot_id": "0" * 64}, {"required": sorted(value["required"])[1:]}):
            with self.subTest(change=sorted(change)), \
                    mock.patch.object(fixture, "released", return_value=(value | change, public)):
                groups = Groups()
                self.assertIs(self.resolve(outcome, groups), False)
                self.assertEqual(groups.calls, [])


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
