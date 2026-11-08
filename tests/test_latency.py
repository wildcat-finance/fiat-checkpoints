"""The metadata latency gate's runner: refusals, verdict and report, checked without measuring.

`scripts/latency.py` measures only on the native aarch64 latency profile. Here
its host and its measurement are replaced, so these checks start no process
and run on any profile; the measurement itself runs in the Exit command.
"""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tests import test_demo_scenario


ROOT = Path(__file__).resolve().parents[1]


def load_runner():
    spec = importlib.util.spec_from_file_location("fiat_checkpoints_latency_runner", ROOT / "scripts/latency.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LATENCY = load_runner()


def host(machine="aarch64", system="Linux"):
    return SimpleNamespace(sysname=system, machine=machine, release="6.8.0-synthetic", nodename="", version="")


def record(p95=19.5, count=80, refused=()):
    return {"count": count, "p95_ms": p95, "refused": list(refused), "routes": {}, "first_request_ms": 3.0}


class LatencyRunnerTests(unittest.TestCase):
    def run_main(self, argv, *, machine="aarch64", measured=None):
        stdout = io.StringIO()
        with mock.patch.object(LATENCY.os, "uname", return_value=host(machine)), \
                mock.patch.object(LATENCY, "measure", return_value=measured or record()) as measure, \
                contextlib.redirect_stdout(stdout):
            code = LATENCY.main(argv)
        return code, stdout.getvalue(), measure

    def refused(self, argv, **options):
        with self.assertRaises(LATENCY.Refusal) as caught:
            self.run_main(argv, **options)
        return str(caught.exception)

    def test_the_parser_declares_only_profile_and_out(self):
        options = {option for action in LATENCY.build_parser()._actions for option in action.option_strings}
        self.assertEqual(options, {"-h", "--help", "--profile", "--out"})

    def test_missing_unknown_or_abbreviated_options_refuse_before_measuring(self):
        self.assertEqual(self.refused([]), "profile-missing")
        self.assertEqual(self.refused(["--profile", "x86-emulated"]), "profile-unknown")
        self.assertEqual(self.refused(["--prof", "arm64-native"]), "option-unknown")

    def test_any_host_but_native_aarch64_linux_refuses(self):
        for machine, system in (("x86_64", "Linux"), ("arm64", "Darwin")):
            with self.subTest(machine=machine), \
                    mock.patch.object(LATENCY, "measure") as measure, \
                    mock.patch.object(LATENCY.os, "uname", return_value=host(machine, system)), \
                    self.assertRaises(LATENCY.Refusal) as caught:
                LATENCY.main(["--profile", "arm64-native"])
            self.assertEqual(str(caught.exception), "latency-profile-required")
            measure.assert_not_called()

    def test_the_verdict_needs_every_sample_no_refusal_and_p95_within_500_ms(self):
        self.assertTrue(LATENCY.verdict(record()))
        self.assertTrue(LATENCY.verdict(record(p95=500)))
        for changed in (record(p95=500.001), record(count=79), record(count=81), record(p95=None),
                        record(refused=[{"route": "announce", "status": 429, "code": "quota_exceeded"}])):
            with self.subTest(record=changed):
                self.assertFalse(LATENCY.verdict(changed))

    def test_a_passing_and_a_failing_measurement_report_every_sample(self):
        code, text, measure = self.run_main(["--profile", "arm64-native"])
        report = json.loads(text)
        self.assertEqual(code, 0)
        measure.assert_called_once_with()
        self.assertEqual((report["schema"], report["profile"], report["limit_ms"], report["samples_required"],
                          report["passed"], report["measurement"]),
                         ("fiat-checkpoints-latency/v1", "arm64-native", 500, 80, True, record()))
        code, text, _ = self.run_main(["--profile", "arm64-native"], measured=record(p95=687.098))
        self.assertEqual((code, json.loads(text)["passed"]), (1, False))

    def test_out_writes_the_same_bytes_to_a_new_file_only(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "latency.json"
            code, text, _ = self.run_main(["--profile", "arm64-native", "--out", str(out)])
            self.assertEqual((code, out.read_text(encoding="utf-8")), (0, text))
            self.assertEqual(self.refused(["--profile", "arm64-native", "--out", str(out)]), "out-exists")
            missing = Path(directory) / "absent" / "latency.json"
            self.assertEqual(self.refused(["--profile", "arm64-native", "--out", str(missing)]), "out-invalid")

    def test_a_failed_measurement_leaves_only_a_fixed_code(self):
        failures = ((test_demo_scenario.DemoRefusal("http-server-unavailable"), "http-server-unavailable"),
                    (RuntimeError("synthetic failure naming a private path"), "measurement-failed"))
        for error, code in failures:
            with self.subTest(code=code), \
                    mock.patch.object(test_demo_scenario, "measure_metadata", side_effect=error), \
                    self.assertRaises(LATENCY.Refusal) as caught:
                LATENCY.measure()
            self.assertEqual(str(caught.exception), code)


if __name__ == "__main__":
    unittest.main()
