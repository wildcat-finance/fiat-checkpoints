#!/usr/bin/env python3
"""Run named test groups, or resolve one design conformance criterion.

A group is every `tests/test_<group>.py` and `tests/test_<group>_*.py` module,
so a later step adds a group by adding its modules. An absent group, a group
with no tests, a skip and an expected-failure outcome each refuse success.
With `--report` the run writes an `elenchus.unittest.v1` counter report and
refuses to start any child process; test classes that declare
`spawns_child_process = True` are left out of that run.
"""

import argparse
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
PYTHON_VERSION = (3, 14, 6)
BUDGET_SECONDS = 7200
GROUP_PATTERN = re.compile(r"[a-z][a-z0-9]{0,31}")
MAX_GROUPS = 32
OPTIONS = frozenset({"--group", "--report", "--candidate", "--criterion", "--out", "--show-failures"})
COUNTER_NAMES = ("failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses")
# multiprocessing's spawn and forkserver starts reach _posixsubprocess directly.
CHILD_PROCESS_EVENTS = frozenset({
    "subprocess.Popen", "_posixsubprocess.fork_exec", "os.posix_spawn", "os.fork",
    "os.forkpty", "os.spawn", "os.system", "os.exec", "os.startfile",
})
SELECTED_CANDIDATE = "isolated-pinned-runtime"
CANDIDATES = frozenset({
    "isolated-pinned-runtime", "isolated-split-runtime",
    "isolated-reference-runtime", "in-process-validation",
})
SELECTION_CRITERIA = frozenset({
    "validator-isolated", "runtime-wheels-resolve", "released-lock-verifies",
    "lock-interpreter", "interpreter-pins", "protocol-check-time", "protocol-check-rss",
})
CONFORMANCE_UNITS = {
    "protocol-lock-shipped": "boolean",
    "restart-recovery": "boolean",
    "native-sequence-linux": "boolean",
    "intake-hostile-suites": "boolean",
    "validation-wall-time": "milliseconds",
    "gateway-stream-memory": "bytes",
}
DESIGN_REPORT_DIRECTORY = (".hexaemeron", "design", "reports")


class Refusal(Exception):
    """A fixed diagnostic code without test output or supplied values."""


def build_parser():
    parser = argparse.ArgumentParser(description="Run checkpoint service checks")
    parser.add_argument("mode", nargs="?", choices=["design"])
    parser.add_argument("--group")
    parser.add_argument("--report")
    parser.add_argument("--candidate")
    parser.add_argument("--criterion")
    parser.add_argument("--out")
    parser.add_argument("--show-failures", action="store_true")
    return parser


def refuse_abbreviations(argv):
    # argparse accepts unique prefixes; an exact option name is required here.
    for token in argv:
        if token == "--":
            break
        if token.startswith("--") and token.split("=", 1)[0] not in OPTIONS:
            raise Refusal("option-unknown")


def root_path(name, code):
    """Resolve a caller path inside ROOT without a symlink or Git component."""
    path = Path(name)
    if not path.is_absolute():
        path = ROOT / path
    # An absolute path may name ROOT through a symlinked ancestor, as macOS
    # /var names /private/var. The shallowest ancestor that is ROOT anchors it;
    # every component below that ancestor still gets the symlink check.
    for ancestor in reversed(path.parents):
        if ancestor == ROOT or ancestor.resolve() == ROOT:
            relative = path.relative_to(ancestor)
            path = ROOT / relative
            break
    else:
        raise Refusal(code + "-outside-root")
    if not relative.parts or any(part in (".", "..", ".git") for part in relative.parts):
        raise Refusal(code + "-invalid")
    current = ROOT
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise Refusal(code + "-symlink")
    if path.exists() and not stat.S_ISREG(path.stat().st_mode):
        raise Refusal(code + "-not-regular")
    return path, relative


def write_json(path, value):
    """Atomically replace one regular file with canonical JSON and a newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temporary = tempfile.mkstemp(prefix=".check-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return hashlib.sha256(raw).hexdigest()


def iter_tests(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from iter_tests(item)
        else:
            yield item


def selected_groups(raw):
    if raw is None:
        raise Refusal("test-group-missing")
    groups = raw.split(",")
    if len(groups) > MAX_GROUPS or len(set(groups)) != len(groups):
        raise Refusal("test-group-invalid")
    if any(GROUP_PATTERN.fullmatch(group) is None for group in groups):
        raise Refusal("test-group-invalid")
    if "all" in groups and len(groups) != 1:
        raise Refusal("test-group-invalid")
    return tuple(groups)


def group_modules(group):
    """Return module names for one group from the tests directory listing."""
    directory = ROOT / "tests"
    try:
        names = sorted(entry.name for entry in os.scandir(directory) if entry.is_file(follow_symlinks=False))
    except OSError as exc:
        raise Refusal("test-directory-unavailable") from exc
    pattern = re.compile(r"test_[a-z0-9_]+\.py" if group == "all" else
                         r"test_" + group + r"(?:_[a-z0-9_]+)?\.py")
    return [name[:-3] for name in names if pattern.fullmatch(name)]


class ModuleImportFailure(unittest.TestCase):
    """Count a test module that cannot be imported as one error."""

    def __init__(self, module):
        super().__init__("runTest")
        self.module = module

    def id(self):
        return self.module

    def runTest(self):
        raise ImportError("test-module-import-failed")


def module_tests(loader, name):
    try:
        module = importlib.import_module(name)
    except Exception:
        # The module's own exception text is not repeated in check output.
        return [ModuleImportFailure(name)]
    return list(iter_tests(loader.loadTestsFromModule(module)))


def discover(groups, in_process_only):
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    seen = set()
    for group in groups:
        modules = group_modules(group)
        if not modules:
            raise Refusal("test-group-absent")
        tests = []
        for module in modules:
            tests.extend(module_tests(loader, "tests." + module))
        if in_process_only:
            tests = [test for test in tests if not getattr(test, "spawns_child_process", False)]
        if not tests:
            raise Refusal("test-group-empty")
        for test in tests:
            if test.id() not in seen:
                seen.add(test.id())
                suite.addTest(test)
    return suite


def forbid_child_processes(event, _arguments):
    # An audit hook cannot be removed, so no later test code reopens this.
    if event in CHILD_PROCESS_EVENTS:
        raise RuntimeError("child-process-refused")


def timed_out(_signum, _frame):
    # A TestCase can catch exceptions, so the outer deadline exits the process.
    print("checks-refused: test-budget-exhausted", file=sys.stderr, flush=True)
    os._exit(2)


def run_suite(suite, show_failures):
    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(BUDGET_SECONDS)
    try:
        # Test output stays private; only case ids and counters leave the run.
        result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    finally:
        signal.alarm(0)
    counters = {
        "schema": "elenchus.unittest.v1",
        "complete": True,
        "testsRun": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "expectedFailures": len(result.expectedFailures),
        "unexpectedSuccesses": len(result.unexpectedSuccesses),
    }
    passed = result.testsRun > 0 and all(counters[name] == 0 for name in COUNTER_NAMES)
    for label, values in (("failure", result.failures), ("error", result.errors),
                          ("skipped", result.skipped)):
        for test, detail in values:
            print(label + ": " + test.id(), file=sys.stderr)
            if show_failures and label != "skipped":
                print(detail, file=sys.stderr)
    return counters, passed


def source_digests():
    digests = {}
    for name in (".python-version", "pyproject.toml", "uv.lock", "scripts/check.py",
                 "docs/specification.md", "protocol.lock.json"):
        path = ROOT / name
        digests[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    return digests


def environment():
    uname = os.uname()
    return {
        "kernel": uname.release,
        "machine": uname.machine,
        "system": uname.sysname,
        "python": platform.python_version(),
        "python_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
    }


def run_groups(args, argv):
    if args.candidate or args.criterion or args.out:
        raise Refusal("design-option-without-mode")
    groups = selected_groups(args.group)
    report = root_path(args.report, "report-path") if args.report else None
    if report:
        sys.addaudithook(forbid_child_processes)
    suite = discover(groups, in_process_only=report is not None)
    case_ids = sorted(test.id() for test in iter_tests(suite))
    counters, passed = run_suite(suite, args.show_failures)
    artifacts = {}
    if report:
        artifacts[report[1].as_posix()] = write_json(report[0], counters)
    print(json.dumps({
        "schema": "fiat-checkpoints-check/v1",
        "argv": ["python3", "scripts/check.py", *argv],
        "exit": 0 if passed else 1,
        "case_ids": case_ids,
        "counters": counters,
        "source_sha256": source_digests(),
        "environment": environment(),
        "artifact_sha256": artifacts,
    }, sort_keys=True))
    return 0 if passed else 1


def typed_value(value, unit):
    if unit == "boolean":
        return type(value) is bool
    return type(value) is int and value >= 0


def run_design(args):
    if args.group or args.report:
        raise Refusal("group-option-in-design-mode")
    if args.candidate not in CANDIDATES:
        raise Refusal("design-candidate-unknown")
    if args.criterion in SELECTION_CRITERIA:
        raise Refusal("design-criterion-selection-only")
    if args.criterion not in CONFORMANCE_UNITS:
        raise Refusal("design-criterion-unknown")
    if args.candidate != SELECTED_CANDIDATE:
        raise Refusal("design-candidate-not-selected")
    if args.out is None:
        raise Refusal("design-out-missing")
    out, relative = root_path(args.out, "design-out")
    expected = Path(*DESIGN_REPORT_DIRECTORY, args.candidate + "-" + args.criterion + ".json")
    if relative != expected:
        raise Refusal("design-out-unexpected")
    from fiat_checkpoints.conformance import DesignContext, RESOLVERS
    resolver = RESOLVERS.get(args.criterion)
    if resolver is None:
        raise Refusal("design-criterion-unavailable")

    def groups_pass(groups):
        suite = discover(selected_groups(",".join(groups)), in_process_only=False)
        return run_suite(suite, args.show_failures)[1]

    unit = CONFORMANCE_UNITS[args.criterion]
    value = resolver(DesignContext(ROOT, args.candidate, args.criterion, groups_pass))
    if not typed_value(value, unit):
        raise Refusal("design-value-type")
    command = ["python3", "scripts/check.py", "design", "--candidate", args.candidate,
               "--criterion", args.criterion, "--out", expected.as_posix()]
    digest = write_json(out, {
        "schema": "protasis-design-report/v1",
        "candidate": args.candidate,
        "criterion": args.criterion,
        "value": value,
        "unit": unit,
        "command": " ".join(command),
        "exit": 0,
    })
    print(json.dumps({"schema": "fiat-checkpoints-design/v1", "report": expected.as_posix(),
                      "sha256": digest, "value": value}, sort_keys=True))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    refuse_abbreviations(argv)
    args = build_parser().parse_args(argv)
    if sys.version_info[:3] != PYTHON_VERSION:
        raise Refusal("python-version-mismatch")
    sys.path.insert(0, str(ROOT / "src"))
    sys.path.insert(0, str(ROOT))
    if args.mode == "design":
        return run_design(args)
    return run_groups(args, argv)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        print("checks-refused: " + str(error), file=sys.stderr)
        raise SystemExit(2)
    except (OSError, ValueError, ImportError):
        print("checks-refused: check-input-unavailable", file=sys.stderr)
        raise SystemExit(2)
