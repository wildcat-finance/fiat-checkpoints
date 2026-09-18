#!/usr/bin/env python3
"""Run named repository test groups; a skip or an empty group refuses success."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
PYTHON_VERSION = (3, 12, 13)
DESIGN_GROUPS = {
    "released-protocol": {"protocol", "domain"},
    "intake-validation": {"auth", "upload", "quarantine", "validation", "sandbox"},
    "validation-wall-time": {"performance"},
    "gateway-incremental-memory": {"performance"},
    "restart-and-fencing": {"persistence", "concurrency"},
}


class Refusal(Exception):
    """A fixed diagnostic code without test output or supplied path values."""


def build_parser():
    parser = argparse.ArgumentParser(description="Run checkpoint service checks")
    parser.add_argument("--group", default="all")
    parser.add_argument("--report")
    parser.add_argument("--design-report")
    parser.add_argument("--candidate")
    parser.add_argument("--criterion")
    return parser


def write_report(name, value):
    """Atomically replace a regular report below ROOT; refuse symlink parents."""
    path = Path(name)
    if not path.is_absolute():
        path = ROOT / path
    try:
        relative = path.relative_to(ROOT)
    except ValueError as exc:
        raise Refusal("report-path-outside-root") from exc
    if not relative.parts or any(p in (".", "..", ".git") for p in relative.parts):
        raise Refusal("report-path-invalid")
    current = ROOT
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise Refusal("report-path-symlink")
    if path.exists() and not stat.S_ISREG(path.stat().st_mode):
        raise Refusal("report-not-regular")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd, temporary = tempfile.mkstemp(prefix=".check-report-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def iter_tests(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from iter_tests(item)
        else:
            yield item


def selected_groups(raw):
    groups = raw.split(",")
    if len(groups) > 32 or len(set(groups)) != len(groups) or any(
        re.fullmatch(r"[a-z][a-z0-9_]{0,63}", group) is None for group in groups
    ) or ("all" in groups and len(groups) != 1):
        raise Refusal("test-group-invalid")
    return groups


def discover(groups):
    suite = unittest.TestSuite()
    seen = set()
    for group in groups:
        patterns = ["test_*.py"] if group == "all" else [
            "test_" + group + ".py", "test_" + group + "_*.py"
        ]
        tests = []
        for pattern in patterns:
            loader = unittest.TestLoader()
            tests.extend(iter_tests(loader.discover(
                str(ROOT / "tests"), pattern=pattern, top_level_dir=str(ROOT)
            )))
        if not tests:
            raise Refusal("test-group-empty")
        for test in tests:
            if test.id() not in seen:
                seen.add(test.id())
                suite.addTest(test)
    return suite


def timed_out(_signum, _frame):
    # A TestCase can catch exceptions, so the outer deadline exits the process.
    print("checks-refused: test-budget-exhausted", file=sys.stderr, flush=True)
    os._exit(2)


def main(argv=None):
    args = build_parser().parse_args(argv)
    if sys.version_info[:3] != PYTHON_VERSION:
        raise Refusal("python-version-mismatch")
    groups = selected_groups(args.group)
    if args.design_report:
        required = DESIGN_GROUPS.get(args.criterion)
        if args.candidate != "mediated-isolated" or required is None or set(groups) != required:
            raise Refusal("design-suite-mismatch")
    elif args.candidate or args.criterion:
        raise Refusal("design-report-missing")
    sys.path.insert(0, str(ROOT / "src"))
    sys.path.insert(0, str(ROOT))
    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(180)
    try:
        suite = discover(groups)
        case_ids = sorted(test.id() for test in iter_tests(suite))
        # Test code is repository-owned; child outputs never become service telemetry.
        result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=1).run(suite)
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
    passed = result.testsRun > 0 and all(counters[name] == 0 for name in (
        "failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses"
    ))
    if args.report:
        write_report(args.report, counters)
    command = shlex.join(["python3", "scripts/check.py", *(sys.argv[1:] if argv is None else argv)])
    if args.design_report:
        write_report(args.design_report, {
            "schema": "protasis-design-report/v1",
            "candidate": args.candidate,
            "criterion": args.criterion,
            "value": passed,
            "unit": "boolean",
            "command": command,
            "exit": 0 if passed else 1,
        })
    sources = {}
    for name in (".python-version", "pyproject.toml", "uv.lock", "scripts/check.py",
                 "docs/specification.md", "protocol.lock.json"):
        path = ROOT / name
        sources[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    artifacts = {}
    for name in (args.report, args.design_report):
        if name:
            path = Path(name) if Path(name).is_absolute() else ROOT / name
            artifacts[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps({
        "schema": "fiat-checkpoints-check/v1", "command": command,
        "exit": 0 if passed else 1, "case_ids": case_ids, "counters": counters,
        "source_sha256": sources, "python": ".".join(map(str, sys.version_info[:3])),
        "tool_sha256": {"python": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()},
        "artifact_sha256": artifacts,
    }, sort_keys=True))
    for label, values in (("failure", result.failures), ("error", result.errors)):
        for test, _ in values:
            print(label + ": " + test.id(), file=sys.stderr)
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        print("checks-refused: " + str(error), file=sys.stderr)
        raise SystemExit(2)
    except (OSError, ValueError, ImportError):
        print("checks-refused: check-input-unavailable", file=sys.stderr)
        raise SystemExit(2)
