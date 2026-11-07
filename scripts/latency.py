#!/usr/bin/env python3
"""Hold the metadata latency gate on the native aarch64 latency profile.

    FIAT_LINUX_PROFILE=latency scripts/linux-env.sh db-start
    FIAT_LINUX_PROFILE=latency scripts/linux-env.sh run python3 scripts/latency.py --profile arm64-native

Specification section 17 asks for metadata p95 of at most 500 ms on the
declared local profile, excluding identity-provider calls. The x86_64 check
profile runs under emulation, so this gate runs on a native aarch64 Linux VM.
Four actors each announce, endorse, upload, complete and read five synthetic
candidates over HTTP on loopback against the PostgreSQL 16 test server. Each
announce, endorsement, complete and status request is one sample; login,
which calls the identity provider, and the upload body are not.

It prints one JSON report holding every sample; `--out` also writes the same
bytes to a new file. Exit 0: all 80 samples, no refused request and a
nearest-rank p95 of at most 500 ms. Exit 1: measured, and the gate failed.
Exit 2: refused, with one fixed code on stderr and no report. Run it on a
quiet host; the number says nothing about production capacity.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import sys


ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "fiat-checkpoints-latency/v1"
PYTHON_VERSION = (3, 14, 6)
OPTIONS = frozenset({"--profile", "--out"})
# Each profile the gate may run on, and the host it requires.
PROFILES = {"arm64-native": ("Linux", "aarch64")}
P95_LIMIT_MS = 500
SAMPLES = 80


class Refusal(Exception):
    """A fixed code; no supplied value, path or library message."""


def build_parser():
    parser = argparse.ArgumentParser(description="Hold the metadata latency gate on the latency profile")
    parser.add_argument("--profile")
    parser.add_argument("--out")
    return parser


def refuse_abbreviations(argv):
    # argparse accepts unique prefixes; an exact option name is required here.
    for token in argv:
        if token == "--":
            break
        if token.startswith("--") and token.split("=", 1)[0] not in OPTIONS:
            raise Refusal("option-unknown")


def out_path(name):
    """A name for a new file in an existing directory; an existing name or a linked parent refuses."""
    path = Path(name)
    if not path.is_absolute():
        path = Path.cwd() / path
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise Refusal("out-invalid")
    if path.exists() or path.is_symlink():
        raise Refusal("out-exists")
    return path


def measure():
    """The metadata workload of `tests/test_demo_scenario.py`, run once in this process."""
    sys.path[:0] = [str(ROOT), str(ROOT / "src")]
    try:
        from tests.test_demo_scenario import DemoRefusal, measure_metadata
    except Exception:
        raise Refusal("measurement-unavailable") from None
    try:
        return measure_metadata()
    except DemoRefusal as error:
        raise Refusal(str(error)) from None
    except Exception:
        # The exception may carry a path or a library message; only a fixed code leaves.
        raise Refusal("measurement-failed") from None


def verdict(record):
    """True only with every sample, no refused request and a p95 within the limit."""
    count, p95 = record.get("count"), record.get("p95_ms")
    return (type(count) is int and count == SAMPLES and record.get("refused") == []
            and type(p95) in (int, float) and 0 <= p95 <= P95_LIMIT_MS)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    refuse_abbreviations(argv)
    args = build_parser().parse_args(argv)
    if args.profile is None:
        raise Refusal("profile-missing")
    if args.profile not in PROFILES:
        raise Refusal("profile-unknown")
    uname = os.uname()
    if (uname.sysname, uname.machine) != PROFILES[args.profile]:
        raise Refusal("latency-profile-required")
    if sys.version_info[:3] != PYTHON_VERSION:
        raise Refusal("python-version-mismatch")
    out = None if args.out is None else out_path(args.out)
    record = measure()
    passed = verdict(record)
    report = {"schema": SCHEMA, "profile": args.profile, "limit_ms": P95_LIMIT_MS, "samples_required": SAMPLES,
              "host": {"system": uname.sysname, "machine": uname.machine, "kernel": uname.release,
                       "cpus": os.cpu_count(), "python": platform.python_version()},
              "measurement": record, "passed": passed}
    text = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
    if out is not None:
        descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
    sys.stdout.write(text)
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        print("latency-refused: " + str(error), file=sys.stderr)
        raise SystemExit(2)
    except OSError:
        print("latency-refused: output-unavailable", file=sys.stderr)
        raise SystemExit(2)
