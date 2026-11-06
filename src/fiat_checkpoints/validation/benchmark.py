"""Measure the released valid fixture through the whole sandboxed native sequence.

`scripts/benchmark.sh --profile local --corpus protocol.lock.json` runs the
fixture the lock's release ships, at its real size, `--repetitions` times one
after another, and prints raw samples with median and p95 wall time, CPU, peak
memory (which includes the job's tmpfs scratch) and process counts, plus the host, kernel, sandbox and tool
pins. It asserts the ceilings: every run completes inside the policy and under
the 900,000 ms validation budget. The numbers describe this host only.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import sys

from fiat_checkpoints.validation import fixture, pins
from fiat_checkpoints.validation.outputs import NativeEvidence
from fiat_checkpoints.validation.refusals import ValidationRefusal
from fiat_checkpoints.validation.sandbox import Sandbox
from fiat_checkpoints.validation.service import service_binds


SCHEMA = "fiat-checkpoints-benchmark/v1"
BUDGET_MS = 900_000
METRICS = ("wall_ms", "cpu_us", "memory_peak_bytes", "pids_peak")


def _p95(values):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, -(-95 * len(ordered) // 100) - 1))]


def host():
    meminfo = Path("/proc/meminfo").read_text(encoding="ascii").splitlines()
    total = next(int(line.split()[1]) * 1024 for line in meminfo if line.startswith("MemTotal:"))
    return {"kernel": os.uname().release, "machine": os.uname().machine, "cpus": os.cpu_count(),
            "memory_bytes": total, "python": platform.python_version()}


def measure(sandbox, release, repetitions, binds=()):
    archive = fixture.valid_archive(release)
    samples = []
    for index in range(repetitions):
        job_request = fixture.request(release, attempt="benchmark-%d" % index)
        outcome, run = fixture.run(sandbox, release, archive, job_request, fixture.run_trust(release), binds=binds)
        samples.append({"completed": isinstance(outcome, NativeEvidence), **run.resources,
                        "refusal": None if isinstance(outcome, NativeEvidence) else outcome.record()})
    summary = {metric: {"median": statistics.median(row[metric] for row in samples),
                        "p95": _p95([row[metric] for row in samples]),
                        "max": max(row[metric] for row in samples)} for metric in METRICS}
    passed = all(row["completed"] for row in samples) and summary["wall_ms"]["max"] <= BUDGET_MS
    return {"schema": SCHEMA, "fixture_bytes": len(archive), "repetitions": repetitions, "concurrency": 1,
            "samples": samples, "summary": summary, "policy": sandbox.policy.record(), "pins": pins.record(),
            "host": host(), "lock_sha256": release.lock_sha256, "trees_sha256": release.trees_sha256,
            "budget_ms": BUDGET_MS, "passed": passed}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Measure sandboxed validation of the released corpus")
    parser.add_argument("--profile", required=True, choices=["local"])
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    from fiat_checkpoints.records.trees import REPOSITORY, load_release
    if Path(args.corpus).resolve() != (REPOSITORY / "protocol.lock.json").resolve():
        print("benchmark-refused: corpus-not-the-shipped-lock", file=sys.stderr)
        return 2
    if not 1 <= args.repetitions <= 50:
        print("benchmark-refused: repetitions-out-of-range", file=sys.stderr)
        return 2
    release = load_release()
    sandbox = Sandbox()
    try:
        sandbox.check()
    except ValidationRefusal as refusal:
        print("benchmark-refused: " + refusal.reason, file=sys.stderr)
        return 2
    report = measure(sandbox, release, args.repetitions, binds=service_binds(REPOSITORY))
    text = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
