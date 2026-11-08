"""Resolvers for the selected design's pending conformance criteria.

`scripts/check.py design` looks a criterion up in `RESOLVERS` and refuses one
that has no entry. A resolver takes a `DesignContext` and returns the typed
value its criterion's unit names. The step that ships a criterion's evidence
registers its resolver here; the runner's own bytes stay fixed.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Callable


@dataclass(frozen=True)
class DesignContext:
    root: Path
    candidate: str
    criterion: str
    # Runs named groups in this process and returns True only for a clean pass.
    run_groups: Callable[[tuple[str, ...]], bool]


RESOLVERS: dict[str, Callable[[DesignContext], object]] = {}


PROTOCOL_CODES = frozenset({
    "protocol-pin-missing", "protocol-lock-malformed", "protocol-trees-missing",
    "protocol-trees-malformed", "protocol-tree-commit", "protocol-tree-relocated",
    "protocol-tree-missing", "protocol-tree-unsafe", "protocol-tree-writable",
    "protocol-tree-extra", "protocol-tree-drift", "protocol-file-unsafe",
    "protocol-file-changed", "protocol-import-failed", "protocol-lock-refused",
    "protocol-python-mismatch",
})


def production_settings():
    """Production declarations only; nothing here can open production."""
    from fiat_checkpoints.config import parse_config
    return parse_config(json.dumps({
        "schema_version": 1, "profile": "production", "service_id": "fiat-checkpoints",
        "environment_id": "production", "host": "127.0.0.1", "port": 8000,
        "trust_profile": "production", "protocol_lock": "protocol.lock.json",
        "sandbox_profile": "gvisor", "request_max_bytes": 65536,
        "carrier_max_bytes": 1073741824, "validation_concurrency": 1,
    }).encode())


def protocol_lock_shipped(context):
    """The shipped lock passes the released `lock` check and startup refuses without it."""
    from fiat_checkpoints.api.app import production_refusals
    from fiat_checkpoints.records.refusals import RecordRefusal
    from fiat_checkpoints.records.trees import DEFAULT_TREES, load_release

    try:
        release = load_release(context.root, DEFAULT_TREES)
    except RecordRefusal:
        return False
    lock = json.loads((context.root / "protocol.lock.json").read_bytes())
    shipped = (release.lock_check["code"] == "lock-agrees"
               and release.lock_check["source_commit"] == lock["authority"]["source_commit"]
               and release.lock_check["release_manifest_sha256"] == lock["authority"]["release_manifest_sha256"])
    settings = production_settings()
    with_lock = production_refusals(settings, context.root, DEFAULT_TREES)
    with tempfile.TemporaryDirectory() as temporary:
        without_lock = production_refusals(settings, Path(temporary), DEFAULT_TREES)
    refuses = "protocol-pin-missing" in without_lock and not PROTOCOL_CODES & set(with_lock)
    return shipped and refuses and context.run_groups(("protocol",))


RESOLVERS["protocol-lock-shipped"] = protocol_lock_shipped


def restart_recovery(context):
    """Migration, restart and stale-fence checks produce no unauthorized intent.

    The value is true only when the restart scenario's every observation holds
    against the pinned PostgreSQL 16 server and the persistence and
    concurrency groups pass in this process.
    """
    from fiat_checkpoints.persistence.restart import holds

    return holds() and context.run_groups(("persistence", "concurrency"))


RESOLVERS["restart-recovery"] = restart_recovery


# Integration criteria (Step 7). Native sequence, hostile suites and wall time
# start gVisor, so they run as the validator image's supervisor
# (`scripts/sandbox-env.sh run`); gateway memory needs only PostgreSQL.

# The seven groups the study's hostile-suite criterion names.
HOSTILE_GROUPS = ("protocol", "domain", "auth", "upload", "quarantine", "validation", "sandbox")
# Specification section 20: the released corpus declares 35 hostile fixture ids.
REJECTION_IDS = 35
WALL_REPETITIONS = 3


def _linux_x86_64():
    uname = os.uname()
    return (uname.sysname, uname.machine) == ("Linux", "x86_64")


def _release(root):
    from fiat_checkpoints.records.trees import DEFAULT_TREES, load_release
    return load_release(root, DEFAULT_TREES)


def _sandbox():
    """The pinned gVisor launcher, or `ValidationRefusal` when this host cannot run it."""
    from fiat_checkpoints.validation.sandbox import Sandbox
    sandbox = Sandbox()
    sandbox.check()
    return sandbox


# The released native criterion (S7-R1-01). The test-only criterion image
# (containers/criterion.Dockerfile) puts its closure from Skills 685158cd and
# native commit 1d4e4eeb, and gpg-agent, in the sandbox root filesystem.
CRITERION_LIST = Path("/opt/fiat-checkpoints/criterion.sha256")
CRITERION_JOB_ROOT = "/opt/fiat-checkpoints/criterion"
CRITERION_REPORT = ".hexaemeron/reports/ordered-replay-native-boundary-coverage.json"
# The criterion job alone exceeds the 300 s validation job CPU ceiling (S7-R2-01).
# On the emulated x86_64 profile it used 2,177.9 s of CPU before the released
# criterion's own 1,800 s deadline stopped it, and a complete run outside gVisor
# took 5,690 s; it runs on a native x86_64 host instead. The job's quota is 2 CPUs,
# so 3,600 s is the most it can use inside that deadline: the released deadline
# binds, not this budget. Wall time is the deadline plus 600 s for the copy and
# the manifest check, so a timeout is the criterion's own recorded refusal. Every
# other limit is the validation job's.
CRITERION_CPU_SECONDS = 3600
CRITERION_WALL_SECONDS = 2400
EXECUTION_COUNTERS = ("failures", "errors", "skips", "expected_failures", "unexpected_successes")
# What the finishing event repeats from the driver's summary, so a false value says why.
CRITERION_EVENT_FIELDS = ("corpus_exit", "criterion_exit", "corpus_event", "criterion_event", "corpus_stderr",
                          "criterion_stderr", "read_error", "code", "complete", "runner_exit", "executed",
                          "execution", "report_sha256")
# Runs in the job as the sandbox user: copy the read-only criterion root to the
# job's scratch (the conformance runner writes its report under it), run the
# released manifest check and the criterion, and print one bounded summary.
CRITERION_DRIVER = r"""
import hashlib, json, os, shutil, subprocess, sys
source, native, root = sys.argv[1], sys.argv[2], "/job/criterion"
shutil.copytree(source, root)
for parent, _directories, files in os.walk(root):
    os.chmod(parent, 0o700)
    for name in files:
        os.chmod(os.path.join(parent, name), 0o600)
environment = dict(os.environ, CHECKPOINT_AUTHORITY_NATIVE_SOURCE=native)
FIELDS = ("event", "stage", "code", "status", "exit")
def run(name, *arguments):
    done = subprocess.run([sys.executable, *arguments], cwd=root, env=environment, capture_output=True)
    # Each child's stderr leaves only as a digest and a byte count. The released
    # runner's own last stdout line is a fixed-vocabulary event; only its short
    # string and integer fields are kept.
    summary[name + "_exit"] = done.returncode
    summary[name + "_stderr"] = {"sha256": hashlib.sha256(done.stderr).hexdigest(), "bytes": len(done.stderr)}
    lines = done.stdout.strip().splitlines()
    try:
        event = json.loads(lines[-1]) if lines else None
    except ValueError:
        event = None
    if type(event) is dict:
        summary[name + "_event"] = {key: event[key] for key in FIELDS if key in event
                                    and ((type(event[key]) is str and len(event[key]) <= 64)
                                         or type(event[key]) is int)}
summary = {}
run("corpus", "plugins/hexaemeron/tests/checkpoint_authority_native_corpus.py", "--check")
run("criterion", "plugins/hexaemeron/tests/checkpoint_authority_conformance.py",
    "--candidate", "ordered-replay", "--criterion", "native-boundary-coverage", "--report", sys.argv[3])
stage = "report"
try:
    with open(os.path.join(root, sys.argv[3]), "rb") as stream:
        report = stream.read()
    stage = "evidence"
    with open(os.path.join(root, sys.argv[3][:-5] + ".evidence.json"), "rb") as stream:
        evidence = json.loads(stream.read())
    execution = evidence.get("execution") or {}
    summary.update(report=json.loads(report), report_sha256=hashlib.sha256(report).hexdigest(),
                   code=evidence.get("code"), complete=evidence.get("complete"),
                   runner_exit=evidence.get("runner_exit"), executed=len(evidence.get("executed_cases") or []),
                   execution={key: value for key, value in execution.items()
                              if key not in ("native", "started", "completed")},
                   native=execution.get("native") is not None)
except (OSError, ValueError, AttributeError) as error:
    summary["read_error"] = {"file": stage, "type": type(error).__name__}
print(json.dumps(summary, sort_keys=True))
"""


def _criterion_files(listing=None, base=None):
    """True only when every listed criterion file is in the root filesystem with its digest, and nothing else."""
    from fiat_checkpoints.validation import pins
    listing = CRITERION_LIST if listing is None else listing
    base = pins.ROOTFS / CRITERION_JOB_ROOT.lstrip("/") if base is None else base
    expected = {}
    try:
        for row in listing.read_text(encoding="ascii").splitlines():
            digest, separator, path = row.partition("  ")
            if (not separator or len(digest) != 64 or set(digest) - set("0123456789abcdef")
                    or path in expected):
                return False
            expected[path] = digest
        present = {}
        for path in base.rglob("*"):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                return False
            if path.is_file():
                present[path.relative_to(base).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, UnicodeError):
        return False
    return bool(expected) and present == expected


def _criterion_policy():
    """The criterion job's limits: the validation job's, with only CPU and wall time raised."""
    from fiat_checkpoints.validation.policy import ResourcePolicy

    class CriterionPolicy(ResourcePolicy):
        # The validation policy refuses any value above the specification's; this
        # one is never a validation job's, so it checks only that each is positive.
        def __post_init__(self):
            for name, value in self.record().items():
                if type(value) is not int or value < 1:
                    raise ValueError("resource-policy-invalid")

    return CriterionPolicy(cpu_seconds=CRITERION_CPU_SECONDS, wall_seconds=CRITERION_WALL_SECONDS)


def _criterion_run():
    """One fresh gVisor job running the released criterion: the `SandboxRun` and the driver's summary."""
    from fiat_checkpoints.validation import pins
    from fiat_checkpoints.validation.sandbox import Sandbox, SandboxJob
    sandbox = Sandbox(_criterion_policy())
    sandbox.check()
    run = sandbox.run(SandboxJob(
        owner="design-native-boundary-coverage", trust=b"{}",
        argv=(pins.SANDBOX_PYTHON, "-I", "-c", CRITERION_DRIVER, CRITERION_JOB_ROOT + "/root",
              CRITERION_JOB_ROOT + "/native-source", CRITERION_REPORT)))
    try:
        summary = json.loads(run.stdout)
    except ValueError:
        summary = None
    return run, summary if type(summary) is dict else None


def _criterion_passed(run, summary):
    """True only for a complete run with every case executed and none failed, errored or skipped."""
    if run.exit != 0 or run.killed is not None or summary is None:
        return False
    report, execution = summary.get("report"), summary.get("execution")
    if type(report) is not dict or type(execution) is not dict:
        return False
    executed = summary.get("executed")
    return (summary.get("corpus_exit") == 0 and summary.get("criterion_exit") == 0
            and report.get("schema") == "protasis-design-report/v1"
            and report.get("criterion") == "native-boundary-coverage"
            and report.get("value") is True and report.get("exit") == 0
            and summary.get("code") == "cases-passed" and summary.get("complete") is True
            and summary.get("runner_exit") == 0 and summary.get("native") is True
            and execution.get("complete") is True and execution.get("passed") is True
            and type(executed) is int and executed > 0 and execution.get("tests_run") == executed
            and all(execution.get(name) == 0 for name in EXECUTION_COUNTERS))


def native_sequence_linux(context):
    """The released native criterion passes every case inside the validator image.

    The criterion is Skills' own: `checkpoint_authority_native_corpus.py --check`
    and `checkpoint_authority_conformance.py --criterion native-boundary-coverage`,
    which runs `checkpoint_authority_native_suite.py`. It runs in one fresh
    gVisor job on the criterion image's root filesystem. The value is true only
    on Linux x86_64 when every listed criterion file is present with its digest
    and nothing else, and the run completes with both commands exiting 0, the
    report true, every case executed and no failure, error or skip. A host
    without the criterion image refuses before any job starts.
    """
    from fiat_checkpoints.validation.refusals import ValidationRefusal

    if not _linux_x86_64() or not _criterion_files():
        return False
    try:
        run, summary = _criterion_run()
    except ValidationRefusal:
        return False
    seen = summary or {}
    print(json.dumps({"event": "native-criterion-finished", "exit": run.exit, "killed": run.killed,
                      "resources": run.resources, "summary_parsed": summary is not None,
                      **{key: seen.get(key) for key in CRITERION_EVENT_FIELDS}}, sort_keys=True), file=sys.stderr)
    return _criterion_passed(run, summary)


RESOLVERS["native-sequence-linux"] = native_sequence_linux


def _rejection_rows(root):
    """Replay every declared hostile id through the sandboxed inspect, as `reject-case.sh --all` does."""
    from fiat_checkpoints.validation.reject import replay
    from fiat_checkpoints.validation.service import service_binds
    from fiat_checkpoints.validation.specimens import Corpus
    release = _release(root)
    corpus = Corpus.released(release)
    sandbox = _sandbox()
    return corpus.declared(), [replay(sandbox, release, corpus, item, binds=service_binds(root))
                               for item in corpus.ids()]


def intake_hostile_suites(context):
    """The seven named groups pass and every released hostile id refuses at its declared phase.

    The rejection rows are the ones `scripts/reject-case.sh --all` prints: all
    35 declared ids, each refused with its declared class at its declared
    stage. The groups then run in this process.
    """
    from fiat_checkpoints.validation.refusals import ValidationRefusal

    try:
        declared, rows = _rejection_rows(context.root)
    except ValidationRefusal:
        return False
    replayed = (len(declared) == REJECTION_IDS and len(rows) == len(declared)
                and sorted(row["id"] for row in rows) == sorted(declared)
                and all(row["passed"] is True for row in rows))
    return replayed and context.run_groups(HOSTILE_GROUPS)


RESOLVERS["intake-hostile-suites"] = intake_hostile_suites


def _validation_samples(root):
    """`scripts/benchmark.sh`'s measurement: the released valid fixture, one job at a time."""
    from fiat_checkpoints.validation.benchmark import measure
    from fiat_checkpoints.validation.service import service_binds
    release = _release(root)
    return measure(_sandbox(), release, WALL_REPETITIONS, binds=service_binds(root))["samples"]


def validation_wall_time(context):
    """The largest wall time, in milliseconds, of three sandboxed validations of the valid fixture.

    With three samples that is the nearest-rank p95. A run that did not
    complete, or a host that cannot start the pinned sandbox, has no
    measurement, so the criterion refuses rather than report a number.
    """
    from fiat_checkpoints.validation.refusals import ValidationRefusal

    try:
        samples = _validation_samples(context.root)
    except ValidationRefusal:
        raise ValueError("validation-unavailable") from None
    if (len(samples) != WALL_REPETITIONS or not all(row["completed"] is True for row in samples)
            or not all(type(row["wall_ms"]) is int and row["wall_ms"] >= 0 for row in samples)):
        raise ValueError("validation-incomplete")
    return max(row["wall_ms"] for row in samples)


RESOLVERS["validation-wall-time"] = validation_wall_time


def _stream_memory():
    from fiat_checkpoints.demo.streams import measure_stream_memory
    return measure_stream_memory()


def gateway_stream_memory(context):
    """The largest incremental gateway memory, in bytes, of one 4 MiB and one 96 MiB stream.

    Memory is the traced Python allocation peak above the level before the
    request, across every thread, through the gateway, staging, the local
    quarantine store, read-back and seal against the PostgreSQL 16 test
    server. Each stream must seal (202) and leave nothing staged.
    """
    rows = _stream_memory()
    if not rows or not all(row["status"] == 202 and row["staged_after_bytes"] == 0
                           and type(row["incremental_python_bytes"]) is int for row in rows):
        raise ValueError("stream-measurement-incomplete")
    return max(row["incremental_python_bytes"] for row in rows)


RESOLVERS["gateway-stream-memory"] = gateway_stream_memory
