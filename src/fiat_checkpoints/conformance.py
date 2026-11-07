"""Resolvers for the selected design's pending conformance criteria.

`scripts/check.py design` looks a criterion up in `RESOLVERS` and refuses one
that has no entry. A resolver takes a `DesignContext` and returns the typed
value its criterion's unit names. The step that ships a criterion's evidence
registers its resolver here; the runner's own bytes stay fixed.
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
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
NATIVE_STAGES = ("inspect", "restore", "verify", "identity")
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


def _native_valid_fixture(root):
    """One sandboxed job over the released valid fixture: the release and `(outcome, SandboxRun)`."""
    from fiat_checkpoints.validation import fixture
    from fiat_checkpoints.validation.service import service_binds
    release = _release(root)
    sandbox = _sandbox()
    job = fixture.run(sandbox, release, fixture.valid_archive(release),
                      fixture.request(release, attempt="design-native-sequence"), fixture.run_trust(release),
                      binds=service_binds(root))
    return release, job


def native_sequence_linux(context):
    """The pinned native sequence completes on the released valid fixture inside the validator image.

    True only on Linux x86_64 when one fresh gVisor job runs inspect, restore,
    verify with observations and identity in order with exit 0, the reminted
    identity is the fixture's, commit-signature coverage is complete over the
    fixture's required commits, nothing was killed, and the `sandbox` group,
    whose cases run the same sequence and every released hostile id, passes in
    this process.
    """
    from fiat_checkpoints.validation import fixture
    from fiat_checkpoints.validation.outputs import NativeEvidence
    from fiat_checkpoints.validation.refusals import ValidationRefusal

    if not _linux_x86_64():
        return False
    try:
        release, (outcome, run) = _native_valid_fixture(context.root)
    except ValidationRefusal:
        return False
    if not isinstance(outcome, NativeEvidence) or run.killed is not None:
        return False
    record = outcome.record
    value, _ = fixture.released(release)
    stages = [(row["stage"], row["exit"]) for row in record["native_results"]]
    held = (stages == [(stage, 0) for stage in NATIVE_STAGES] and record["complete"] is True
            and record["coverage"]["complete"] is True
            and record["coverage"]["required"] == sorted(value["required"])
            and record["identity"]["snapshot_id"] == value["snapshot_id"])
    return held and context.run_groups(("sandbox",))


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
