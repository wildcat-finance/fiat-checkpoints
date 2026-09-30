"""Resolvers for the selected design's pending conformance criteria.

`scripts/check.py design` looks a criterion up in `RESOLVERS` and refuses one
that has no entry. A resolver takes a `DesignContext` and returns the typed
value its criterion's unit names. The step that ships a criterion's evidence
registers its resolver here; the runner's own bytes stay fixed.
"""

from dataclasses import dataclass
import json
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
