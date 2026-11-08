"""Gateway incremental memory per stream, measured the way Step 5 measures it.

One scratch database, one private staging area and one local quarantine store
take two synthetic streams, of 4 MiB and 96 MiB, through the real gateway in
262,144-byte body messages, each a fresh bytes object. Memory is the traced Python allocation peak above
the level before the request, across every thread; disk is the largest staged
total seen between chunks and the staged and stored totals afterwards. The
grant check is answered in process and the endorsement is written as the row
Step 4 records after verifying one, so no process starts. Every byte is
synthetic. The `gateway-stream-memory` design criterion and
`tests/test_performance.py` both call `measure_stream_memory`.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import gc
import hashlib
import os
from pathlib import Path
import random
import resource
import secrets
import tempfile
import tracemalloc
from types import SimpleNamespace

from fiat_checkpoints.api.gateway import GatewayServices, create_gateway_app
from fiat_checkpoints.config import load_config
from fiat_checkpoints.domain.coordination import AnnounceRequest, QuotaPolicy, RunScope
from fiat_checkpoints.domain.identities import CheckpointIdentities
from fiat_checkpoints.grants.endorsement import EndorsementStore
from fiat_checkpoints.grants.intake import Intake
from fiat_checkpoints.persistence.coordinator import Coordinator
from fiat_checkpoints.persistence.migrations import migrate
from fiat_checkpoints.persistence.scratch import ScratchDatabase
from fiat_checkpoints.persistence.transfer import Transfers
from fiat_checkpoints.records.trees import REPOSITORY
from fiat_checkpoints.storage.quarantine import DirectoryQuarantine
from fiat_checkpoints.upload.issuer import UploadIssuer
from fiat_checkpoints.upload.staging import StagingArea


T0 = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
SCOPE = RunScope("fiat-checkpoints-test", 7, "fiat-" + "a" * 64)
ACTOR = 41
PARENT = "5" * 64
BLOCK_BYTES = 262_144
# 16 and 384 blocks: 4 MiB and 96 MiB.
COUNTS = (16, 384)
CAPACITY_BYTES = 128 * 1_048_576
SAMPLE_EVERY = 16


class _Grants:
    """Every grant check the issuer and gateway make answers current."""

    environment = "test"

    def run_for(self, scope):
        return SimpleNamespace(scope=scope, environment=self.environment)

    def current(self, _run):
        return self

    def named_grant(self, grant, _actor_id, _permission, _now):
        return grant

    def grant(self, actor_id, permission, now):
        return self.named_grant({"type": "run-grant", "sha256": "6" * 64}, actor_id, permission, now)


def _block():
    seed = hashlib.sha256(b"measure").digest()
    return (seed * (BLOCK_BYTES // len(seed) + 1))[:BLOCK_BYTES]


def _staged_bytes(directory):
    return sum(entry.stat(follow_symlinks=False).st_size for entry in os.scandir(directory))


async def _put(app, path, headers, block, count, sample):
    """One PUT as raw ASGI messages, so every chunk and every pause is the caller's."""
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "PUT",
             "scheme": "https", "path": path, "raw_path": path.encode(), "query_string": b"",
             "headers": [(name.encode(), value.encode()) for name, value in headers],
             "server": ("measure", 443), "client": ("127.0.0.1", 50000), "root_path": ""}
    sent, index = [], 0

    async def receive():
        nonlocal index
        if index >= count:
            await asyncio.Event().wait()
        if index % SAMPLE_EVERY == 0:
            sample()
        index += 1
        # A fresh object per message, as a server delivers it: a shared one would
        # hide a gateway that keeps every chunk (S7-R1-03).
        return {"type": "http.request", "body": bytes(memoryview(block)), "more_body": index < count}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return next(message["status"] for message in sent if message["type"] == "http.response.start")


def _measure(context, block, count):
    coordinator, endorsements, issuer = context["coordinator"], context["endorsements"], context["issuer"]
    digest = hashlib.sha256()
    for _ in range(count):
        digest.update(block)
    size, archive = len(block) * count, digest.hexdigest()
    key = ("measure-stream-%d" % count).ljust(16, "x")
    candidate = coordinator.announce(SCOPE, ACTOR, key, AnnounceRequest(archive, size, {}), T0).candidate_id
    identities = CheckpointIdentities("1" * 64, "2" * 64, archive)
    endorsements.bind(candidate, identities, PARENT, T0)
    challenge = endorsements.bind(candidate, identities, PARENT, T0)
    envelope = b'{"synthetic-endorsement":"' + secrets.token_hex(16).encode() + b'"}'
    connection = context["database"].connect()
    try:
        connection.execute(
            "INSERT INTO upload_endorsements (candidate_id, sequence, envelope, envelope_sha256, policy_sha256, "
            "enrollment_sha256, grant_sha256, key_fingerprint, trust_count, trust_tail_sha256, issued_at, "
            "expires_at, verified_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1, %s, %s, %s, %s)",
            (candidate, challenge.sequence, envelope, hashlib.sha256(envelope).hexdigest(), "7" * 64, "8" * 64,
             "6" * 64, "9" * 64, "4" * 64, T0, T0 + timedelta(seconds=120), T0))
    finally:
        connection.close()
    capability = issuer.issue(ACTOR, candidate, T0)
    headers = [("authorization", "Upload " + capability.value), ("content-length", str(size)),
               ("content-type", "application/octet-stream")]
    staging, quarantine = context["root"] / "staging", context["root"] / "quarantine"
    staged = []
    gc.collect()
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    tracemalloc.start()
    try:
        base = tracemalloc.get_traced_memory()[0]
        status = asyncio.run(_put(context["gateway"], "/v1/candidates/%s/content" % candidate, headers, block,
                                  count, lambda: staged.append(_staged_bytes(staging))))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {"status": status, "declared_bytes": size, "incremental_python_bytes": peak - base,
            "peak_rss_growth_kib": rss_after - rss_before, "staged_peak_bytes": max(staged),
            "staged_after_bytes": _staged_bytes(staging), "quarantine_bytes": _staged_bytes(quarantine)}


def measure_stream_memory():
    """Stream 4 MiB then 96 MiB through the gateway; one row per stream with its HTTP status."""
    with tempfile.TemporaryDirectory(prefix="fiat-checkpoints-measure-") as directory:
        root = Path(directory)
        for name in ("staging", "quarantine"):
            (root / name).mkdir(mode=0o700)
        scratch = ScratchDatabase()
        try:
            migrate(scratch.database)
            coordinator = Coordinator(scratch.database, quotas=QuotaPolicy(), random_source=random.Random(7))
            grants = _Grants()
            endorsements = EndorsementStore(scratch.database)
            staging = StagingArea(root / "staging", capacity_bytes=CAPACITY_BYTES)
            quarantine = DirectoryQuarantine(root / "quarantine")
            try:
                settings = load_config(REPOSITORY / "config/local.json")
                gateway = create_gateway_app(settings, GatewayServices(
                    Transfers.from_coordinator(coordinator), endorsements, grants, staging, quarantine,
                    lambda: T0))
                issuer = UploadIssuer(Intake(scratch.database, coordinator, grants), environment=settings.environment_id)
                context = {"coordinator": coordinator, "endorsements": endorsements, "issuer": issuer,
                           "database": scratch.database, "gateway": gateway, "root": root}
                block = _block()
                return [_measure(context, block, count) for count in COUNTS]
            finally:
                quarantine.close()
                staging.close()
        finally:
            scratch.close()
