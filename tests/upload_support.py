"""Shared set-up for the upload and quarantine groups.

Each test gets a migrated scratch database, a private staging directory and a
private quarantine directory. Grants are answered by an in-process stub and
endorsements are written as rows, so these checks start no verifier process;
`tests/test_upload_flow.py` repeats the path with real operator-signed
records. Requests reach the gateway as raw ASGI messages, so a test controls
every header, every chunk, every pause and the moment a client disconnects.
All bytes are synthetic.
"""

import asyncio
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
from types import SimpleNamespace

from fiat_checkpoints.api.gateway import GatewayLimits, GatewayServices, create_gateway_app
from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.config import load_config
from fiat_checkpoints.domain.coordination import RunScope
from fiat_checkpoints.domain.identities import CheckpointIdentities
from fiat_checkpoints.grants.endorsement import EndorsementStore
from fiat_checkpoints.grants.intake import Intake
from fiat_checkpoints.persistence.transfer import Transfers
from fiat_checkpoints.storage.quarantine import DirectoryQuarantine, QuarantineError, _file_name
from fiat_checkpoints.upload.issuer import UploadIssuer
from fiat_checkpoints.upload.staging import StagingArea
from tests.persistence_support import T0, DatabaseCase, key, request as announce_request


ROOT = Path(__file__).resolve().parents[1]
SETTINGS = load_config(ROOT / "config/local.json")
SCOPE = RunScope("fiat-checkpoints-test", 7, "fiat-" + "a" * 64)
ACTOR = 41
OTHER_ACTOR = 42
PARENT = "5" * 64
CHUNK = 65_536
MIB = 1_048_576


def payload(size, seed=b"synthetic"):
    """Deterministic synthetic bytes of exactly `size`."""
    block = hashlib.sha256(seed).digest() * (CHUNK // 32)
    whole, rest = divmod(size, len(block))
    return block * whole + block[:rest]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class Declared:
    """A body declared by digest and size only, for streams too large to hold in a test."""

    def __init__(self, digest, size):
        self.digest, self.size = digest, size


def declared(value):
    """The (SHA-256, size) a candidate declares for `value`: bytes or a `Declared`."""
    if isinstance(value, Declared):
        return value.digest, value.size
    return sha256(value), len(value)


def repeated(block, count):
    """One block `count` times: its declaration and the steps that stream it without copying."""
    digest = hashlib.sha256()
    for _ in range(count):
        digest.update(block)
    steps = [chunk(block) for _ in range(count)]
    steps[-1] = chunk(block, False)
    return Declared(digest.hexdigest(), len(block) * count), steps


class GrantStub:
    """Answers the grant checks the issuer and gateway make; `refusal` makes every check refuse."""

    environment = "test"

    def __init__(self):
        self.refusal = None
        self.checked = []

    def run_for(self, scope):
        return SimpleNamespace(scope=scope, environment=self.environment)

    def current(self, _run):
        return self

    def named_grant(self, grant, actor_id, permission, now):
        self.checked.append((grant["sha256"], actor_id, permission, now))
        if self.refusal is not None:
            raise self.refusal
        return grant

    def grant(self, actor_id, permission, now):
        return self.named_grant({"type": "run-grant", "sha256": "6" * 64}, actor_id, permission, now)


def revoked():
    return AuthRefusal("endorsement_invalid", "grant-not-current")


# Requests as ASGI messages -------------------------------------------------


def chunk(data, more=True):
    return ("chunk", data, more)


def pause(seconds):
    return ("pause", seconds)


def effect(function):
    return ("effect", function)


def disconnect():
    return ("disconnect",)


def body_steps(data, size=CHUNK):
    """The whole body in chunks, the last one ending the request."""
    steps = [chunk(data[offset:offset + size]) for offset in range(0, len(data), size)]
    if steps:
        steps[-1] = chunk(steps[-1][1], False)
    else:
        steps = [chunk(b"", False)]
    return steps


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.text = body.decode()
        self.body = json.loads(body) if body else None

    def header(self, name):
        values = [value for key, value in self.headers if key == name]
        return values[0] if values else None


async def exchange(app, method, path, headers, steps):
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
             "scheme": "https", "path": path, "raw_path": path.encode(), "query_string": b"",
             "headers": [(name.lower().encode(), value.encode()) for name, value in headers],
             "server": ("testserver", 443), "client": ("127.0.0.1", 50000), "root_path": ""}
    pending = list(steps)
    sent = []

    async def receive():
        while pending:
            step = pending.pop(0)
            if step[0] == "chunk":
                return {"type": "http.request", "body": step[1], "more_body": step[2]}
            if step[0] == "pause":
                await asyncio.sleep(step[1])
            elif step[0] == "effect":
                step[1]()
            elif step[0] == "disconnect":
                return {"type": "http.disconnect"}
        # A client that has stopped sending: the gateway's own limits must end the wait.
        await asyncio.Event().wait()

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    start = next(message for message in sent if message["type"] == "http.response.start")
    body = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    headers = [(bytes(name).decode(), bytes(value).decode()) for name, value in start["headers"]]
    return Response(start["status"], headers, body)


def run(coroutine):
    return asyncio.run(coroutine)


class UploadCase(DatabaseCase):
    """A gateway, an issuer and their stores over one migrated database."""

    capacity_bytes = 64 * MIB
    limits = GatewayLimits()

    def setUp(self):
        super().setUp()
        self.clock_now = T0
        self.transfers = Transfers.from_coordinator(self.coordinator)
        self.endorsements = EndorsementStore(self.database)
        self.grants = GrantStub()
        directory = tempfile.TemporaryDirectory(prefix="fiat-checkpoints-upload-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "staging").mkdir(mode=0o700)
        (self.root / "quarantine").mkdir(mode=0o700)
        self.staging = self.make_staging()
        self.quarantine = self.make_quarantine()
        self.addCleanup(self.quarantine.close)
        self.gateway = self.make_gateway()
        intake = Intake(self.database, self.coordinator, self.grants)
        self.issuer = UploadIssuer(intake, environment=SETTINGS.environment_id)

    def make_staging(self, **options):
        options.setdefault("capacity_bytes", self.capacity_bytes)
        area = StagingArea(self.root / "staging", **options)
        self.addCleanup(area.close)
        return area

    def make_quarantine(self, **faults):
        return FaultyQuarantine(self.root / "quarantine", **faults)

    def clock(self):
        return self.clock_now

    def advance(self, seconds):
        self.clock_now += timedelta(seconds=seconds)
        return self.clock_now

    def services(self, **changes):
        values = {"transfers": self.transfers, "endorsements": self.endorsements, "projections": self.grants,
                  "staging": self.staging, "quarantine": self.quarantine, "clock": self.clock,
                  "limits": self.limits}
        values.update(changes)
        return GatewayServices(**values)

    def make_gateway(self, **changes):
        return create_gateway_app(SETTINGS, self.services(**changes))

    # Candidates and endorsements ------------------------------------------

    def announce(self, data, label="one", actor=ACTOR, scope=SCOPE, now=None):
        """Announce `data` and bind its first challenge; returns the candidate id."""
        now = now or self.clock_now
        digest, size = declared(data)
        announced = self.coordinator.announce(scope, actor, key(label), announce_request(digest, size), now)
        identities = CheckpointIdentities("1" * 64, "2" * 64, digest)
        self.endorsements.bind(announced.candidate_id, identities, PARENT, now)
        return announced.candidate_id

    def endorse(self, candidate_id, data, now=None, lifetime=120):
        """Record one endorsement row for the candidate's current challenge, as Step 4 would after verifying it."""
        now = now or self.clock_now
        identities = CheckpointIdentities("1" * 64, "2" * 64, declared(data)[0])
        challenge = self.endorsements.bind(candidate_id, identities, PARENT, now)
        envelope = b'{"synthetic-endorsement":"' + secrets.token_hex(16).encode() + b'"}'
        connection = self.database.connect()
        try:
            connection.execute(
                "INSERT INTO upload_endorsements (candidate_id, sequence, envelope, envelope_sha256, policy_sha256, "
                "enrollment_sha256, grant_sha256, key_fingerprint, trust_count, trust_tail_sha256, issued_at, "
                "expires_at, verified_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1, %s, %s, %s, %s)",
                (candidate_id, challenge.sequence, envelope, sha256(envelope), "7" * 64, "8" * 64, "6" * 64,
                 "9" * 64, "4" * 64, now, now + timedelta(seconds=lifetime), now))
        finally:
            connection.close()
        return sha256(envelope)

    def ready(self, data, label="one", actor=ACTOR, lifetime=120):
        """An announced, endorsed candidate and a capability for it."""
        candidate = self.announce(data, label, actor)
        self.endorse(candidate, data, lifetime=lifetime)
        return candidate, self.issuer.issue(actor, candidate, self.clock_now)

    # Requests --------------------------------------------------------------

    @staticmethod
    def headers(capability, length, extra=(), drop=()):
        """The gateway's required headers, less the names in `drop`, then every pair in `extra`."""
        values = [("authorization", "Upload " + capability.value), ("content-length", str(length)),
                  ("content-type", "application/octet-stream")]
        return [(name, value) for name, value in values if name not in drop] + list(extra)

    def put(self, candidate, capability, steps, headers=None, app=None, length=None):
        path = f"/v1/candidates/{candidate}/content"
        if headers is None:
            headers = self.headers(capability, length if length is not None else capability.declared_size)
        return run(exchange(app or self.gateway, "PUT", path, headers, steps))

    def upload(self, candidate, capability, data, **options):
        return self.put(candidate, capability, body_steps(data), **options)

    # Observations ----------------------------------------------------------

    def staged_bytes(self):
        return sum(entry.stat(follow_symlinks=False).st_size for entry in os.scandir(self.root / "staging"))

    def staged(self):
        return sorted(entry.name for entry in os.scandir(self.root / "staging"))

    def stored(self):
        return sorted(entry.name for entry in os.scandir(self.root / "quarantine"))

    def attempts(self, candidate):
        return [(row["attempt_number"], row["state"]) for row in self.query(
            "SELECT attempt_number, state FROM upload_attempts WHERE candidate_id = %s ORDER BY attempt_number",
            (candidate,))]

    def state(self, candidate):
        return self.scalar("SELECT state FROM candidates WHERE candidate_id = %s", (candidate,))

    def streams(self):
        return self.scalar("SELECT streams FROM quota_usage WHERE scope_kind = 'global'")

    def assert_refused(self, response, status, code):
        self.assertEqual((response.status, response.body["code"]), (status, code), response.text)
        retry = {429: 60, 503: 30}.get(status)
        self.assertEqual(set(response.body), {"request_id", "code"} | ({"retry_after_seconds"} if retry else set()))
        self.assertEqual((response.header("retry-after"), response.body.get("retry_after_seconds")),
                         (None if retry is None else str(retry), retry))
        self.assertEqual(response.header("cache-control"), "no-store")

    def assert_nothing_held(self, candidate):
        """No staged file, no stream reservation and no sealed attempt remain for a refused stream."""
        self.assertEqual(self.staged(), [])
        self.assertEqual(self.staging.usage()["reserved_bytes"], 0)
        self.assertEqual(self.streams(), 0)
        self.assertNotIn("sealed", [state for _number, state in self.attempts(candidate)])
        self.assert_quota_consistent()


class FaultyQuarantine(DirectoryQuarantine):
    """The local store with one injected fault at a time.

    `short-write` drops the last bytes yet reports success, `truncate` cuts a
    completed object, `substitute` swaps its bytes for others of the same
    length, `full` fails a write with ENOSPC, `late` hides an object for its
    first `late_reads` reads and `delete-fails` refuses every delete.
    """

    def __init__(self, directory, fault=None, late_reads=0):
        super().__init__(directory)
        self.root = Path(directory)
        self.fault = fault
        self.late_reads = late_reads
        self.reads = 0

    def _path(self, key):
        return self.root / _file_name(key)

    def put_new(self, key, source_fd, size):
        if self.fault == "full":
            raise QuarantineError("quarantine_full")
        if self.fault == "short-write":
            size -= 1
        super().put_new(key, source_fd, size)
        path = self._path(key)
        if self.fault in ("truncate", "substitute"):
            data = bytearray(path.read_bytes())
            path.chmod(0o600)
            if self.fault == "truncate":
                data = data[: len(data) // 2]
            else:
                data[0] ^= 0xFF
            path.write_bytes(bytes(data))

    def read(self, key, chunk_bytes=1_048_576):
        self.reads += 1
        if self.reads <= self.late_reads:
            raise QuarantineError("quarantine_missing")
        return super().read(key, chunk_bytes)

    def delete(self, key):
        if self.fault == "delete-fails":
            raise QuarantineError("quarantine_unavailable")
        return super().delete(key)
