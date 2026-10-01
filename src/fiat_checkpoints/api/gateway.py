"""The upload gateway: one fixed route that streams exact bytes into quarantine.

`PUT /v1/candidates/{id}/content` takes an upload capability in
`Authorization: Upload <capability>`, an exact `Content-Length`, the type
`application/octet-stream` and nothing that makes the length ambiguous: no
`Transfer-Encoding`, no `Content-Encoding`, no range and no second length. A
body that is missing, short, long or slow, or whose SHA-256 differs from the
capability's, fails the attempt and gives its stream back.

The gateway counts and hashes every byte itself while it writes them to a
bounded staged file. Only then does it create a fresh quarantine key, read the
object back in full and seal the attempt; a store's own metadata never stands
in for that read. The capability is checked against the candidate's bound
endorsement and the grant that endorsement names before the stream starts and
again before the seal. Every exception becomes a fixed refusal from
specification section 16, and no header, capability or library message
appears in a response or an event. The app is a plain ASGI callable so it
sees every header exactly as sent. See adr/seal-uploads-in-bounded-quarantine.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
import hmac
import json
import logging
import re
import secrets
import time
from typing import Callable
import uuid

from fiat_checkpoints.api.app import StartupRefusal, production_refusals
from fiat_checkpoints.auth.refusals import AuthRefusal, public
from fiat_checkpoints.config import Settings
from fiat_checkpoints.domain.coordination import GIB, CoordinationRefusal, candidate_uuid, require_now
from fiat_checkpoints.grants.endorsement import EndorsementStore
from fiat_checkpoints.grants.projection import reference
from fiat_checkpoints.persistence.transfer import Completed, Transfers, object_key
from fiat_checkpoints.records.trees import DEFAULT_TREES, REPOSITORY
from fiat_checkpoints.storage.quarantine import QuarantineError, QuarantineStore, R2Quarantine, read_back
from fiat_checkpoints.upload.capability import capability_sha256, presented
from fiat_checkpoints.upload.staging import StagingArea, StagingRefusal


LOGGER = logging.getLogger("fiat_checkpoints")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())
ROUTE = re.compile(r"/v1/candidates/([^/]{1,64})/content")
ROUTE_TEMPLATE = "/v1/candidates/{candidate_id}/content"
CONTENT_LENGTH = re.compile(r"[0-9]{1,19}")
MAX_HEADERS = 64
MAX_HEADER_BYTES = 8192
# Section 9: a 60-second idle limit and a 30-minute absolute stream limit.
IDLE_SECONDS = 60
STREAM_SECONDS = 1800


@dataclass(frozen=True)
class GatewayLimits:
    """Transfer bounds; each may be lowered for a deployment, never raised."""
    carrier_max_bytes: int = GIB
    idle_seconds: float = IDLE_SECONDS
    stream_seconds: float = STREAM_SECONDS

    def __post_init__(self):
        if (type(self.carrier_max_bytes) is not int or not 1 <= self.carrier_max_bytes <= GIB
                or type(self.idle_seconds) not in (int, float) or not 0 < self.idle_seconds <= IDLE_SECONDS
                or type(self.stream_seconds) not in (int, float) or not 0 < self.stream_seconds <= STREAM_SECONDS):
            raise StartupRefusal(("configuration-value",))


@dataclass(frozen=True)
class EdgeProfile:
    """How requests reach the gateway: `direct` TLS, or a `proxy` with its tested body limit.

    A proxy must pass every allowed body through as it arrives. One that
    buffers the whole request, or whose tested limit is below the carrier
    ceiling, would refuse or hold uploads the service admits (specification
    section 5), so the gateway refuses to start behind it.
    """
    kind: str = "direct"
    tested_body_limit_bytes: int | None = None
    streams_requests: bool = True


def edge_refusals(edge, carrier_max_bytes):
    """The proxy-size deployment guard: fixed codes for an edge that cannot carry the ceiling."""
    if not isinstance(edge, EdgeProfile) or edge.kind not in ("direct", "proxy"):
        return ("configuration-value",)
    if edge.kind == "direct":
        return () if edge.tested_body_limit_bytes is None else ("configuration-value",)
    codes = []
    limit = edge.tested_body_limit_bytes
    if type(limit) is not int or limit < carrier_max_bytes:
        codes.append("proxy-body-limit")
    if edge.streams_requests is not True:
        codes.append("proxy-buffering")
    return tuple(codes)


@dataclass(frozen=True)
class GatewayServices:
    """What the gateway role holds: coordination, trust reads, one staging area and one quarantine store."""
    transfers: Transfers
    endorsements: EndorsementStore
    projections: object
    staging: StagingArea
    quarantine: QuarantineStore
    clock: Callable[[], datetime]
    limits: GatewayLimits = GatewayLimits()
    edge: EdgeProfile = EdgeProfile()


def create_gateway_app(settings, services, root=REPOSITORY, trees=DEFAULT_TREES):
    """Return the gateway app, or refuse with fixed startup codes.

    Production refuses exactly as the health and intake apps do. A local
    gateway serves test-scope runs only, with a real store rather than the
    refusing live adapter, and behind an edge that passes the ceiling.
    """
    if not isinstance(settings, Settings):
        raise StartupRefusal(("configuration-fields",))
    refusals = production_refusals(settings, root, trees)
    if refusals:
        raise StartupRefusal(refusals)
    if (not isinstance(services, GatewayServices) or not isinstance(services.transfers, Transfers)
            or not isinstance(services.endorsements, EndorsementStore)
            or not isinstance(services.staging, StagingArea)
            or not isinstance(services.quarantine, QuarantineStore) or isinstance(services.quarantine, R2Quarantine)
            or not isinstance(services.limits, GatewayLimits)):
        raise StartupRefusal(("scaffold-only",))
    if getattr(services.projections, "environment", None) != "test":
        raise StartupRefusal(("configuration-local-identity",))
    if services.limits.carrier_max_bytes > settings.carrier_max_bytes:
        raise StartupRefusal(("configuration-value",))
    guarded = edge_refusals(services.edge, services.limits.carrier_max_bytes)
    if guarded:
        raise StartupRefusal(guarded)
    return UploadGateway(settings, services)


def _headers(scope):
    """Header values by lower-case name, every repetition kept."""
    raw = scope.get("headers") or []
    if len(raw) > MAX_HEADERS or sum(len(name) + len(value) for name, value in raw) > MAX_HEADER_BYTES:
        raise AuthRefusal("request_invalid", "headers-bounds")
    found = {}
    for name, value in raw:
        found.setdefault(bytes(name).decode("latin-1").lower(), []).append(bytes(value).decode("latin-1"))
    return found


def _unavailable(reason):
    return AuthRefusal("storage_unavailable", reason)


def _staging(refusal):
    """The public refusal for a staging failure once the stream has started."""
    if refusal.code == "body_extra":
        return AuthRefusal("upload_integrity", "body-extra")
    return _unavailable({"staging_full": "staging-full", "staging_mismatch": "staging-mismatch"}.get(
        refusal.code, "staging-unavailable"))


async def _staged(function, *arguments):
    try:
        return await asyncio.to_thread(function, *arguments)
    except StagingRefusal as refusal:
        raise _staging(refusal) from None


class UploadGateway:
    """The gateway ASGI app. Blocking database, disk and store work runs in worker threads."""

    def __init__(self, settings, services):
        self.services = services
        self.environment = settings.environment_id
        self.carrier_max_bytes = min(settings.carrier_max_bytes, services.limits.carrier_max_bytes)

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope.get("type") != "http":
            return
        request_id = uuid.uuid4().hex
        started = time.monotonic_ns()
        record = {"route": "other"}
        try:
            status, body = await self._dispatch(scope, receive, record)
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            status, body = self._refusal(error, record)
        await self._send(send, request_id, status, body)
        fields = {"event": "gateway-request", "request_id": request_id, "status": status,
                  "duration_us": max(0, (time.monotonic_ns() - started) // 1000), **record}
        LOGGER.log(logging.WARNING if status >= 400 else logging.INFO, "gateway-request", extra=fields)

    @staticmethod
    async def _lifespan(receive, send):
        while True:
            message = await receive()
            if message.get("type") == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message.get("type") == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    @staticmethod
    def _refusal(error, record):
        refusal = public(error)
        record.update(code=refusal.code, reason=refusal.reason)
        body = {"code": refusal.code}
        if refusal.retry_after_seconds is not None:
            body["retry_after_seconds"] = refusal.retry_after_seconds
        return refusal.status, body

    @staticmethod
    async def _send(send, request_id, status, body):
        payload = json.dumps({"request_id": request_id, **body}, sort_keys=True, separators=(",", ":")).encode()
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode()),
                   (b"cache-control", b"no-store"), (b"x-request-id", request_id.encode()),
                   (b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer")]
        retry = body.get("retry_after_seconds")
        if retry is not None:
            headers.append((b"retry-after", str(retry).encode()))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": payload})

    async def _dispatch(self, scope, receive, record):
        method, path = scope.get("method"), scope.get("path")
        if method == "GET" and path == "/health/live":
            return 200, {"status": "live"}
        if method == "GET" and path == "/health/ready":
            return 503, {"status": "unavailable", "code": "intake-closed"}
        match = ROUTE.fullmatch(path) if type(path) is str else None
        if match is None or method != "PUT":
            raise AuthRefusal("not_found", "route-unknown")
        record["route"] = ROUTE_TEMPLATE
        return await self._upload(scope, receive, match.group(1), record)

    def _framing(self, headers, scope):
        """The exact declared length, or the fixed refusal for ambiguous or unsupported framing."""
        if scope.get("query_string"):
            raise AuthRefusal("request_invalid", "query-unexpected")
        lengths = headers.get("content-length", [])
        if headers.get("transfer-encoding"):
            raise AuthRefusal("request_invalid" if lengths else "length_required",
                              "body-framing" if lengths else "length-unknown")
        if not lengths:
            raise AuthRefusal("length_required", "length-missing")
        if len(lengths) != 1 or CONTENT_LENGTH.fullmatch(lengths[0]) is None:
            raise AuthRefusal("request_invalid", "body-framing")
        if "content-encoding" in headers:
            raise AuthRefusal("request_invalid", "content-encoding")
        if "content-range" in headers or "range" in headers:
            raise AuthRefusal("request_invalid", "range-unsupported")
        types = headers.get("content-type", [])
        if len(types) != 1 or types[0].strip().lower() != "application/octet-stream":
            raise AuthRefusal("request_invalid", "content-type")
        if [value.strip().lower() for value in headers.get("expect", ["100-continue"])] != ["100-continue"]:
            raise AuthRefusal("request_invalid", "expect-unsupported")
        declared = int(lengths[0])
        if declared > self.carrier_max_bytes:
            raise AuthRefusal("upload_too_large", "carrier-limit")
        return declared

    def _now(self):
        return require_now(self.services.clock())

    def _grant_current(self, view, bound, now):
        run = self.services.projections.run_for(view.scope)
        self.services.projections.current(run).named_grant(reference("run-grant", bound.grant_sha256),
                                                           view.actor_id, "upload", now)

    def _bound(self, view, now):
        """The candidate's bound endorsement, which must be the one the capability was issued from."""
        bound = self.services.endorsements.bound(view.actor_id, view.candidate_id, now)
        if (bound.sequence != view.endorsement_sequence
                or not hmac.compare_digest(bound.envelope_sha256, view.endorsement_sha256)):
            raise AuthRefusal("endorsement_invalid", "endorsement-superseded")
        self._grant_current(view, bound, now)
        return bound

    async def _upload(self, scope, receive, path_candidate, record):
        headers = _headers(scope)
        value = presented(headers.get("authorization", []))
        if value is None:
            raise AuthRefusal("auth_required", "capability-missing")
        declared = self._framing(headers, scope)
        try:
            path_id = candidate_uuid(path_candidate)
        except CoordinationRefusal:
            raise AuthRefusal("not_found", "candidate-unknown") from None
        hashed = capability_sha256(value)
        transfers = self.services.transfers
        view = await asyncio.to_thread(transfers.capability, hashed)
        if view is None or view.environment != self.environment:
            raise AuthRefusal("auth_required", "capability-unknown")
        if view.candidate_id != path_id:
            raise AuthRefusal("not_found", "candidate-unknown")
        record.update(candidate=str(view.candidate_id), attempt=view.attempt_number)
        if declared != view.declared_size:
            raise AuthRefusal("upload_integrity", "length-mismatch")
        key = object_key(view.candidate_id, view.attempt_number, secrets.token_hex(16))
        if view.attempt_state == "sealed" or view.stream_started:
            # A sealed attempt replays its result; a started one never takes a
            # second stream. `start` answers both under the candidate lock.
            return self._completed(await asyncio.to_thread(transfers.start, hashed, key, self.environment,
                                                           self._now()), replayed=True)
        now = self._now()
        # A spent or closed capability is expired whatever its endorsement says;
        # `start` decides again under the candidate lock.
        if view.attempt_state != "open" or now >= view.start_expires_at:
            raise AuthRefusal("candidate_expired", "capability-expired")
        bound = await asyncio.to_thread(self._bound, view, now)
        try:
            reservation = self.services.staging.reserve(declared)
        except StagingRefusal as refusal:
            if refusal.code == "staging_full":
                raise AuthRefusal("quota_exceeded", "staging-full") from None
            raise _unavailable("staging-unavailable") from None
        try:
            started = await asyncio.to_thread(transfers.start, hashed, key, self.environment, now)
            if isinstance(started, Completed):
                return self._completed(started, replayed=True)
            return await self._stream(receive, reservation, started, view, bound, record)
        finally:
            await asyncio.to_thread(reservation.close)

    @staticmethod
    def _completed(result, *, replayed):
        if not isinstance(result, Completed):
            raise AuthRefusal("authority_unavailable", "completion-missing")
        return (200 if replayed else 202), {
            "candidate_id": str(result.candidate_id), "state": result.state, "attempt": result.attempt_number,
            "length": result.sealed_size, "sha256": result.sealed_sha256, "replayed": replayed}

    async def _stream(self, receive, reservation, stream, view, bound, record):
        """Receive, check, publish, read back and seal one started stream; fail its attempt otherwise."""
        created = []
        try:
            await _staged(reservation.create)
            await self._receive(receive, reservation, stream, record)
            count, sha256 = await _staged(reservation.finish)
            record["bytes"] = count
            if count != stream.declared_size or not hmac.compare_digest(sha256, stream.archive_sha256):
                raise AuthRefusal("upload_integrity", "digest-mismatch")
            # A revocation during the transfer stops the seal; so does a newer
            # endorsement, which the seal's own transaction checks.
            await asyncio.to_thread(self._grant_current, view, bound, self._now())
            await asyncio.to_thread(self._publish, reservation, stream, created)
            sealed = await asyncio.to_thread(self.services.transfers.seal_stream, stream.lease, count, sha256,
                                             stream.object_key, view.endorsement_sequence,
                                             view.endorsement_sha256, self._now())
            return self._completed(Completed(stream.lease.candidate_id, "quarantined", sealed, count, sha256),
                                   replayed=False)
        except BaseException as error:
            record["bytes"] = reservation.count
            await asyncio.to_thread(self._abandon, stream, error, bool(created))
            raise

    def _publish(self, reservation, stream, created):
        """Create the attempt's fresh quarantine key from the staged bytes and read it back in full."""
        store = self.services.quarantine
        try:
            store.put_new(stream.object_key, reservation.descriptor, stream.declared_size)
            created.append(stream.object_key)
        except QuarantineError as error:
            # An occupied key is read like any other: only its exact bytes pass.
            if error.code != "quarantine_conflict":
                raise _unavailable("quarantine-unavailable") from None
        try:
            count, sha256 = read_back(store, stream.object_key, stream.declared_size)
        except QuarantineError as error:
            raise _unavailable("quarantine-missing" if error.code == "quarantine_missing"
                               else "quarantine-unavailable") from None
        if count != stream.declared_size or sha256 is None or not hmac.compare_digest(sha256, stream.archive_sha256):
            raise AuthRefusal("authority_unavailable", "quarantine-mismatch")

    def _abandon(self, stream, error, created):
        """Fail the attempt; remove what this stream wrote only once its attempt is known unsealed.

        An object that failed its read-back is kept and held as evidence of a
        store that lost, changed or swapped bytes (specification section 12).
        """
        refusal = public(error) if isinstance(error, Exception) else AuthRefusal("upload_integrity", "stream-ended")
        hold = refusal.reason == "quarantine-mismatch"
        try:
            failed = self.services.transfers.fail(stream.lease, refusal.code, self._now(), hold=hold)
        except Exception:
            # The lease expires and the sweeper reclaims the attempt and its object.
            return
        if failed and created and not hold:
            try:
                self.services.quarantine.delete(stream.object_key)
            except Exception:
                pass

    async def _receive(self, receive, reservation, stream, record):
        """Read exactly the declared bytes within the idle and absolute limits and the lease."""
        limits = self.services.limits
        remaining = (stream.lease.expires_at - self._now()).total_seconds()
        deadline = time.monotonic() + min(limits.stream_seconds, max(0.0, remaining))
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise AuthRefusal("upload_integrity", "stream-deadline")
            wait = min(limits.idle_seconds, left)
            try:
                message = await asyncio.wait_for(receive(), timeout=wait)
            except TimeoutError:
                raise AuthRefusal("upload_integrity", "stream-idle" if wait < left else "stream-deadline") from None
            kind = message.get("type")
            if kind == "http.disconnect":
                raise AuthRefusal("upload_integrity", "body-truncated")
            body = message.get("body", b"")
            if kind != "http.request" or type(body) is not bytes:
                raise AuthRefusal("request_invalid", "body-framing")
            if body:
                await _staged(reservation.write, body)
            now = self._now()
            if now >= stream.candidate_expires_at:
                raise AuthRefusal("candidate_expired", "candidate-expired")
            if now >= stream.lease.expires_at:
                raise AuthRefusal("upload_integrity", "stream-deadline")
            if not message.get("more_body", False):
                break
        if reservation.count != stream.declared_size:
            raise AuthRefusal("upload_integrity", "body-truncated")
