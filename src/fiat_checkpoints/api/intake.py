"""Contributor login, sessions, announce, endorsement and proof of possession over HTTP.

Each route reads a bounded body itself, authenticates by exactly one
credential and answers with a fixed code from specification section 16. A
browser session is a `__Host-` cookie that is Secure, HttpOnly and
SameSite=Strict, and every unsafe browser request also carries the CSRF token
derived from it. A CLI access token arrives only as `Authorization: Bearer`.
A provider token, a login name and a pasted personal token are never
credentials here. Nothing a caller sends and no library or database message
appears in a response or an event. See adr/bind-uploads-to-enrolled-keys.
"""

from dataclasses import dataclass
from datetime import datetime
import json
import logging
import re
import time
from typing import Callable
from urllib.parse import parse_qsl
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from fiat_checkpoints.api.app import StartupRefusal, production_refusals
from fiat_checkpoints.auth.identity import IdentityProvider, authorization_url
from fiat_checkpoints.auth.refusals import PROTOCOL_CODE_PUBLIC, AuthRefusal, public
from fiat_checkpoints.auth.sessions import LOGIN_STATE_LIFETIME, SessionStore
from fiat_checkpoints.auth.tokens import csrf_matches, csrf_token, pkce_challenge, pkce_verifier, well_formed
from fiat_checkpoints.config import Settings
from fiat_checkpoints.domain.coordination import require_now
from fiat_checkpoints.grants.intake import Intake
from fiat_checkpoints.grants.projection import Projections
from fiat_checkpoints.records.trees import DEFAULT_TREES, REPOSITORY


LOGGER = logging.getLogger("fiat_checkpoints")
SESSION_COOKIE = "__Host-fiat-session"
LOGIN_COOKIE = "__Host-fiat-login"
MAX_BODY_BYTES = 65_536
MAX_HEADER_BYTES = 4096
MAX_QUERY_BYTES = 1024
CONTENT_LENGTH = re.compile(r"[0-9]{1,12}")
REPOSITORY_ID = re.compile(r"[1-9][0-9]{0,18}")


@dataclass(frozen=True)
class IntakeServices:
    """Everything the routes call; the clock is the one time source for every decision."""
    sessions: SessionStore
    provider: IdentityProvider
    projections: Projections
    intake: Intake
    clock: Callable[[], datetime]


def _refuse(code, reason):
    raise AuthRefusal(code, reason)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _no_number(_value):
    raise ValueError("non-integer number")


def json_body(raw):
    """One bounded JSON object: UTF-8, no duplicate keys, no floats or constants."""
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_float=_no_number,
                           parse_constant=_no_number)
    except (UnicodeError, ValueError, RecursionError):
        raise AuthRefusal("request_invalid", "body-malformed") from None
    if type(value) is not dict:
        raise AuthRefusal("request_invalid", "body-malformed")
    return value


async def read_body(request, limit=MAX_BODY_BYTES):
    """Read at most `limit` bytes; ambiguous framing or a declared or actual excess refuses."""
    headers = request.headers
    lengths = headers.getlist("content-length")
    if (len(lengths) > 1 or (lengths and headers.getlist("transfer-encoding"))
            or headers.getlist("content-encoding")):
        raise AuthRefusal("request_invalid", "body-framing")
    declared = None
    if lengths:
        if CONTENT_LENGTH.fullmatch(lengths[0]) is None:
            raise AuthRefusal("request_invalid", "body-framing")
        declared = int(lengths[0])
        if declared > limit:
            raise AuthRefusal("request_invalid", "body-too-large")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise AuthRefusal("request_invalid", "body-too-large")
        chunks.append(chunk)
    if declared is not None and size != declared:
        raise AuthRefusal("request_invalid", "body-framing")
    return b"".join(chunks)


def cookie_values(request, name):
    """Every value the Cookie headers give `name`; a repeated cookie is ambiguous."""
    joined = "; ".join(request.headers.getlist("cookie"))
    if len(joined) > MAX_HEADER_BYTES:
        raise AuthRefusal("auth_required", "cookie-bounds")
    values = []
    for part in joined.split(";"):
        key, separator, value = part.strip().partition("=")
        if separator and key == name:
            values.append(value)
    return values


def _instant(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _cookie(response, name, value, seconds, same_site):
    response.set_cookie(name, value, max_age=max(0, int(seconds)), path="/", secure=True, httponly=True,
                        samesite=same_site)


def create_intake_app(settings, services, root=REPOSITORY, trees=DEFAULT_TREES):
    """Return the contributor intake app, or refuse with the fixed startup codes.

    Production refuses exactly as the health app does. A local app must name
    the same service and environment as its configuration and serve test-scope
    runs only.
    """
    if not isinstance(settings, Settings):
        raise StartupRefusal(("configuration-fields",))
    refusals = production_refusals(settings, root, trees)
    if refusals:
        raise StartupRefusal(refusals)
    if not isinstance(services, IntakeServices):
        raise StartupRefusal(("scaffold-only",))
    if (services.sessions.audience, services.sessions.environment) != (settings.service_id, settings.environment_id):
        raise StartupRefusal(("configuration-value",))
    if services.projections.environment != "test":
        raise StartupRefusal(("configuration-local-identity",))

    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None, redirect_slashes=False)

    def refusal_response(request, error):
        refusal = public(error)
        request.state.code, request.state.reason = refusal.code, refusal.reason
        request.state.protocol_code = refusal.protocol_code
        body = {"request_id": request.state.request_id, "code": refusal.code}
        if refusal.protocol_code is not None and refusal.code in PROTOCOL_CODE_PUBLIC:
            body["protocol_code"] = refusal.protocol_code
        return JSONResponse(status_code=refusal.status, content=body)

    @app.middleware("http")
    async def correlate(request: Request, call_next):
        request.state.request_id = uuid.uuid4().hex
        started = time.monotonic_ns()
        try:
            response = await call_next(request)
        except Exception:
            response = refusal_response(request, None)
        fields = {"event": "intake-request", "request_id": request.state.request_id,
                  "route": getattr(request.state, "route", "other"), "status": response.status_code,
                  "duration_us": max(0, (time.monotonic_ns() - started) // 1000)}
        for name in ("code", "reason", "protocol_code"):
            value = getattr(request.state, name, None)
            if value is not None:
                fields[name] = value
        LOGGER.log(logging.WARNING if response.status_code >= 400 else logging.INFO, "intake-request",
                   extra=fields)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        # The login callback carries its code and state in the query; no page may forward them.
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(StarletteHTTPException)
    async def routing_refusal(request: Request, exc):
        # An unknown route and an unknown resource read the same.
        return refusal_response(request, AuthRefusal(
            "not_found" if exc.status_code in (404, 405) else "request_invalid", "route-unknown"))

    @app.exception_handler(RequestValidationError)
    async def validation_refusal(request: Request, _exc):
        return refusal_response(request, AuthRefusal("request_invalid", "route-parameters"))

    def route(method, path):
        """Register one guarded route; every exception it raises becomes a fixed refusal."""
        def register(handler):
            async def endpoint(request: Request):
                request.state.route = path
                try:
                    now = require_now(services.clock())
                    return await handler(request, now)
                except Exception as error:
                    return refusal_response(request, error)

            app.add_api_route(path, endpoint, methods=[method])
            return handler
        return register

    async def authenticate(request, now, *, unsafe):
        """The one credential this request carries; ambiguity and a CSRF miss refuse."""
        authorization = request.headers.getlist("authorization")
        sessions = cookie_values(request, SESSION_COOKIE)
        if len(authorization) > 1 or len(sessions) > 1 or (authorization and sessions):
            _refuse("auth_required", "credential-ambiguous")
        if authorization:
            scheme, separator, token = authorization[0].partition(" ")
            if scheme != "Bearer" or not separator:
                _refuse("auth_required", "credential-scheme")
            return await run_in_threadpool(services.sessions.token, token, now), None
        if not sessions:
            _refuse("auth_required", "credential-missing")
        secret = sessions[0]
        if not well_formed(secret):
            _refuse("auth_required", "session-malformed")
        if unsafe:
            presented = request.headers.getlist("x-csrf-token")
            if len(presented) != 1 or not csrf_matches(secret, presented[0]):
                _refuse("auth_required", "csrf-refused")
        return await run_in_threadpool(services.sessions.session, secret, now), secret

    async def empty_body(request):
        if await read_body(request):
            _refuse("request_invalid", "body-unexpected")

    def reply(request, status, body):
        return JSONResponse(status_code=status, content={"request_id": request.state.request_id, **body})

    @route("POST", "/v1/login")
    async def begin_login(request, now):
        await empty_body(request)
        start = await run_in_threadpool(services.sessions.begin_login, now)
        url = await run_in_threadpool(authorization_url, services.provider, start.state,
                                      pkce_challenge(pkce_verifier(start.state, start.binding)))
        response = reply(request, 200, {"authorization_url": url, "expires_at": _instant(start.expires_at)})
        _cookie(response, LOGIN_COOKIE, start.binding, LOGIN_STATE_LIFETIME.total_seconds(), "lax")
        return response

    @route("GET", "/v1/login/callback")
    async def complete_login(request, now):
        query = request.scope.get("query_string", b"")
        if len(query) > MAX_QUERY_BYTES:
            _refuse("request_invalid", "callback-query")
        try:
            pairs = parse_qsl(query.decode("ascii"), keep_blank_values=True, strict_parsing=True, max_num_fields=2)
        except (UnicodeError, ValueError):
            raise AuthRefusal("request_invalid", "callback-query") from None
        if sorted(key for key, _ in pairs) != ["code", "state"]:
            _refuse("request_invalid", "callback-query")
        parameters = dict(pairs)
        bindings = cookie_values(request, LOGIN_COOKIE)
        if len(bindings) != 1:
            _refuse("auth_required", "login-binding-missing")
        opened = await run_in_threadpool(services.sessions.complete_login, parameters["state"], bindings[0],
                                         parameters["code"], services.provider, now)
        response = reply(request, 200, {"csrf_token": opened.csrf_token,
                                        "expires_at": _instant(opened.actor.session_expires_at)})
        _cookie(response, SESSION_COOKIE, opened.secret, (opened.actor.session_expires_at - now).total_seconds(),
                "strict")
        _cookie(response, LOGIN_COOKIE, "", 0, "lax")
        return response

    @route("GET", "/v1/session")
    async def current_session(request, now):
        actor, secret = await authenticate(request, now, unsafe=False)
        if secret is None:
            _refuse("auth_required", "session-required")
        return reply(request, 200, {"csrf_token": csrf_token(secret),
                                    "expires_at": _instant(actor.session_expires_at)})

    @route("POST", "/v1/logout")
    async def logout(request, now):
        actor, _secret = await authenticate(request, now, unsafe=True)
        await empty_body(request)
        await run_in_threadpool(services.sessions.logout, actor, now)
        response = reply(request, 200, {"state": "revoked"})
        _cookie(response, SESSION_COOKIE, "", 0, "strict")
        return response

    @route("POST", "/v1/access-tokens")
    async def access_token(request, now):
        actor, _secret = await authenticate(request, now, unsafe=True)
        await empty_body(request)
        if not await run_in_threadpool(services.projections.any_grant, actor.actor_id, now):
            _refuse("not_found", "grant-absent")
        issued = await run_in_threadpool(services.sessions.issue_token, actor, now)
        return reply(request, 200, {"access_token": issued.token, "expires_at": _instant(issued.expires_at)})

    @route("POST", "/v1/candidates")
    async def announce(request, now):
        actor, _secret = await authenticate(request, now, unsafe=True)
        keys = request.headers.getlist("idempotency-key")
        if len(keys) != 1:
            _refuse("request_invalid", "idempotency-key")
        body = json_body(await read_body(request))
        made = await run_in_threadpool(services.intake.announce, actor.actor_id, keys[0], body, now)
        run = services.projections.run(body["run"]["repository_id"], body["run"]["run_id"])
        return reply(request, 200 if made.replayed else 201, {
            "candidate_id": str(made.candidate_id), "state": made.state, "expires_at": _instant(made.expires_at),
            "endorsement": {
                "candidate_id": str(made.candidate_id), "nonce": made.nonce,
                "not_before": _instant(made.not_before), "expires_at": _instant(made.expires_at),
                "environment": run.environment, "service": run.scope.service_id,
                "scope": {"repository_id": run.scope.repository_id, "run_id": run.scope.run_id},
                "policy": made.policy, "upload": made.upload}})

    @route("POST", "/v1/candidates/{candidate_id}/endorsement")
    async def endorse(request, now):
        actor, _secret = await authenticate(request, now, unsafe=True)
        envelope = await read_body(request)
        done = await run_in_threadpool(services.intake.endorse, actor.actor_id,
                                       request.path_params["candidate_id"], envelope, now)
        return reply(request, 200, {"candidate_id": str(done.candidate_id),
                                    "endorsement_sha256": done.envelope_sha256,
                                    "expires_at": _instant(done.expires_at), "replayed": done.replayed})

    @route("GET", "/v1/candidates/{candidate_id}")
    async def status(request, now):
        actor, _secret = await authenticate(request, now, unsafe=False)
        seen = await run_in_threadpool(services.intake.status, actor.actor_id, request.path_params["candidate_id"],
                                       now)
        return reply(request, 200, {"candidate_id": str(seen.candidate_id), "state": seen.state,
                                    "code": seen.code})

    @route("POST", "/v1/runs/{repository_id}/{run_id}/enrollment-proofs")
    async def enrollment_proof(request, now):
        actor, _secret = await authenticate(request, now, unsafe=True)
        repository = request.path_params["repository_id"]
        if REPOSITORY_ID.fullmatch(repository) is None or int(repository) > 2**63 - 1:
            _refuse("not_found", "run-unknown")
        body = json_body(await read_body(request))
        proved = await run_in_threadpool(services.intake.prove_enrollment, actor.actor_id, int(repository),
                                         request.path_params["run_id"], body, now)
        return reply(request, 202, {"state": "awaiting_operator", "replayed": proved.replayed})

    return app
