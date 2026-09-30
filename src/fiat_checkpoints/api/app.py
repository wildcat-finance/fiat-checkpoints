"""Expose health only; production cannot start in this scaffold."""

import logging
from pathlib import Path
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from fiat_checkpoints.config import Settings
from fiat_checkpoints.records.refusals import RecordRefusal
from fiat_checkpoints.records.trees import DEFAULT_TREES, load_release


LOGGER = logging.getLogger("fiat_checkpoints")


class StartupRefusal(Exception):
    """Contain fixed refusal codes without input bytes or paths."""

    def __init__(self, codes):
        self.codes = tuple(codes)
        super().__init__("intake-closed")


def production_refusals(settings: Settings, root: Path, trees: Path = DEFAULT_TREES):
    """Name every known blocker; a shipped lock must pass the released lock check."""
    if settings.profile == "local":
        return ()
    codes = []
    if settings.trust_profile == "local-test" or settings.environment_id.endswith("-local"):
        codes.append("test-trust-forbidden")
    if settings.protocol_lock is None:
        codes.append("protocol-pin-missing")
    else:
        # The released lock check runs over the read-only trees before anything else.
        try:
            load_release(root, trees)
        except RecordRefusal as error:
            codes.append(error.code)
    # A declared runtime name cannot establish isolation that has not been built.
    codes.extend(("isolation-unavailable", "scaffold-only"))
    return tuple(codes)


def create_app(settings: Settings, root: Path, trees: Path = DEFAULT_TREES):
    """Return the local health app, or refuse every production start."""
    refusals = production_refusals(settings, root, trees)
    if refusals:
        raise StartupRefusal(refusals)
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None,
                  redirect_slashes=False)

    @app.middleware("http")
    async def health_event(request: Request, call_next):
        request_id = uuid.uuid4().hex
        started = time.monotonic_ns()
        response = await call_next(request)
        route = request.url.path if request.url.path in ("/health/live", "/health/ready") else "other"
        LOGGER.info("health-request", extra={"event": "health-request",
                    "request_id": request_id, "route": route,
                    "status": response.status_code,
                    "duration_us": max(0, (time.monotonic_ns() - started) // 1000)})
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health/live")
    async def live():
        return {"status": "live"}

    @app.get("/health/ready")
    async def ready():
        return JSONResponse(status_code=503, content={"status": "unavailable", "code": "intake-closed"})

    return app
