"""Start local health from an explicit non-secret JSON configuration."""

import argparse
import logging
from pathlib import Path
import sys
import uuid

import uvicorn

from fiat_checkpoints import RUNTIME_PYTHON
from fiat_checkpoints.api.app import create_app, StartupRefusal
from fiat_checkpoints.config import ConfigError, load_config
from fiat_checkpoints.telemetry.logging import configure_logging


def main(argv=None):
    parser = argparse.ArgumentParser(description="Start checkpoint scaffold health")
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    configure_logging()
    logger = logging.getLogger("fiat_checkpoints")
    request_id = uuid.uuid4().hex
    try:
        if sys.version_info[:3] != RUNTIME_PYTHON:
            raise ConfigError("python-version-mismatch")
        settings = load_config(args.config)
        app = create_app(settings, Path(__file__).resolve().parents[2])
    except (ConfigError, StartupRefusal) as error:
        codes = error.codes if isinstance(error, StartupRefusal) else (str(error),)
        logger.warning("startup-refused", extra={"event": "startup-refused",
                       "request_id": request_id, "codes": codes})
        return 2
    logger.info("local-health-starting", extra={"event": "local-health-starting",
                "request_id": request_id, "codes": ["intake-closed"]})
    uvicorn.run(app, host=settings.host, port=settings.port, access_log=False,
                server_header=False, proxy_headers=False, log_config=None, log_level="critical",
                limit_concurrency=8, timeout_keep_alive=5, timeout_graceful_shutdown=5)
    return 0
