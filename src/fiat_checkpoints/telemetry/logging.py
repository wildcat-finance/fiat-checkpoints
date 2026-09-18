"""Emit the small event field set; never format request or exception bodies."""

import json
import logging


class EventFormatter(logging.Formatter):
    def format(self, record):
        event = {key: getattr(record, key) for key in (
            "event", "request_id", "route", "status", "codes", "duration_us"
        ) if hasattr(record, key)}
        return json.dumps(event, sort_keys=True, separators=(",", ":"))


def configure_logging():
    logger = logging.getLogger("fiat_checkpoints")
    handler = logging.StreamHandler()
    handler.setFormatter(EventFormatter())
    logger.handlers[:] = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
