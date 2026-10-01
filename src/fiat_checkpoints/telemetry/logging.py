"""Emit the small event field set; never format request or exception bodies."""

import json
import logging


# Candidate, attempt and job identifiers are random service ids for private
# correlation. Actor ids, digests, tokens, keys and bodies are never fields;
# `reason` and `protocol_code` hold only fixed vocabulary.
FIELDS = (
    "event", "request_id", "route", "status", "codes", "duration_us",
    "candidate", "attempt", "job", "kind", "fence", "from_state", "to_state",
    "code", "scope", "age_ms", "delay_ms", "count", "reason", "protocol_code", "bytes",
)


class EventFormatter(logging.Formatter):
    def format(self, record):
        event = {key: getattr(record, key) for key in FIELDS if hasattr(record, key)}
        return json.dumps(event, sort_keys=True, separators=(",", ":"))


def configure_logging():
    logger = logging.getLogger("fiat_checkpoints")
    handler = logging.StreamHandler()
    handler.setFormatter(EventFormatter())
    logger.handlers[:] = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
