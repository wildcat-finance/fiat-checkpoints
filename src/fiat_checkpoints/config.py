"""Parse bounded scaffold settings without loading credentials or protocol data."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat


MAX_CONFIG_BYTES = 16_384
FIELDS = {
    "schema_version", "profile", "service_id", "environment_id", "host", "port",
    "trust_profile", "protocol_lock", "sandbox_profile", "request_max_bytes",
    "carrier_max_bytes", "validation_concurrency",
}


class ConfigError(Exception):
    """Carry a fixed code; supplied configuration values stay out of diagnostics."""


@dataclass(frozen=True)
class Settings:
    schema_version: int
    profile: str
    service_id: str
    environment_id: str
    host: str
    port: int
    trust_profile: str
    protocol_lock: str | None
    sandbox_profile: str
    request_max_bytes: int
    carrier_max_bytes: int
    validation_concurrency: int


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("configuration-duplicate-key")
        result[key] = value
    return result


def finite_number(_value):
    raise ConfigError("configuration-malformed")


def parse_config(raw):
    """Return Settings for exact UTF-8 JSON bytes, or raise a fixed ConfigError."""
    if not isinstance(raw, bytes) or len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError("configuration-size")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=finite_number)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ConfigError("configuration-malformed") from exc
    if type(data) is not dict or set(data) != FIELDS:
        raise ConfigError("configuration-fields")
    for key, low, high in (
        ("schema_version", 1, 1), ("port", 1, 65_535),
        ("request_max_bytes", 1, 65_536), ("carrier_max_bytes", 1, 1_073_741_824),
        ("validation_concurrency", 1, 4),
    ):
        if type(data[key]) is not int or not low <= data[key] <= high:
            raise ConfigError("configuration-value")
    for key, allowed in (
        ("profile", {"local", "production"}),
        ("host", {"127.0.0.1", "::1", "0.0.0.0"}),
        ("trust_profile", {"local-test", "production"}),
        ("sandbox_profile", {"unavailable", "gvisor"}),
    ):
        if type(data[key]) is not str or data[key] not in allowed:
            raise ConfigError("configuration-value")
    for key in ("service_id", "environment_id"):
        if type(data[key]) is not str or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", data[key]):
            raise ConfigError("configuration-value")
    if data["protocol_lock"] is not None and data["protocol_lock"] != "protocol.lock.json":
        raise ConfigError("configuration-value")
    if data["profile"] == "local" and (
        data["trust_profile"] != "local-test" or not data["environment_id"].endswith("-local")
    ):
        raise ConfigError("configuration-local-identity")
    return Settings(**data)


def load_config(path):
    """Read one bounded regular file without following its final symlink."""
    descriptor = None
    try:
        descriptor = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_CONFIG_BYTES:
            raise ConfigError("configuration-file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(MAX_CONFIG_BYTES + 1)
            after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise ConfigError("configuration-changed")
    except OSError as exc:
        raise ConfigError("configuration-unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return parse_config(raw)
