"""Scopes, quota ceilings, leases and retry timing for coordinated intake work.

These types carry values the persistence layer stores and compares. None of
them establishes authorization, accepted status or the truth of the evidence a
transition names; the owning step checks that before it calls persistence.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import re
import uuid

from fiat_checkpoints.domain.identities import SHA256


GIB = 1_073_741_824
SERVICE_ID = re.compile(r"[a-z][a-z0-9-]{0,63}")
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
# Specification section 11: a 16 to 128 character opaque ASCII token.
IDEMPOTENCY_KEY = re.compile(r"[!-~]{16,128}")
CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
MAX_BIGINT = 2**63 - 1
MAX_REQUEST_BYTES = 65_536
MAX_EVIDENCE_BYTES = 65_536

# Section 9 of the specification; configuration may lower these, never raise them.
CANDIDATE_LIFETIME = timedelta(hours=24)
IDEMPOTENCY_RETENTION = CANDIDATE_LIFETIME + timedelta(days=7)
RETRY_CAP_SECONDS = 300


class CoordinationRefusal(Exception):
    """One fixed code. No supplied value, digest or identifier is carried."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require_now(now):
    if type(now) is not datetime or now.utcoffset() != timedelta(0):
        raise CoordinationRefusal("request_invalid")
    return now.astimezone(timezone.utc)


def positive_int(value, high=MAX_BIGINT):
    if type(value) is not int or not 1 <= value <= high:
        raise CoordinationRefusal("request_invalid")
    return value


def digest(value):
    if type(value) is not str or SHA256.fullmatch(value) is None:
        raise CoordinationRefusal("request_invalid")
    return value


def fixed_code(value):
    if type(value) is not str or CODE.fullmatch(value) is None:
        raise CoordinationRefusal("request_invalid")
    return value


def candidate_uuid(value):
    """Parse a caller-supplied candidate id; anything else is simply not found."""
    if isinstance(value, uuid.UUID):
        return value
    if type(value) is not str or len(value) != 36:
        raise CoordinationRefusal("not_found")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise CoordinationRefusal("not_found") from None
    if str(parsed) != value:
        raise CoordinationRefusal("not_found")
    return parsed


@dataclass(frozen=True)
class RunScope:
    """The authorized run a request acts in; Step 4 establishes the grant."""

    service_id: str
    repository_id: int
    run_id: str

    def __post_init__(self):
        if type(self.service_id) is not str or SERVICE_ID.fullmatch(self.service_id) is None:
            raise CoordinationRefusal("request_invalid")
        positive_int(self.repository_id)
        if type(self.run_id) is not str or RUN_ID.fullmatch(self.run_id) is None:
            raise CoordinationRefusal("request_invalid")

    def canonical(self):
        return {"service_id": self.service_id, "repository_id": self.repository_id, "run_id": self.run_id}


def _canonical_value(value, depth=0):
    """Accept only JSON strings, integers, booleans, null, lists and string-keyed objects."""
    if depth > 16:
        raise CoordinationRefusal("request_invalid")
    if value is None or type(value) in (str, bool):
        return value
    if type(value) is int:
        if not -MAX_BIGINT - 1 <= value <= MAX_BIGINT:
            raise CoordinationRefusal("request_invalid")
        return value
    if type(value) is list:
        return [_canonical_value(item, depth + 1) for item in value]
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: _canonical_value(item, depth + 1) for key, item in value.items()}
    raise CoordinationRefusal("request_invalid")


def canonical_bytes(value):
    raw = json.dumps(_canonical_value(value), sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(raw) > MAX_REQUEST_BYTES:
        raise CoordinationRefusal("request_invalid")
    return raw


@dataclass(frozen=True)
class AnnounceRequest:
    """The canonical announce body: exact size, carrier digest and every other field.

    `fields` holds the remaining canonical body fields (parents and the like);
    all of them enter the idempotency fingerprint.
    """

    archive_sha256: str
    declared_size: int
    fields: dict

    def __post_init__(self):
        digest(self.archive_sha256)
        positive_int(self.declared_size, GIB)
        if type(self.fields) is not dict or {"archive_sha256", "declared_size"} & set(self.fields):
            raise CoordinationRefusal("request_invalid")
        canonical_bytes(self.fields)

    def body(self):
        return {"archive_sha256": self.archive_sha256, "declared_size": self.declared_size,
                **self.fields}


def idempotency_key(value):
    if type(value) is not str or IDEMPOTENCY_KEY.fullmatch(value) is None:
        raise CoordinationRefusal("request_invalid")
    return value


@dataclass(frozen=True)
class QuotaPolicy:
    """Outstanding-work ceilings; each defaults to the specification's initial value."""

    candidates_per_actor: int = 5
    candidates_per_run: int = 20
    candidates_global: int = 100
    bytes_per_actor: int = 5 * GIB
    bytes_per_run: int = 20 * GIB
    bytes_global: int = 100 * GIB
    streams_per_actor: int = 2
    streams_global: int = 8

    def __post_init__(self):
        ceiling = QuotaPolicy.__dataclass_fields__
        for name, field in ceiling.items():
            positive_int(getattr(self, name), field.default)


@dataclass(frozen=True)
class LeasePolicy:
    """How long a lease lives. The 15-minute start and 30-minute stream limits are ceilings."""

    upload_seconds: int = 1800
    validation_seconds: int = 900
    job_seconds: int = 300
    tool_retry_limit: int = 5

    def __post_init__(self):
        positive_int(self.upload_seconds, 1800)
        positive_int(self.validation_seconds, 900)
        positive_int(self.job_seconds, 900)
        positive_int(self.tool_retry_limit, 32)


@dataclass(frozen=True)
class Lease:
    """A fenced claim. Only the holder of the current fence may advance its candidate."""

    candidate_id: uuid.UUID
    kind: str
    attempt_number: int
    fence: int
    expires_at: datetime
    job_id: int | None = None


# Dependency outages keep the candidate and its phase until expiry or an operator
# acts; a sandbox or tool failure retries a bounded number of times, then holds.
DEPENDENCY_REASONS = frozenset({"replica_unavailable", "signer_unavailable", "policy_unavailable",
                                "sandbox_unavailable", "storage_unavailable"})
TOOL_REASONS = frozenset({"validation_failed"})


def retry_delay_ms(attempts, random_fraction):
    """Exponential backoff with equal jitter, capped at five minutes.

    `attempts` counts failures so far (1 for the first retry). `random_fraction`
    is in [0, 1). The upper half of each window is jittered, so a burst of
    retries spreads out while no retry waits past the cap.
    """
    positive_int(attempts)
    if type(random_fraction) is not float or not 0.0 <= random_fraction < 1.0:
        raise CoordinationRefusal("request_invalid")
    window_ms = min(RETRY_CAP_SECONDS, 2 ** min(attempts - 1, 16)) * 1000
    return window_ms // 2 + int((window_ms - window_ms // 2) * random_fraction)
