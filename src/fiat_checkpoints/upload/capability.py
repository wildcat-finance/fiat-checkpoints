"""The opaque upload capability: 32 random bytes, shown once, stored only as a domain-separated SHA-256.

A contributor presents it as `Authorization: Upload <capability>` on the
gateway's fixed content route and nowhere else. It is never logged, never part
of a representation, an exception or a refusal, and a presented value of any
other shape is refused before a lookup. See adr/seal-uploads-in-bounded-quarantine.
"""

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import uuid

from fiat_checkpoints.auth.tokens import new_secret, well_formed


CONTEXT = b"fiat-checkpoints/upload-capability/v1\x00"
SCHEME = "upload"


def new_capability():
    return new_secret()


def capability_sha256(value):
    """The stored form; the context keeps it apart from a session or token hash of the same bytes."""
    return hashlib.sha256(CONTEXT + value.encode("ascii")).hexdigest()


def presented(values):
    """The one well-formed capability an `Authorization` header list carries, or None.

    Two headers, another scheme, a missing value or a value of any other shape
    all give None, so nothing reaches a lookup.
    """
    if len(values) != 1:
        return None
    scheme, separator, value = values[0].partition(" ")
    if not separator or scheme.lower() != SCHEME or not well_formed(value):
        return None
    return value


@dataclass(frozen=True)
class IssuedCapability:
    """A capability returned to its contributor once; the value stays out of every representation."""
    value: str = field(repr=False)
    candidate_id: uuid.UUID
    attempt_number: int
    expires_at: datetime
    declared_size: int
    archive_sha256: str
    renewed: bool
