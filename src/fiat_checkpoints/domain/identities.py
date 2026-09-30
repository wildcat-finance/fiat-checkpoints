"""The three checkpoint identities, kept under their own names.

The service calls the carrier digest `archive_sha256`; the protocol calls the
same value `outer_sha256`. Neither is ever substituted for `snapshot_id` or
`controller_manifest_sha256`, and none is recomputed here: the pinned native
commands and the released records produce them.
"""

from dataclasses import dataclass
import re


SHA256 = re.compile(r"[0-9a-f]{64}")
PROTOCOL_ROLES = ("snapshot_id", "controller_manifest_sha256", "outer_sha256")


class IdentityMismatch(Exception):
    """A fixed code; neither digest value appears in it."""

    def __init__(self, code="identity_mismatch"):
        self.code = code
        super().__init__(code)


def sha256_value(value):
    if type(value) is not str or SHA256.fullmatch(value) is None:
        raise IdentityMismatch("identity_malformed")
    return value


@dataclass(frozen=True)
class CheckpointIdentities:
    snapshot_id: str
    controller_manifest_sha256: str
    archive_sha256: str

    def __post_init__(self):
        for value in (self.snapshot_id, self.controller_manifest_sha256, self.archive_sha256):
            sha256_value(value)

    @classmethod
    def from_protocol(cls, value):
        """Read a record's closed `identities` object by role, never by position."""
        if type(value) is not dict or set(value) != set(PROTOCOL_ROLES):
            raise IdentityMismatch("identity_malformed")
        return cls(value["snapshot_id"], value["controller_manifest_sha256"], value["outer_sha256"])

    def protocol(self):
        return {"snapshot_id": self.snapshot_id,
                "controller_manifest_sha256": self.controller_manifest_sha256,
                "outer_sha256": self.archive_sha256}

    def require(self, other):
        """Refuse unless every role carries the same value; a swapped role is a mismatch."""
        if not isinstance(other, CheckpointIdentities) or other != self:
            raise IdentityMismatch()
        return self
