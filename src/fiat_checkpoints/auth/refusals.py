"""Fixed public refusal codes of specification section 16, with their HTTP status.

A refusal carries one public code and one fixed private reason for events. A
`protocol_code` is present only when the pinned library emitted it. None of
them ever holds a supplied value, a token, a key or a library message.
"""

import re

from fiat_checkpoints.domain.coordination import RETRY_CAP_SECONDS, CoordinationRefusal
from fiat_checkpoints.records.refusals import PROTOCOL


PUBLIC_STATUS = {
    "auth_required": 401,
    "not_found": 404,
    "request_invalid": 400,
    "protocol_unsupported": 422,
    "identity_mismatch": 422,
    "endorsement_invalid": 422,
    "signer_not_enrolled": 422,
    "protocol_refused": 422,
    "quota_exceeded": 429,
    "idempotency_conflict": 409,
    "upload_in_progress": 409,
    "candidate_expired": 410,
    "checkpoint_ineligible": 409,
    "policy_unavailable": 503,
    "validation_failed": 503,
    "authority_unavailable": 503,
    "capability_not_enabled": 501,
}
# Sections 13 and 16 ask a client to retry a quota or dependency refusal only
# after a bounded wait. The values are this service's choice, never above
# Step 3's retry cap; see adr/bind-uploads-to-enrolled-keys.
RETRY_AFTER_SECONDS = {429: 60, 503: 30}
if not all(0 < seconds <= RETRY_CAP_SECONDS for seconds in RETRY_AFTER_SECONDS.values()):
    raise ValueError("retry-after-bound")
# Only these name evidence the caller supplied and can correct, so only these
# may carry the library's own code back to the caller.
PROTOCOL_CODE_PUBLIC = frozenset({"identity_mismatch", "endorsement_invalid", "signer_not_enrolled",
                                  "protocol_refused"})
REASON = re.compile(r"[a-z][a-z0-9-]{0,63}")
PROTOCOL_CODE = re.compile(r"[a-z][a-z0-9-]{0,63}")


class AuthRefusal(CoordinationRefusal):
    """One public code, one fixed reason and, from the library only, its code."""

    def __init__(self, code, reason=None, *, protocol_code=None):
        if code not in PUBLIC_STATUS:
            raise ValueError("refusal-code")
        reason = code.replace("_", "-") if reason is None else reason
        if REASON.fullmatch(reason) is None:
            raise ValueError("refusal-reason")
        if protocol_code is not None and (type(protocol_code) is not str
                                          or PROTOCOL_CODE.fullmatch(protocol_code) is None):
            raise ValueError("refusal-protocol-code")
        super().__init__(code)
        self.reason = reason
        self.protocol_code = protocol_code

    @property
    def status(self):
        return PUBLIC_STATUS[self.code]

    @property
    def retry_after_seconds(self):
        """The bounded wait before a retry, for quota and dependency refusals only."""
        return RETRY_AFTER_SECONDS.get(self.status)


def from_record(code, error, reason):
    """Map a `RecordRefusal`; its protocol code survives only if the library produced it."""
    protocol_code = error.protocol_code if error.producer == PROTOCOL else None
    return AuthRefusal(code, reason, protocol_code=protocol_code)


# Step 3's persistence codes as the caller sees them. A database outage keeps
# the caller's work and asks for a retry of the same operation; anything the
# service did not expect is a storage or authority failure for an operator.
INTERNAL = {
    "request_invalid": "request_invalid",
    "not_found": "not_found",
    "quota_exceeded": "quota_exceeded",
    "attempt_limit": "quota_exceeded",
    "idempotency_conflict": "idempotency_conflict",
    "state_conflict": "idempotency_conflict",
    "lease_stale": "idempotency_conflict",
    "upload_in_progress": "upload_in_progress",
    "candidate_expired": "candidate_expired",
    "identity_mismatch": "identity_mismatch",
    "database_unavailable": "policy_unavailable",
    "persistence_contention": "policy_unavailable",
}


def public(error):
    """Return an `AuthRefusal` for any refusal type this service raises."""
    if isinstance(error, AuthRefusal):
        return error
    if isinstance(error, CoordinationRefusal):
        code = INTERNAL.get(error.code, "authority_unavailable")
        reason = error.code.replace("_", "-") if REASON.fullmatch(error.code.replace("_", "-")) else None
        return AuthRefusal(code, reason)
    return AuthRefusal("authority_unavailable", "unexpected-failure")
