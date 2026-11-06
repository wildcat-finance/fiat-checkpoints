"""Fixed validation outcomes: a service code, a fixed reason and maybe a protocol code.

A protocol code passes through only when the pinned producer named it: the
native adapter's own refusal, or a native command whose whole stderr is one
allowlisted class for that stage. Anything else, including an unexpected
exception or malformed output, is `validation_failed` with no diagnostic text.
"""

import re


PROTOCOL_CODE = re.compile(r"[a-z][a-z0-9-]{0,63}")
REASON = re.compile(r"[a-z][a-z0-9-]{0,63}")
SERVICE_CODES = frozenset({
    "validation_failed", "sandbox_unavailable", "policy_unavailable", "storage_unavailable",
    "authority_unavailable", "protocol_refused", "identity_mismatch", "signer_not_enrolled",
    "endorsement_invalid", "checkpoint_ineligible", "capability_not_enabled",
})
# Deterministic refusals end the candidate; the others keep it for a retry.
DETERMINISTIC = frozenset({
    "protocol_refused", "identity_mismatch", "signer_not_enrolled", "endorsement_invalid",
    "checkpoint_ineligible", "capability_not_enabled",
})
RETRY_REASON = {
    "validation_failed": "validation_failed", "sandbox_unavailable": "sandbox_unavailable",
    "policy_unavailable": "policy_unavailable", "storage_unavailable": "storage_unavailable",
    "authority_unavailable": "storage_unavailable",
}
NATIVE_STAGES = ("inspect", "restore", "verify", "identity")
# The runner's reason when the coverage stage's commands failed and the pinned
# inspect saw a signer outside the injected keys: git cannot verify that
# commit, so the failure is the signer, not the tool. No protocol code is set.
COVERAGE_SIGNER_UNAPPROVED = "coverage-signer-unapproved"

# The native adapter's request joins: the archive is not the one announced.
IDENTITY_CODES = frozenset({
    "native-input-length", "native-input-digest", "native-controller-manifest",
    "native-inspect-input", "native-restore-input", "native-identity-input",
})
# Commit-signature coverage against the injected approved history.
SIGNER_CODES = frozenset({
    "native-signer-unapproved", "native-signature-invalid", "native-signature-contradiction",
    "native-enrollment-ambiguous",
})
# Archive content the released adapter refuses deterministically.
ARCHIVE_CODES = frozenset({
    "native-worktree-outside-attempt", "native-observations-unavailable",
    "native-immediate-restore-tail", "native-anchor-unavailable", "native-producer-ledger",
    "native-private-custody-unavailable", "native-metadata-unavailable", "native-producer-shape",
    "native-signature-format-unavailable", "native-restore-join", "native-ref-unavailable",
    "native-producer-version-unavailable", "native-producer-limit", "native-producer-binding",
    "native-object-format-unavailable", "native-nested-restore-unavailable", "native-manifest-encoding",
    "native-inspect-findings", "native-identity-unavailable", "native-identity-join",
    "native-identity-digest", "native-coverage-duplicate", "native-boundary-unavailable",
    "native-history-class-unavailable", "native-step-topology", "native-push-ledger",
    "native-implementation-ledger", "native-audit-ledger", "native-approved-base-mismatch",
    "native-working-commit", "native-step-ref-moved", "native-step-base",
    "native-required-object-unavailable", "native-range-coverage", "native-range-boundary",
    "native-platform-evidence-unavailable", "native-implementation-missing",
    "native-current-boundary-coverage", "native-coverage-limit", "native-coverage-empty",
    "native-audit-coverage", "native-anchor-ledger", "native-archive-limit",
})


class ValidationRefusal(Exception):
    """One fixed outcome. No digest, path, key or diagnostic text is ever a field."""

    def __init__(self, code, reason, *, protocol_code=None, stage=None):
        if code not in SERVICE_CODES or type(reason) is not str or REASON.fullmatch(reason) is None:
            code, reason, protocol_code, stage = "validation_failed", "refusal-malformed", None, None
        if protocol_code is not None and (type(protocol_code) is not str
                                          or PROTOCOL_CODE.fullmatch(protocol_code) is None):
            protocol_code = None
        if stage is not None and (type(stage) is not str or REASON.fullmatch(stage) is None):
            stage = None
        self.code, self.reason, self.protocol_code, self.stage = code, reason, protocol_code, stage
        super().__init__(code)

    @property
    def deterministic(self):
        return self.code in DETERMINISTIC

    def record(self):
        return {"code": self.code, "reason": self.reason, "protocol_code": self.protocol_code,
                "stage": self.stage}

    def __repr__(self):
        return "ValidationRefusal(%s, %s)" % (self.code, self.reason)

    __str__ = __repr__


def stage_codes(capabilities):
    """Map each native stage to the refusal classes the release says it can emit."""
    allowed = {stage: set() for stage in NATIVE_STAGES}
    for row in capabilities["refusals"]:
        for stage in row["stages"]:
            if stage in allowed and PROTOCOL_CODE.fullmatch(row["name"]):
                allowed[stage].add(row["name"])
    return {stage: frozenset(names) for stage, names in allowed.items()}


def classify(code, stage, protocol_code=None):
    """Turn a released native refusal into a fixed service outcome."""
    if type(code) is not str or PROTOCOL_CODE.fullmatch(code) is None:
        return ValidationRefusal("validation_failed", "native-refusal-malformed")
    if code == "native-command-failed":
        if protocol_code is not None and stage in NATIVE_STAGES:
            return ValidationRefusal("protocol_refused", "native-command-refused",
                                     protocol_code=protocol_code, stage=stage)
        return ValidationRefusal("validation_failed", "native-command-unmapped", stage=_stage(stage))
    if code == COVERAGE_SIGNER_UNAPPROVED and stage == "coverage":
        return ValidationRefusal("signer_not_enrolled", COVERAGE_SIGNER_UNAPPROVED, stage="coverage")
    if code in IDENTITY_CODES:
        return ValidationRefusal("identity_mismatch", "native-identity-join", protocol_code=code,
                                 stage=_stage(stage))
    if code in SIGNER_CODES:
        return ValidationRefusal("signer_not_enrolled", "native-signature-coverage", protocol_code=code,
                                 stage=_stage(stage))
    if code in ARCHIVE_CODES:
        return ValidationRefusal("protocol_refused", "native-adapter-refused", protocol_code=code,
                                 stage=_stage(stage))
    return ValidationRefusal("validation_failed", "native-operational", stage=_stage(stage))


def _stage(stage):
    return stage if type(stage) is str and REASON.fullmatch(stage) else None
