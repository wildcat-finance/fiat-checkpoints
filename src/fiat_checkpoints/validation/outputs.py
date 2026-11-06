"""Read a sandbox run as one typed outcome, or refuse it with a fixed code.

The job is untrusted, so its stdout is a claim to check, not a result: one
canonical JSON line naming this job, then either a refusal whose protocol
code the release lists for that stage, or a native result whose request,
pins, stage exits, identity and coverage all match what the supervisor asked
for (`native-local-errors`). A killed, truncated, stale, malformed or
mismatched run is `validation_failed`; a resource kill is not evidence that
the archive is hostile.
"""

from dataclasses import dataclass
import re

from fiat_checkpoints.validation.refusals import NATIVE_STAGES, ValidationRefusal, classify


SCHEMA_RESULT = "fiat-checkpoints-sandbox-result/v1"
RESULT_FIELDS = frozenset({"schema", "job_id", "status", "native_result", "native_result_sha256", "refusal"})
REFUSAL_FIELDS = frozenset({"code", "stage", "protocol_code"})
NATIVE_FIELDS = frozenset({
    "schema", "complete", "request", "source_commit", "executable_sha256", "profile",
    "source_profile_sha256", "tools", "public_trust_sha256", "native_results", "identity",
    "status_sha256", "next", "coverage", "operation_ran", "historical_commands_executed",
    "current_eligibility", "service_acceptance", "resources",
})
STAGE_FIELDS = frozenset({"stage", "attempt_id", "input_sha256", "exit", "output_sha256", "log_sha256",
                          "output_bytes", "log_bytes", "duration_ms"})
VERIFIED_FIELDS = frozenset({"commit", "enrollment", "evidence_class", "fingerprint", "native_current_boundary"})
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
FINGERPRINT = re.compile(r"[0-9A-F]{40}")


@dataclass(frozen=True)
class Expected:
    """What the supervisor asked for; every field comes from trusted state."""
    job_id: str
    request: dict
    tools: tuple
    public_trust_sha256: str | None
    stage_codes: dict


@dataclass(frozen=True)
class NativeEvidence:
    """A bound native result. It proves one current attempt, not acceptance."""
    job_id: str
    payload: bytes
    sha256: str
    record: dict
    signers: tuple

    def __repr__(self):
        return "NativeEvidence(%s)" % self.job_id


@dataclass(frozen=True)
class InspectPassed:
    job_id: str


def _failed(reason):
    return ValidationRefusal("validation_failed", reason)


def _closed(value, names, reason):
    if type(value) is not dict or set(value) != names:
        raise _failed(reason)
    return value


def read(run, expected, library, *, mode="validate"):
    """Return NativeEvidence, InspectPassed, or raise one ValidationRefusal."""
    if run.killed is not None:
        raise _failed("sandbox-" + run.killed)
    if run.exit != 0:
        raise _failed("sandbox-exit")
    Refusal = library.canonical.Refusal
    data = run.stdout
    if type(data) is not bytes or not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise _failed("sandbox-output-malformed")
    try:
        value = library.canonical.decode(data[:-1], require_canonical=True, limit=len(data))
    except Refusal:
        raise _failed("sandbox-output-malformed") from None
    _closed(value, RESULT_FIELDS, "sandbox-output-malformed")
    if value["schema"] != SCHEMA_RESULT:
        raise _failed("sandbox-output-malformed")
    if value["job_id"] != expected.job_id:
        raise _failed("sandbox-output-stale")
    status = value["status"]
    if status == "error":
        raise _failed("sandbox-runner-error")
    if status == "refused":
        if value["native_result"] is not None or value["native_result_sha256"] is not None:
            raise _failed("sandbox-output-malformed")
        refusal = _closed(value["refusal"], REFUSAL_FIELDS, "sandbox-output-malformed")
        code, stage, protocol_code = refusal["code"], refusal["stage"], refusal["protocol_code"]
        if protocol_code is not None and (stage not in NATIVE_STAGES or code != "native-command-failed"
                                          or protocol_code not in expected.stage_codes.get(stage, ())):
            raise _failed("sandbox-protocol-code-unlisted")
        raise classify(code, stage, protocol_code)
    if status != "complete" or value["refusal"] is not None:
        raise _failed("sandbox-output-malformed")
    if mode == "inspect-case":
        if value["native_result"] is not None or value["native_result_sha256"] is not None:
            raise _failed("sandbox-output-malformed")
        return InspectPassed(expected.job_id)
    return _bind(value, expected, library)


def _bind(value, expected, library):
    record = value["native_result"]
    try:
        payload = library.canonical.canonical(record)
    except library.canonical.Refusal:
        raise _failed("native-result-malformed") from None
    sha256 = library.canonical.digest(payload)
    if value["native_result_sha256"] != sha256:
        raise _failed("native-result-digest")
    _closed(record, NATIVE_FIELDS, "native-result-malformed")
    native, records = library.native, library.native_records
    request = expected.request
    if (record["schema"] != "checkpoint-authority-native-result/v1" or record["complete"] is not True
            or record["operation_ran"] is not True or record["historical_commands_executed"] is not False
            or record["current_eligibility"] != "unknown" or record["service_acceptance"] != "unavailable"):
        raise _failed("native-result-malformed")
    if record["request"] != request:
        raise _failed("native-result-stale")
    if (record["source_commit"] != records.NATIVE_COMMIT or record["executable_sha256"] != records.CONTROLLER_SHA256
            or record["profile"] != records.PROFILE or record["source_profile_sha256"] != native.LAYOUT_SHA256
            or record["tools"] != [{"name": item.name, "sha256": item.sha256} for item in expected.tools]):
        raise _failed("native-result-pins")
    if expected.public_trust_sha256 is not None and record["public_trust_sha256"] != expected.public_trust_sha256:
        raise _failed("native-result-trust")
    stages = record["native_results"]
    if type(stages) is not list or len(stages) != len(NATIVE_STAGES):
        raise _failed("native-result-stages")
    for stage, row in zip(NATIVE_STAGES, stages):
        _closed(row, STAGE_FIELDS, "native-result-stages")
        # A later stage's success never stands in for an earlier failure.
        if (row["stage"] != stage or row["attempt_id"] != request["attempt_id"]
                or row["input_sha256"] != request["outer_sha256"] or type(row["exit"]) is not int
                or row["exit"] != 0):
            raise _failed("native-result-stages")
    try:
        identity = records.identity_result(record["identity"])
    except library.canonical.Refusal:
        raise _failed("native-result-malformed") from None
    if identity["snapshot_id"] != request["snapshot_id"]:
        raise ValidationRefusal("identity_mismatch", "native-result-identity")
    if type(record["status_sha256"]) is not str or SHA256.fullmatch(record["status_sha256"]) is None:
        raise _failed("native-result-malformed")
    coverage = record["coverage"]
    if type(coverage) is not dict or coverage.get("complete") is not True:
        raise ValidationRefusal("signer_not_enrolled", "native-coverage-incomplete")
    verified = coverage.get("verified")
    if type(verified) is not list or not verified:
        raise ValidationRefusal("signer_not_enrolled", "native-coverage-incomplete")
    signers, commits = [], set()
    for row in verified:
        _closed(row, VERIFIED_FIELDS, "native-result-malformed")
        enrollment = row["enrollment"]
        if (type(row["commit"]) is not str or COMMIT.fullmatch(row["commit"]) is None or row["commit"] in commits
                or type(row["fingerprint"]) is not str or FINGERPRINT.fullmatch(row["fingerprint"]) is None
                or row["evidence_class"] != "local-signature" or type(row["native_current_boundary"]) is not bool
                or type(enrollment) is not dict or set(enrollment) != {"type", "sha256"}
                or type(enrollment["sha256"]) is not str or SHA256.fullmatch(enrollment["sha256"]) is None):
            raise _failed("native-result-malformed")
        commits.add(row["commit"])
        signers.append(((enrollment["type"], enrollment["sha256"]), row["fingerprint"]))
    required = coverage.get("required")
    if type(required) is not list or sorted(commits) != sorted(required):
        raise ValidationRefusal("signer_not_enrolled", "native-coverage-incomplete")
    return NativeEvidence(expected.job_id, payload, sha256, record, tuple(sorted(set(signers))))
