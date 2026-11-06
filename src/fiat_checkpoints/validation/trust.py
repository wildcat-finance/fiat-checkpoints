"""Inject only independently approved public trust into a job.

A job's trust document carries the request the supervisor derived from its
own records, the run's approved history of public OpenPGP keys and the pinned
tool digests. Nothing in it is read from the archive, the upload request or a
previous job. No private key, agent socket or credential is ever part of it;
the sandbox seeds its per-job keyring from these public bytes alone and the
native adapter refuses any secret key it finds.

Two sources implement the same seam. `ProjectionTrust` reads the run's
verified Step 4 projection: every operator-enrolled OpenPGP key of the run,
and after the job, the exact `(enrollment, fingerprint)` pairs that signed
must resolve through `Projection.historical_signers`. `FixedTrust` carries a
released fixture's own approval; the released native fixture's private key
was destroyed by its producer, so no Step 4 enrollment of it can exist.
"""

from dataclasses import dataclass
import base64
import hashlib
import json
import re

from fiat_checkpoints.validation import pins
from fiat_checkpoints.validation.refusals import ValidationRefusal


SCHEMA_JOB = "fiat-checkpoints-sandbox-job/v1"
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
FINGERPRINT = re.compile(r"[0-9A-F]{40}")
JOB_ID = re.compile(r"[0-9a-f]{32}")
ENROLLMENT_TYPES = ("key-enrollment", "key-rotation")
MAX_KEYS = 128
STEP_LIMIT = 4096


def canonical(value):
    """The released canonical form: sorted, compact, ASCII-escaped JSON."""
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


@dataclass(frozen=True)
class HistoricalKey:
    """One approved public signing key of the run and the enrollment that approved it."""
    fingerprint: str
    public: bytes
    enrollment_type: str
    enrollment_sha256: str
    actor_id: int
    first_step: int = 1
    last_step: int = STEP_LIMIT

    def row(self):
        if (type(self.fingerprint) is not str or FINGERPRINT.fullmatch(self.fingerprint) is None
                or type(self.public) is not bytes or not 1 <= len(self.public) <= 6144
                or self.enrollment_type not in ENROLLMENT_TYPES or type(self.enrollment_sha256) is not str
                or SHA256.fullmatch(self.enrollment_sha256) is None or type(self.actor_id) is not int
                or not 1 <= self.actor_id < 2 ** 63 or type(self.first_step) is not int
                or type(self.last_step) is not int or not 1 <= self.first_step <= self.last_step <= STEP_LIMIT):
            raise ValidationRefusal("validation_failed", "trust-key-invalid")
        return {"key": {"format": "openpgp-v4", "algorithm": "openpgp", "fingerprint": self.fingerprint,
                        "public": base64.b64encode(self.public).decode("ascii")},
                "enrollment": {"type": self.enrollment_type, "sha256": self.enrollment_sha256},
                "actor_id": self.actor_id, "first_step": self.first_step, "last_step": self.last_step}


@dataclass(frozen=True)
class RunTrust:
    """The approved inputs `verify_native` needs, all from trusted state."""
    anchor_sha256: str
    initial_base: str
    start_commit: str
    keys: tuple

    def approval(self):
        if (type(self.anchor_sha256) is not str or SHA256.fullmatch(self.anchor_sha256) is None
                or any(type(value) is not str or COMMIT.fullmatch(value) is None
                       for value in (self.initial_base, self.start_commit))):
            raise ValidationRefusal("validation_failed", "trust-run-invalid")
        if type(self.keys) is not tuple or not self.keys:
            raise ValidationRefusal("signer_not_enrolled", "trust-history-empty")
        if len(self.keys) > MAX_KEYS:
            raise ValidationRefusal("validation_failed", "trust-history-limit")
        return {"anchor_sha256": self.anchor_sha256, "initial_base": self.initial_base,
                "start_commit": self.start_commit, "history": [key.row() for key in self.keys]}

    def public_trust_sha256(self):
        """The digest the native adapter reports for the keyring it seeded."""
        unique = {}
        for key in self.keys:
            if unique.get(key.fingerprint, key.public) != key.public:
                raise ValidationRefusal("validation_failed", "trust-history-ambiguous")
            unique[key.fingerprint] = key.public
        return hashlib.sha256(b"".join(unique[name] for name in sorted(unique))).hexdigest()

    def pairs(self):
        return frozenset(((key.enrollment_type, key.enrollment_sha256), key.fingerprint) for key in self.keys)


def tool_rows(tools=None):
    names = pins.NATIVE_TOOLS
    tools = pins.TOOLS if tools is None else tools
    by_name = {item.name: item for item in tools}
    return [{"name": name, "path": by_name[name].path, "sha256": by_name[name].sha256} for name in names]


def job_document(job_id, request, trust, *, mode="validate", case=None, tools=None):
    """The canonical bytes bound read-only at `/trust/job.json` for one job."""
    if type(job_id) is not str or JOB_ID.fullmatch(job_id) is None or mode not in ("validate", "inspect-case"):
        raise ValidationRefusal("validation_failed", "trust-job-invalid")
    if (mode == "inspect-case") != (case is not None):
        raise ValidationRefusal("validation_failed", "trust-job-invalid")
    return canonical({"schema": SCHEMA_JOB, "job_id": job_id, "mode": mode, "request": dict(request),
                      "approval": trust.approval(), "tools": tool_rows(tools), "case": case})


class FixedTrust:
    """A released fixture's approval, used as is; it names no Step 4 projection."""

    def __init__(self, run_trust):
        self.run_trust = run_trust

    def for_candidate(self, context):
        return self.run_trust

    def approve(self, context, signers):
        if not signers or not set(signers) <= self.run_trust.pairs():
            raise ValidationRefusal("signer_not_enrolled", "historical-signer-unapproved")
        return [{"type": kind, "sha256": sha256} for (kind, sha256), _fingerprint in signers]


class ProjectionTrust:
    """Approved history from the run's verified projection; the operator sets the start commit."""

    def __init__(self, projections, start_commits):
        self.projections = projections
        self.start_commits = dict(start_commits)

    def for_candidate(self, context):
        projection = context.projection
        registration = context.registration
        start = self.start_commits.get(context.run.key)
        if start is None:
            raise ValidationRefusal("checkpoint_ineligible", "run-start-unapproved")
        keys = []
        for item in projection.accepted:
            if item.record_type not in ENROLLMENT_TYPES:
                continue
            record = item.record
            key = record.get("key", {})
            if key.get("format") != "openpgp-v4":
                continue
            try:
                public = base64.b64decode(key["public"], validate=True)
            except (KeyError, ValueError, TypeError):
                raise ValidationRefusal("authority_unavailable", "trust-key-unreadable") from None
            keys.append(HistoricalKey(key["fingerprint"], public, item.record_type, item.envelope_sha256,
                                      record["actor_id"]))
        return RunTrust(registration["native_anchor_sha256"], registration["initial_base"], start, tuple(keys))

    def approve(self, context, signers):
        from fiat_checkpoints.auth.refusals import AuthRefusal
        try:
            return context.projection.historical_signers(
                [({"type": kind, "sha256": sha256}, fingerprint) for (kind, sha256), fingerprint in signers])
        except AuthRefusal as error:
            if error.code == "signer_not_enrolled":
                raise ValidationRefusal("signer_not_enrolled", "historical-signer-unapproved") from None
            raise ValidationRefusal("policy_unavailable", "historical-signers-unavailable") from None
