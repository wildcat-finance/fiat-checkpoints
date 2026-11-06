"""The released valid native fixture as a job: its request, approval and input.

The fixture's own approval names the test issuer reference its producer used,
because the fixture's private key was destroyed; it is test trust and never a
production enrollment.
"""

import base64
import hashlib
import json
import os
import tempfile

from fiat_checkpoints.validation import outputs, pins
from fiat_checkpoints.validation.refusals import stage_codes
from fiat_checkpoints.validation.sandbox import SandboxJob
from fiat_checkpoints.validation.specimens import CAPABILITIES, FIXTURE
from fiat_checkpoints.validation.trust import FixedTrust, HistoricalKey, RunTrust, job_document


TEST_ENROLLMENT = "a" * 64


def released(release):
    library, root = release.library, release.authority_root
    value = json.loads(library.native_io.read(root / FIXTURE / "fixture.json"))
    public = library.native_io.read(root / FIXTURE / "independent-public-key.gpg")
    if hashlib.sha256(public).hexdigest() != value["public_sha256"]:
        raise ValueError("released-fixture-drift")
    return value, public


def run_trust(release, *, first_step=1, last_step=2):
    value, public = released(release)
    key = HistoricalKey(value["fingerprint"], public, "key-enrollment", TEST_ENROLLMENT, 17, first_step, last_step)
    return RunTrust(value["anchor_sha256"], value["initial_base"], value["start_commit"], (key,))


def fixed_trust(release):
    return FixedTrust(run_trust(release))


def request(release, *, attempt="fixture-attempt", lease="fixture-lease", candidate="fixture-candidate", **changes):
    value, _ = released(release)
    result = {"attempt_id": attempt, "lease_id": lease, "candidate_id": candidate,
              "outer_sha256": value["outer_sha256"], "snapshot_id": value["snapshot_id"],
              "controller_manifest_sha256": value["controller_manifest_sha256"],
              "carrier_length": value["carrier_length"]}
    result.update(changes)
    return result


def valid_archive(release):
    return release.library.native_io.read(release.authority_root / FIXTURE / "checkpoint.zip", 1_073_741_824)


def capability_codes(release):
    library = release.library
    return stage_codes(library.canonical.decode(
        library.native_io.read(release.authority_root / CAPABILITIES, 1_048_576)))


def run(sandbox, release, archive, job_request, trust, *, mode="validate", case=None, binds=(), owner=None,
        argv=None):
    """Run one job over `archive` bytes and read it; returns (outcome or refusal, SandboxRun)."""
    from fiat_checkpoints.validation.refusals import ValidationRefusal
    from fiat_checkpoints.validation.service import sandbox_argv
    job_id = os.urandom(16).hex()
    document = job_document(job_id, job_request, trust, mode=mode, case=case)
    with tempfile.TemporaryFile() as stream:
        stream.write(archive)
        stream.flush()
        job = SandboxJob(owner=owner or job_id, argv=argv or sandbox_argv(), trust=document,
                         input_fd=stream.fileno(), input_sha256=hashlib.sha256(archive).hexdigest(),
                         input_length=len(archive), binds=tuple(binds))
        result = sandbox.run(job)
    expected = outputs.Expected(job_id, job_request, tuple(pins.tool(name) for name in pins.NATIVE_TOOLS),
                                trust.public_trust_sha256(), capability_codes(release))
    try:
        return outputs.read(result, expected, release.library, mode=mode), result
    except ValidationRefusal as refusal:
        return refusal, result


def case(specimen):
    return {"sha256": specimen.inspect_sha256, "sidecar": specimen.sidecar}


def base64_public(release):
    return base64.b64encode(released(release)[1]).decode("ascii")
