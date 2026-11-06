"""Shared set-up for the validation and sandbox groups.

Process-free checks build synthetic sandbox runs over the released library,
so the Elenchus report run exercises the parsing, binding, trust and policy
code without a child process. Classes that start runsc, OpenSSL or any other
process set `spawns_child_process = True`. The sandbox classes need the
validator image's supervisor (`scripts/sandbox-env.sh run`); every archive is
the released synthetic fixture or a specimen rebuilt from it.
"""

import copy
import functools
import hashlib
import json
import os
import unittest

from fiat_checkpoints.records.trees import DEFAULT_TREES, REPOSITORY, load_release
from fiat_checkpoints.validation import fixture, outputs, pins
from fiat_checkpoints.validation.sandbox import Sandbox, SandboxRun, leftovers
from fiat_checkpoints.validation.service import service_binds


JOB_ID = "0123456789abcdef0123456789abcdef"


@functools.cache
def release():
    return load_release(REPOSITORY, DEFAULT_TREES)


def library():
    return release().library


def canonical(value):
    return library().canonical.canonical(value)


def request(**changes):
    return fixture.request(release(), **changes)


def trust():
    return fixture.run_trust(release())


def expected(job_id=JOB_ID, job_request=None, run_trust=None):
    run_trust = trust() if run_trust is None else run_trust
    return outputs.Expected(job_id, request() if job_request is None else job_request,
                            tuple(pins.tool(name) for name in pins.NATIVE_TOOLS),
                            run_trust.public_trust_sha256(), fixture.capability_codes(release()))


def native_record(job_request=None):
    """A complete native result in the released shape, built from the fixture's recorded outputs."""
    value, _ = fixture.released(release())
    job_request = request() if job_request is None else job_request
    records, native = library().native_records, library().native
    stages = [{"stage": stage, "attempt_id": job_request["attempt_id"], "input_sha256": job_request["outer_sha256"],
               "exit": 0, "output_sha256": "e" * 64, "log_sha256": "f" * 64, "output_bytes": 10, "log_bytes": 0,
               "duration_ms": 5} for stage in ("inspect", "restore", "verify", "identity")]
    verified = [{"commit": commit, "enrollment": {"type": "key-enrollment", "sha256": fixture.TEST_ENROLLMENT},
                 "evidence_class": "local-signature", "fingerprint": value["fingerprint"],
                 "native_current_boundary": commit in value["native_expected"]} for commit in value["required"]]
    return {"schema": "checkpoint-authority-native-result/v1", "complete": True, "request": dict(job_request),
            "source_commit": records.NATIVE_COMMIT, "executable_sha256": records.CONTROLLER_SHA256,
            "profile": records.PROFILE, "source_profile_sha256": native.LAYOUT_SHA256,
            "tools": [{"name": item.name, "sha256": item.sha256} for item in
                      (pins.tool(name) for name in pins.NATIVE_TOOLS)],
            "public_trust_sha256": trust().public_trust_sha256(), "native_results": stages,
            "identity": copy.deepcopy(value["original_outputs"]["identity"]), "status_sha256": "c" * 64,
            "next": {"do": "implement"},
            "coverage": {"required": sorted(value["required"]), "verified": verified, "complete": True},
            "operation_ran": True, "historical_commands_executed": False, "current_eligibility": "unknown",
            "service_acceptance": "unavailable", "resources": {"input_bytes": 1, "output_bytes": 1, "duration_ms": 1}}


def result_line(job_id=JOB_ID, status="complete", record=None, refusal=None, digest=None):
    value = {"schema": outputs.SCHEMA_RESULT, "job_id": job_id, "status": status, "native_result": record,
             "native_result_sha256": None, "refusal": refusal}
    if record is not None:
        value["native_result_sha256"] = digest or hashlib.sha256(canonical(record)).hexdigest()
    return canonical(value) + b"\n"


def run_of(stdout, *, exit=0, killed=None, job_id=JOB_ID):
    return SandboxRun(job_id, exit, stdout, "0" * 64, 0, killed, {"wall_ms": 1})


class SandboxCase(unittest.TestCase):
    """A real gVisor sandbox from the validator image; refuses rather than skips outside it."""

    spawns_child_process = True
    policy = None
    slots = 2

    @classmethod
    def setUpClass(cls):
        cls.release = release()
        cls.sandbox = Sandbox(cls.policy, slots=cls.slots) if cls.policy else Sandbox(slots=cls.slots)
        cls.sandbox.check()
        cls.binds = service_binds(REPOSITORY)

    def tearDown(self):
        self.assertEqual({"jobs": [], "cgroups": []}, leftovers())

    def hostile(self, code, *, policy_sandbox=None, owner=None, trust_bytes=b"{}", **job):
        """Run a Python snippet as the untrusted workload; returns the SandboxRun."""
        from fiat_checkpoints.validation.sandbox import SandboxJob
        sandbox = policy_sandbox or self.sandbox
        return sandbox.run(SandboxJob(owner=owner or os.urandom(8).hex(),
                                      argv=(pins.SANDBOX_PYTHON, "-I", "-c", code), trust=trust_bytes,
                                      binds=self.binds, **job))

    def valid_job(self, **changes):
        return fixture.run(self.sandbox, self.release, fixture.valid_archive(self.release),
                           request(**changes), trust(), binds=self.binds)


def stdout_json(run):
    return json.loads(run.stdout)
