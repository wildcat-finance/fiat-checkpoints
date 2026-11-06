"""The sandbox profile, its ceilings and its refusal to run without gVisor.

These checks start no process. The OCI spec is built as data; a missing or
altered runsc refuses `sandbox_unavailable` before anything is launched, and
no path falls back to a plain subprocess.
"""

import os
from pathlib import Path
import re
import tempfile
import unittest

from fiat_checkpoints.records.trees import REPOSITORY
from fiat_checkpoints.validation import pins
from fiat_checkpoints.validation.policy import GIB, SPECIFICATION, ResourcePolicy
from fiat_checkpoints.validation.refusals import ValidationRefusal
from fiat_checkpoints.validation.sandbox import ENVIRONMENT, Sandbox, SandboxJob
from fiat_checkpoints.validation.service import sandbox_argv, service_binds


def job(**changes):
    values = {"owner": "candidate", "argv": sandbox_argv(), "trust": b"{}"}
    values.update(changes)
    return SandboxJob(**values)


class SandboxPolicyTests(unittest.TestCase):
    def test_default_policy_is_the_specification(self):
        self.assertEqual({"cpus": 2, "memory_bytes": 4 * GIB, "scratch_bytes": 8 * GIB, "processes": 256,
                          "filesystem_nodes": 100_000, "cpu_seconds": 300, "wall_seconds": 900,
                          "stdout_bytes": 65_536, "stderr_bytes": 16_384, "open_files": 1_024},
                         SPECIFICATION.record())

    def test_policy_lowers_and_never_raises(self):
        lowered = SPECIFICATION.lowered(memory_bytes=GIB, wall_seconds=60)
        self.assertEqual((GIB, 60), (lowered.memory_bytes, lowered.wall_seconds))
        for change in ({"memory_bytes": 5 * GIB}, {"processes": 257}, {"cpu_seconds": 0}, {"unknown": 1},
                       {"wall_seconds": True}, {"stdout_bytes": 65_537}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                SPECIFICATION.lowered(**change)

    def test_oci_spec_denies_network_privilege_and_writes_outside_the_job(self):
        config = Sandbox().oci_config(job(binds=service_binds("/checkout")), "a" * 32, Path("/state/job"))
        process = config["process"]
        self.assertEqual({"uid": pins.SANDBOX_UID, "gid": pins.SANDBOX_UID}, process["user"])
        self.assertTrue(process["noNewPrivileges"])
        self.assertTrue(all(value == [] for value in process["capabilities"].values()))
        self.assertTrue(config["root"]["readonly"])
        self.assertIn({"type": "network"}, config["linux"]["namespaces"])
        mounts = {mount["destination"]: mount for mount in config["mounts"]}
        self.assertEqual({"/proc", "/job", "/tmp", "/input/checkpoint.zip", "/trust/job.json",
                          "/opt/fiat-checkpoints/service/src", "/opt/fiat-checkpoints/service/protocol.lock.json",
                          "/opt/fiat-checkpoints/service/protocol.trees.json"}, set(mounts))
        writable = [name for name, mount in mounts.items()
                    if mount["type"] == "tmpfs" or "rw" in mount.get("options", [])]
        self.assertEqual(["/job", "/tmp"], writable)
        self.assertEqual("tmpfs", mounts["/job"]["type"])
        self.assertEqual(["size=%d" % (8 * GIB), "mode=0700", "uid=65532", "gid=65532", "nosuid", "nodev", "noexec"],
                         mounts["/job"]["options"])
        for name in ("/input/checkpoint.zip", "/trust/job.json"):
            self.assertIn("ro", mounts[name]["options"])
        self.assertEqual("/fiat-validator/" + "a" * 32, config["linux"]["cgroupsPath"])
        resources = config["linux"]["resources"]
        self.assertEqual((4 * GIB, 4 * GIB, 256, 200_000), (resources["memory"]["limit"], resources["memory"]["swap"],
                                                            resources["pids"]["limit"], resources["cpu"]["quota"]))
        limits = {row["type"]: row["hard"] for row in process["rlimits"]}
        self.assertEqual({"RLIMIT_CPU": 300, "RLIMIT_NOFILE": 1024, "RLIMIT_CORE": 0, "RLIMIT_FSIZE": 8 * GIB}, limits)

    def test_tmp_is_private_bounded_and_noexec_like_the_job_root(self):
        # S6-R1-04: runsc mounts a world-writable, executable, unsized /tmp unless the
        # spec names one; native Git writes there, so it stays writable but bounded.
        config = Sandbox().oci_config(job(), "0" * 32, Path("/run/fiat-validator/jobs/x"))
        tmp = [mount for mount in config["mounts"] if mount["destination"] == "/tmp"]
        self.assertEqual(1, len(tmp), "runsc would add its own /tmp")
        mounts = {mount["destination"]: mount for mount in config["mounts"]}
        self.assertEqual(("tmpfs", mounts["/job"]["options"]), (tmp[0]["type"], tmp[0]["options"]))

    def test_reap_removes_only_jobs_whose_lock_is_free(self):
        # S6-R1-05: a job whose supervisor died keeps its sandbox, cgroup and state
        # until the next start reaps it; a job whose lock is held is live and stays.
        self.assertTrue(callable(getattr(Sandbox, "reap", None)), "no reaper for a dead supervisor's jobs")
        import fcntl
        from unittest import mock
        orphan, live, lockless = "a" * 32, "b" * 32, "c" * 32
        cleaned = []
        with tempfile.TemporaryDirectory() as root:
            state, groups = Path(root) / "state", Path(root) / "cgroup"
            (state / "jobs").mkdir(parents=True)
            for job_id in (orphan, live):
                (state / "jobs" / job_id).mkdir()
                (state / "jobs" / (job_id + ".lock")).touch()
            (groups / "fiat-validator" / lockless).mkdir(parents=True)
            held = os.open(state / "jobs" / (live + ".lock"), os.O_RDWR)
            fcntl.flock(held, fcntl.LOCK_EX)
            try:
                with mock.patch.object(Sandbox, "_cleanup", lambda self, job_id, directory, cgroup: cleaned.append(
                        (job_id, directory is not None, cgroup is not None))):
                    reaped = Sandbox(state_root=state, cgroup_root=groups).reap()
                remaining = sorted(os.listdir(state / "jobs"))
            finally:
                os.close(held)
        self.assertEqual([orphan, lockless], sorted(reaped))
        self.assertEqual({(orphan, True, False), (lockless, False, True)}, set(cleaned))
        self.assertEqual([orphan, live, live + ".lock"], remaining)

    def test_checks_and_runbooks_name_the_sandbox_launcher_and_resolve_their_decisions(self):
        # S6-R1-02: the documented check commands name the launcher these groups need,
        # and each validation runbook's decision reference resolves read on its own.
        command = "scripts/sandbox-env.sh run python3 scripts/check.py --group validation,sandbox"
        for name in ("README.md", "AGENTS.md"):
            with self.subTest(document=name):
                self.assertIn(command, (REPOSITORY / name).read_text(encoding="utf-8"))
        for name in ("validation-failures.md", "policy-freshness.md"):
            path = REPOSITORY / "docs/runbooks" / name
            text = path.read_text(encoding="utf-8")
            with self.subTest(runbook=name):
                self.assertNotRegex(text, r"(?<![\w/.])adr/[a-z0-9-]+")
                for target in re.findall(r"\]\((\.\./decisions/[^)]+)\)", text):
                    self.assertTrue((path.parent / target).is_file(), target)

    def test_environment_is_an_allowlist_with_no_credentials(self):
        config = Sandbox().oci_config(job(), "a" * 32, Path("/state/job"))
        names = {entry.split("=", 1)[0] for entry in config["process"]["env"]}
        self.assertEqual({name for name, _ in ENVIRONMENT}, names)
        for name in ("AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "GPG_AGENT_INFO", "GIT_DIR", "PYTHONPATH",
                     "GIT_CONFIG_GLOBAL", "HTTPS_PROXY"):
            with self.subTest(name=name), self.assertRaises(ValidationRefusal) as caught:
                Sandbox().oci_config(job(environment=ENVIRONMENT + ((name, "synthetic"),)), "a" * 32, Path("/s"))
            self.assertEqual("sandbox_unavailable", caught.exception.code)

    def test_runsc_arguments_deny_network_and_host_files(self):
        argv = Sandbox()._runsc("run", "--bundle", "/b", "a" * 32)
        self.assertEqual(str(pins.RUNSC_PATH), argv[0])
        for flag in ("--network=none", "--host-uds=none", "--host-fifo=none", "--platform=systrap"):
            self.assertIn(flag, argv)

    def test_validation_argv_names_no_record_field(self):
        argv = sandbox_argv()
        self.assertEqual(pins.SANDBOX_PYTHON, argv[0])
        self.assertEqual(("-I", "-B"), argv[1:3])
        self.assertTrue(all(part.startswith("/") or part.startswith("-") for part in argv))

    def test_missing_or_altered_runsc_refuses_instead_of_falling_back(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Sandbox(runsc=Path(directory) / "runsc")
            with self.assertRaises(ValidationRefusal) as caught:
                missing.check()
            self.assertEqual("sandbox_unavailable", caught.exception.code)
            altered = Path(directory) / "altered"
            altered.write_bytes(b"#!/bin/sh\nexec \"$@\"\n")
            os.chmod(altered, 0o755)
            with self.assertRaises(ValidationRefusal) as caught:
                Sandbox(runsc=altered).check()
            self.assertEqual("sandbox_unavailable", caught.exception.code)
            with self.assertRaises(ValidationRefusal):
                Sandbox(runsc=altered).run(job())

    def test_missing_rootfs_or_cgroup_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            for sandbox in (Sandbox(rootfs=Path(directory) / "rootfs"), Sandbox(cgroup_root=Path(directory))):
                with self.subTest(sandbox=sandbox), self.assertRaises(ValidationRefusal) as caught:
                    sandbox.check()
                self.assertEqual("sandbox_unavailable", caught.exception.code)

    def test_invalid_jobs_and_configuration_refuse(self):
        for values in ({"slots": 0}, {"slots": 65}, {"platform": "kvm-or-anything"}, {"policy": object()}):
            with self.subTest(values=values), self.assertRaises(ValidationRefusal):
                Sandbox(**values)
        for bad in (job(owner=""), job(owner="x" * 129), "not-a-job"):
            with self.subTest(job=bad), self.assertRaises(ValidationRefusal):
                Sandbox().run(bad)


if __name__ == "__main__":
    unittest.main()
