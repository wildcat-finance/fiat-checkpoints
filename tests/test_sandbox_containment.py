"""Hostile workloads inside a real gVisor sandbox leave nothing behind.

Each job runs as the untrusted program it would be: no network, no host
socket, no credential, no shared parent, no other job's files, and the whole
job killed at its ceilings. Skills #1647, #1648 and #1649 are contained here,
not fixed: raw stderr stays private, a job's state is a fresh root-only
directory read through held descriptors, and one owner never runs twice at once.
"""

import json
import os
import tempfile
import threading
import unittest

from fiat_checkpoints.validation import fixture
from fiat_checkpoints.validation.outputs import read
from fiat_checkpoints.validation.policy import ResourcePolicy
from fiat_checkpoints.validation.refusals import ValidationRefusal
from fiat_checkpoints.validation.sandbox import Sandbox, SandboxJob
from tests.validation_support import SandboxCase, expected, library, stdout_json


SMALL = ResourcePolicy().lowered(memory_bytes=256 * 1024 * 1024, processes=64, cpu_seconds=20, wall_seconds=60,
                                 scratch_bytes=32 * 1024 * 1024)


def probe(body):
    """A workload that prints one JSON object of observations."""
    return "import json, os, socket, sys\nout = {}\n" + body + "\nprint(json.dumps(out, sort_keys=True))\n"


class SandboxIsolationTests(SandboxCase):
    def test_network_dns_and_metadata_are_unreachable(self):
        run = self.hostile(probe(
            "out['interfaces'] = sorted(name for _, name in socket.if_nameindex())\n"
            "for name, target in (('metadata', ('169.254.169.254', 80)), ('gateway', ('10.0.2.2', 53)),\n"
            "                     ('public', ('1.1.1.1', 443))):\n"
            "    try:\n"
            "        socket.create_connection(target, timeout=3); out[name] = 'connected'\n"
            "    except OSError as error:\n"
            "        out[name] = 'refused'\n"
            "try:\n"
            "    socket.getaddrinfo('github.com', 443); out['dns'] = 'resolved'\n"
            "except OSError:\n"
            "    out['dns'] = 'refused'\n"))
        observed = stdout_json(run)
        self.assertEqual(["lo"], observed["interfaces"])
        for name in ("metadata", "gateway", "public", "dns"):
            self.assertEqual("refused", observed[name], name)

    def test_no_credential_socket_or_host_path_is_visible(self):
        os.environ["AWS_SECRET_ACCESS_KEY"] = "synthetic-not-a-credential"
        os.environ["SSH_AUTH_SOCK"] = "/tmp/synthetic-agent"
        try:
            run = self.hostile(probe(
                "out['env'] = sorted(os.environ)\n"
                "out['uid'] = os.getuid()\n"
                "out['paths'] = {path: os.path.exists(path) for path in ('/run/fiat-postgres',\n"
                "    '/var/run/docker.sock', '/run/fiat-validator', '/etc/gitconfig', '/tmp/fiat-checkpoints',\n"
                "    '/opt/fiat-checkpoints/service/.git', '/opt/fiat-checkpoints/service/.hexaemeron',\n"
                "    '/opt/fiat-checkpoints/gvisor', '/sys/fs/cgroup/fiat-validator')}\n"
                "out['environ'] = open('/proc/self/environ', 'rb').read().count(b'synthetic')\n"
                "out['root_listable'] = os.access('/root', os.R_OK)\n"))
        finally:
            del os.environ["AWS_SECRET_ACCESS_KEY"], os.environ["SSH_AUTH_SOCK"]
        observed = stdout_json(run)
        self.assertEqual(["HOME", "LANG", "LC_ALL", "PATH", "PYTHONDONTWRITEBYTECODE", "TMPDIR"], observed["env"])
        self.assertEqual(65532, observed["uid"])
        self.assertEqual(0, observed["environ"])
        self.assertEqual({}, {path: seen for path, seen in observed["paths"].items() if seen})
        self.assertFalse(observed["root_listable"])

    def test_root_toolchain_and_input_are_read_only(self):
        run = self.hostile(probe(
            "for path in ('/usr/bin/git', '/opt/fiat-checkpoints/protocol/native/x', '/input/checkpoint.zip',\n"
            "             '/trust/job.json', '/opt/fiat-checkpoints/service/src/fiat_checkpoints/x.py', '/etc/x',\n"
            "             '/var/tmp/x', '/dev/shm/x'):\n"
            "    try:\n"
            "        open(path, 'ab').write(b'x'); out[path] = 'written'\n"
            "    except OSError:\n"
            "        out[path] = 'refused'\n"
            "for name in ('rename', 'rmdir'):\n"
            "    try:\n"
            "        (os.rename('/job', '/job2') if name == 'rename' else os.rmdir('/job')); out[name] = 'done'\n"
            "    except OSError:\n"
            "        out[name] = 'refused'\n"
            "st = os.stat('/job'); out['job'] = [st.st_uid, oct(st.st_mode)]\n"
            "st = os.stat('/tmp'); out['tmp'] = [st.st_uid, oct(st.st_mode)]\n"
            "open('/tmp/run.sh', 'w').write('#!/bin/sh\\necho ran\\n'); os.chmod('/tmp/run.sh', 0o755)\n"
            "try:\n"
            "    os.execv('/tmp/run.sh', ['/tmp/run.sh'])\n"
            "except OSError:\n"
            "    out['tmp-exec'] = 'refused'\n"))
        observed = stdout_json(run)
        self.assertEqual({"refused"}, {value for key, value in observed.items() if key not in ("job", "tmp")})
        self.assertEqual([65532, "0o40700"], observed["job"])
        self.assertEqual([65532, "0o40700"], observed["tmp"])

    def test_hooks_and_git_configuration_from_the_host_do_not_reach_the_job(self):
        run = self.hostile(probe(
            "import subprocess\n"
            "os.makedirs('/job/repo/.git/hooks')\n"
            "p = subprocess.run(['git', 'config', '--list', '--show-origin'], capture_output=True, cwd='/job',\n"
            "                   env={'PATH': '/usr/bin:/bin', 'HOME': '/job'})\n"
            "out['config'] = p.stdout.decode()\n"
            "out['exists'] = [os.path.exists(p) for p in ('/etc/gitconfig', '/job/.gitconfig',\n"
            "                 os.path.expanduser('~/.gitconfig'))]\n"))
        observed = stdout_json(run)
        self.assertEqual("", observed["config"])
        self.assertEqual([False, False, False], observed["exists"])


class SandboxOtherJobTests(SandboxCase):
    slots = 2

    def test_concurrent_jobs_cannot_see_each_other(self):
        marker = os.urandom(16).hex()
        results = {}

        def first():
            results["first"] = self.hostile(probe(
                "open('/job/" + marker + "', 'w').write('" + marker + "')\n"
                "import time; time.sleep(20)\nout['wrote'] = True\n"))

        thread = threading.Thread(target=first)
        thread.start()
        try:
            import time
            time.sleep(8)
            results["second"] = self.hostile(probe(
                "found = []\n"
                "for top in ('/job', '/tmp', '/proc', '/run', '/var', '/opt'):\n"
                "    for root, dirs, files in os.walk(top):\n"
                "        if '" + marker + "' in files: found.append(root)\n"
                "        if root.startswith('/proc/') and root.count('/') > 2: dirs[:] = []\n"
                "out['found'] = found\n"
                "out['pids'] = sorted(int(p) for p in os.listdir('/proc') if p.isdigit())\n"))
        finally:
            thread.join()
        self.assertTrue(stdout_json(results["first"])["wrote"])
        observed = stdout_json(results["second"])
        self.assertEqual([], observed["found"])
        self.assertLessEqual(len(observed["pids"]), 3)

    def test_jobs_for_one_owner_never_overlap(self):
        # Skills #1649: a second job for the same candidate refuses while the first runs.
        started = threading.Event()
        results = {}

        def first():
            started.set()
            results["first"] = self.hostile("import time; time.sleep(15); print('{}')", owner="candidate-one")

        thread = threading.Thread(target=first)
        thread.start()
        try:
            started.wait()
            import time
            time.sleep(3)
            with self.assertRaises(ValidationRefusal) as caught:
                self.hostile("print('{}')", owner="candidate-one")
            self.assertEqual(("sandbox_unavailable", "sandbox-owner-busy"),
                             (caught.exception.code, caught.exception.reason))
        finally:
            thread.join()
        self.assertEqual(0, results["first"].exit)
        self.assertEqual(0, self.hostile("print('{}')", owner="candidate-one").exit)

    def test_slots_bound_concurrent_jobs(self):
        sandbox = Sandbox(slots=1)
        started = threading.Event()
        results = {}

        def first():
            started.set()
            results["first"] = self.hostile("import time; time.sleep(12); print('{}')", policy_sandbox=sandbox)

        thread = threading.Thread(target=first)
        thread.start()
        try:
            started.wait()
            import time
            time.sleep(3)
            with self.assertRaises(ValidationRefusal) as caught:
                self.hostile("print('{}')", policy_sandbox=sandbox)
            self.assertEqual("sandbox-slots-exhausted", caught.exception.reason)
        finally:
            thread.join()


class SandboxStateSwapTests(SandboxCase):
    def test_replaced_job_state_directory_refuses_before_launch(self):
        # Skills #1648: a swap of the job's state path after it was created is detected.
        class Swapping(Sandbox):
            def _cgroup(self, job_id):
                directory = self.state_root / "jobs" / job_id
                os.rename(directory, str(directory) + "-moved")
                os.mkdir(directory, 0o700)
                self.moved = str(directory) + "-moved"
                return super()._cgroup(job_id)

        sandbox = Swapping()
        with self.assertRaises(ValidationRefusal) as caught:
            self.hostile("print('{}')", policy_sandbox=sandbox)
        self.assertEqual("sandbox-state-changed", caught.exception.reason)
        import shutil
        shutil.rmtree(sandbox.moved)

    def test_input_is_copied_from_the_held_descriptor_and_digest_checked(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(b"synthetic input bytes")
            stream.flush()
            import hashlib
            good = hashlib.sha256(b"synthetic input bytes").hexdigest()
            run = self.hostile("print(open('/input/checkpoint.zip', 'rb').read().decode())",
                               input_fd=stream.fileno(), input_sha256=good, input_length=21)
            self.assertEqual(b"synthetic input bytes\n", run.stdout)
            with self.assertRaises(ValidationRefusal) as caught:
                self.hostile("print('{}')", input_fd=stream.fileno(), input_sha256="0" * 64, input_length=21)
            self.assertEqual("sandbox-input-changed", caught.exception.reason)
            with self.assertRaises(ValidationRefusal):
                self.hostile("print('{}')", input_fd=stream.fileno(), input_sha256=good, input_length=20)


class SandboxCeilingTests(SandboxCase):
    policy = SMALL

    def assert_killed(self, run, reason):
        self.assertEqual(reason, run.killed)
        with self.assertRaises(ValidationRefusal) as caught:
            read(run, expected(run.job_id), library())
        self.assertEqual(("validation_failed", "sandbox-" + reason), (caught.exception.code, caught.exception.reason))

    def test_memory_ceiling_kills_the_whole_job(self):
        run = self.hostile("b = bytearray(400 * 1024 * 1024); print('{}')")
        self.assert_killed(run, "memory-limit")
        self.assertGreaterEqual(run.resources["oom_kills"], 1)

    def test_process_ceiling_holds_under_a_fork_flood(self):
        # The cgroup counts the sentry's own host threads with the job's tasks, so a
        # flood either fails to spawn inside the job or stops the whole sandbox.
        run = self.hostile(probe(
            "import subprocess\nprocs, failed = [], 0\n"
            "for _ in range(200):\n"
            "    try:\n"
            "        procs.append(subprocess.Popen(['sleep', '5']))\n"
            "    except OSError:\n"
            "        failed += 1\n"
            "out['started'] = len(procs); out['failed'] = failed\n"
            "for p in procs: p.kill()\n"))
        self.assertLessEqual(run.resources["pids_peak"], SMALL.processes)
        if run.exit == 0 and run.killed is None and run.stdout:
            self.assertLess(stdout_json(run)["started"], 200)
        else:
            with self.assertRaises(ValidationRefusal) as caught:
                read(run, expected(run.job_id), library())
            self.assertEqual("validation_failed", caught.exception.code)

    def test_cpu_seconds_ceiling_kills_a_spinning_job(self):
        policy = SMALL.lowered(cpu_seconds=5)
        run = self.hostile("import time\nend = time.time() + 50\nwhile time.time() < end: pass\nprint('{}')",
                           policy_sandbox=Sandbox(policy))
        self.assertIn(run.killed, ("cpu-limit", None))
        if run.killed is None:
            # RLIMIT_CPU inside gVisor stopped it first: still no result.
            self.assertNotEqual(b"{}\n", run.stdout)

    def test_wall_ceiling_kills_a_sleeping_job(self):
        run = self.hostile("import time; time.sleep(120); print('{}')", wall_seconds=5)
        self.assert_killed(run, "wall-limit")
        self.assertLess(run.resources["wall_ms"], 60_000)

    def test_scratch_ceiling_refuses_writes_past_it(self):
        run = self.hostile(probe(
            "try:\n"
            "    for index in range(8):\n"
            "        with open('/job/fill-%d' % index, 'wb') as f: f.write(b'x' * 8 * 1024 * 1024)\n"
            "    out['filled'] = True\n"
            "except OSError as error:\n"
            "    out['errno'] = error.errno\n"))
        self.assertIsNone(run.killed)
        self.assertEqual({"errno": 28}, stdout_json(run))

    def test_output_ceilings_kill_and_refuse(self):
        self.assert_killed(self.hostile("import sys\nsys.stdout.write('x' * 200000)"), "stdout-limit")
        self.assert_killed(self.hostile("import sys\nsys.stderr.write('x' * 200000)"), "stderr-limit")

    def test_native_diagnostics_stay_private(self):
        # Skills #1647: a signing-key id in stderr is hashed, never returned.
        key_id = "8CF45B322E7748BF"
        run = self.hostile("import sys\nsys.stderr.write('gpg: Signature made with key " + key_id + "\\n')\n"
                           "print('signature-unverified " + key_id + "')")
        self.assertGreater(run.stderr_bytes, 0)
        self.assertNotIn(key_id.encode(), repr(run).encode())
        with self.assertRaises(ValidationRefusal) as caught:
            read(run, expected(run.job_id), library())
        self.assertEqual("validation_failed", caught.exception.code)
        self.assertNotIn(key_id, repr(caught.exception) + json.dumps(caught.exception.record()))


if __name__ == "__main__":
    unittest.main()
