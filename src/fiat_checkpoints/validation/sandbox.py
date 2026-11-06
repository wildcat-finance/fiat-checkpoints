"""Launch one job in a fresh gVisor sandbox and give back bounded, private output.

The supervisor is trusted and runs as root; the job is not. Each job gets:

- a private state directory under a root-only parent, named by 32 random hex
  characters, holding its own copy of the sealed input, its trust document
  and its OCI bundle, so no other job or process can name or replace them
  (Skills #1648);
- a fresh gVisor-internal tmpfs as `/job`, owned by the sandbox user and
  bounded by the scratch ceiling. Its pages are sentry memory, so they also
  count against the job's memory limit. A gofer-backed host directory cannot
  serve here: the native restore publishes with `renameat2(RENAME_NOREPLACE)`,
  which gVisor refuses with EINVAL on a bind mount;
- its own cgroup with memory (no swap), process and CPU-share limits, which
  the supervisor also reads for CPU seconds, peaks and OOM kills;
- `runsc` with no network, no host sockets or FIFOs, and a read-only root.

Jobs that name the same owner never overlap (Skills #1649), and at most
`slots` jobs run at once. A job's stdout is capped and returned for strict
parsing; its stderr is capped, hashed and kept private (Skills #1647). On any
exit the whole cgroup is killed, the sandbox deleted (with its tmpfs) and the
state directory removed. A missing or altered runsc, root filesystem or
cgroup controller refuses as `sandbox_unavailable`; nothing falls back to a
plain subprocess.
"""

import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import threading
import time
from dataclasses import dataclass

from fiat_checkpoints.validation import pins
from fiat_checkpoints.validation.policy import ResourcePolicy
from fiat_checkpoints.validation.refusals import ValidationRefusal


LOGGER = logging.getLogger("fiat_checkpoints")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())
STATE_ROOT = Path("/run/fiat-validator")
CGROUP_ROOT = Path("/sys/fs/cgroup")
CGROUP_PARENT = "fiat-validator"
CONTROLLERS = ("cpu", "memory", "pids")
CPU_PERIOD_US = 100_000
POLL_SECONDS = 0.05
KILL_GRACE_SECONDS = 30
JOB_ID_BYTES = 16
ENVIRONMENT = (("PATH", "/usr/local/bin:/usr/bin:/bin"), ("LANG", "C.UTF-8"), ("LC_ALL", "C"),
               ("HOME", "/job"), ("TMPDIR", "/job"), ("PYTHONDONTWRITEBYTECODE", "1"))
ENVIRONMENT_NAMES = frozenset({"PATH", "LANG", "LC_ALL", "HOME", "TMPDIR", "PYTHONDONTWRITEBYTECODE",
                               "PYTHONUNBUFFERED"})
@dataclass(frozen=True)
class SandboxJob:
    """One job: argv and environment inside the sandbox, and what to bind.

    `input_fd` is read with `pread` into the job's private state before launch and
    bound read-only at `/input/checkpoint.zip`; `trust` is bound read-only at
    `/trust/job.json`; each `binds` pair is a read-only host path and its
    mount point inside the root filesystem.
    """
    owner: str
    argv: tuple
    trust: bytes
    input_fd: int | None = None
    input_sha256: str | None = None
    input_length: int | None = None
    environment: tuple = ENVIRONMENT
    binds: tuple = ()
    wall_seconds: int | None = None


@dataclass(frozen=True)
class SandboxRun:
    job_id: str
    exit: int | None
    stdout: bytes
    stderr_sha256: str
    stderr_bytes: int
    killed: str | None
    resources: dict

    def __repr__(self):
        return "SandboxRun(%s, exit=%r, killed=%r)" % (self.job_id, self.exit, self.killed)


def _unavailable(reason):
    return ValidationRefusal("sandbox_unavailable", reason)


def _digest(path, algorithm, maximum=256 * 1024 * 1024):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise _unavailable("sandbox-binary-kind")
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise _unavailable("sandbox-binary-writable")
        hasher = hashlib.new(algorithm)
        while chunk := os.read(descriptor, 1024 * 1024):
            hasher.update(chunk)
        return hasher.hexdigest()
    finally:
        os.close(descriptor)


def _write(path, text):
    with open(path, "w", encoding="ascii") as stream:
        stream.write(text)


def _read_int(path, key=None):
    try:
        text = Path(path).read_text(encoding="ascii")
    except OSError:
        return None
    if key is None:
        value = text.strip()
        return int(value) if value.isdigit() else None
    for line in text.splitlines():
        name, _, value = line.partition(" ")
        if name == key and value.strip().isdigit():
            return int(value)
    return None


class Sandbox:
    """The gVisor launcher. One instance per supervisor process."""

    def __init__(self, policy=None, *, slots=1, state_root=STATE_ROOT, runsc=pins.RUNSC_PATH,
                 rootfs=pins.ROOTFS, platform=pins.PLATFORM, cgroup_root=CGROUP_ROOT,
                 runsc_sha512=pins.RUNSC_SHA512, sidecars=None, tools=pins.TOOLS):
        self.policy = policy if policy is not None else ResourcePolicy()
        if not isinstance(self.policy, ResourcePolicy):
            raise _unavailable("sandbox-policy-invalid")
        if type(slots) is not int or not 1 <= slots <= 64 or platform not in ("systrap", "ptrace"):
            raise _unavailable("sandbox-config-invalid")
        self.slots, self.platform = slots, platform
        self.state_root, self.runsc, self.rootfs = Path(state_root), Path(runsc), Path(rootfs)
        self.cgroup_root, self.runsc_sha512 = Path(cgroup_root), runsc_sha512
        self.sidecars = dict(pins.GVISOR_SIDECARS if sidecars is None else sidecars)
        self.tools = tools
        self._lock = threading.Lock()
        self._owners = set()
        self._running = 0

    # Availability ----------------------------------------------------------

    def check(self):
        """Refuse unless the pinned runtime, root filesystem and cgroups are usable."""
        if os.geteuid() != 0:
            raise _unavailable("sandbox-supervisor-unprivileged")
        try:
            if _digest(self.runsc, "sha512") != self.runsc_sha512:
                raise _unavailable("sandbox-runsc-pin")
            for name, expected in self.sidecars.items():
                if _digest(self.runsc.parent / name, "sha512") != expected:
                    raise _unavailable("sandbox-runsc-pin")
            info = os.stat(self.rootfs, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise _unavailable("sandbox-rootfs-unsafe")
            for item in self.tools:
                if _digest(self.rootfs / item.path.lstrip("/"), "sha256") != item.sha256:
                    raise _unavailable("sandbox-rootfs-pin")
            controllers = (self.cgroup_root / "cgroup.controllers").read_text(encoding="ascii").split()
            enabled = (self.cgroup_root / "cgroup.subtree_control").read_text(encoding="ascii").split()
        except ValidationRefusal:
            raise
        except (OSError, ValueError):
            raise _unavailable("sandbox-runtime-missing") from None
        if any(name not in controllers or name not in enabled for name in CONTROLLERS):
            raise _unavailable("sandbox-cgroup-unavailable")
        return True

    def _state(self):
        try:
            os.makedirs(self.state_root, mode=0o700, exist_ok=True)
            info = os.stat(self.state_root, follow_symlinks=False)
        except OSError:
            raise _unavailable("sandbox-state-unavailable") from None
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise _unavailable("sandbox-state-unsafe")
        for name in ("jobs", "owners", "runsc"):
            path = self.state_root / name
            try:
                os.mkdir(path, 0o700)
            except FileExistsError:
                pass
            except OSError:
                raise _unavailable("sandbox-state-unavailable") from None
            info = os.stat(path, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                raise _unavailable("sandbox-state-unsafe")

    def _cgroup_parent(self):
        parent = self.cgroup_root / CGROUP_PARENT
        try:
            parent.mkdir(exist_ok=True)
            enabled = (parent / "cgroup.subtree_control").read_text(encoding="ascii").split()
            if any(name not in enabled for name in CONTROLLERS):
                _write(parent / "cgroup.subtree_control", " ".join("+" + name for name in CONTROLLERS))
        except OSError:
            raise _unavailable("sandbox-cgroup-unavailable") from None
        return parent

    # One job ---------------------------------------------------------------

    def run(self, job):
        if not isinstance(job, SandboxJob) or type(job.owner) is not str or not 1 <= len(job.owner) <= 128:
            raise _unavailable("sandbox-job-invalid")
        self.check()
        self._state()
        owner_key = hashlib.sha256(job.owner.encode("utf-8")).hexdigest()
        with self._lock:
            if owner_key in self._owners:
                raise _unavailable("sandbox-owner-busy")
            if self._running >= self.slots:
                raise _unavailable("sandbox-slots-exhausted")
            self._owners.add(owner_key)
            self._running += 1
        owner_fd = None
        try:
            # A lock file excludes other supervisor processes sharing this state root.
            owner_fd = os.open(self.state_root / "owners" / owner_key,
                               os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                fcntl.flock(owner_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise _unavailable("sandbox-owner-busy") from None
            return self._run(job)
        except OSError:
            raise _unavailable("sandbox-state-unavailable") from None
        finally:
            if owner_fd is not None:
                os.close(owner_fd)
            with self._lock:
                self._owners.discard(owner_key)
                self._running -= 1

    def _run(self, job):
        job_id = secrets.token_hex(JOB_ID_BYTES)
        directory = self.state_root / "jobs" / job_id
        cgroup = None
        created = False
        try:
            os.mkdir(directory, 0o700)
            created = True
            held = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                bundle = self._prepare(job, job_id, directory)
                cgroup = self._cgroup(job_id)
                self._same(held, directory)
                result = self._execute(job, job_id, bundle, cgroup)
                self._same(held, directory)
                return result
            finally:
                os.close(held)
        except ValidationRefusal:
            raise
        except OSError:
            raise _unavailable("sandbox-setup-failed") from None
        finally:
            self._cleanup(job_id, directory if created else None, cgroup)

    @staticmethod
    def _same(held, directory):
        named = os.stat(directory, follow_symlinks=False)
        actual = os.fstat(held)
        if (named.st_dev, named.st_ino) != (actual.st_dev, actual.st_ino) or not stat.S_ISDIR(named.st_mode):
            raise _unavailable("sandbox-state-changed")

    def _prepare(self, job, job_id, directory):
        if job.input_fd is not None:
            self._copy_input(job, directory / "input.zip")
        else:
            fd = os.open(directory / "input.zip", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
            os.close(fd)
        if type(job.trust) is not bytes or len(job.trust) > 1_048_576:
            raise _unavailable("sandbox-job-invalid")
        fd = os.open(directory / "trust.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
        with os.fdopen(fd, "wb") as stream:
            stream.write(job.trust)
        bundle = directory / "bundle"
        os.mkdir(bundle, 0o700)
        config = self.oci_config(job, job_id, directory)
        fd = os.open(bundle / "config.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, "wb") as stream:
            stream.write(json.dumps(config, sort_keys=True).encode())
        return bundle

    @staticmethod
    def _copy_input(job, target):
        """Copy the caller's held descriptor; a path is never reopened (Skills #1648)."""
        if type(job.input_fd) is not int or not stat.S_ISREG(os.fstat(job.input_fd).st_mode):
            raise _unavailable("sandbox-input-kind")
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o444)
        hasher, count = hashlib.sha256(), 0
        try:
            while chunk := os.pread(job.input_fd, 1024 * 1024, count):
                count += len(chunk)
                if job.input_length is not None and count > job.input_length:
                    raise _unavailable("sandbox-input-changed")
                hasher.update(chunk)
                view = memoryview(chunk)
                while view:
                    view = view[os.write(out, view):]
            os.fsync(out)
        finally:
            os.close(out)
        if ((job.input_length is not None and count != job.input_length)
                or (job.input_sha256 is not None and hasher.hexdigest() != job.input_sha256)):
            raise _unavailable("sandbox-input-changed")

    def oci_config(self, job, job_id, directory):
        """The OCI runtime spec for one job. Pure: it reads nothing from disk."""
        policy = self.policy
        environment = []
        for name, value in job.environment:
            if name not in ENVIRONMENT_NAMES or "\x00" in value or "=" in name:
                raise _unavailable("sandbox-environment-refused")
            environment.append(name + "=" + value)
        mounts = [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": pins.SANDBOX_JOB, "type": "tmpfs", "source": "tmpfs",
             "options": ["size=%d" % policy.scratch_bytes, "mode=0700", "uid=%d" % pins.SANDBOX_UID,
                         "gid=%d" % pins.SANDBOX_UID, "nosuid", "nodev", "noexec"]},
            # Without this mount runsc adds a world-writable, executable tmpfs at /tmp that
            # the scratch size does not bound. Native Git writes temporary files there, so
            # /tmp stays writable, but private to the job user, sized and noexec like /job.
            {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
             "options": ["size=%d" % policy.scratch_bytes, "mode=0700", "uid=%d" % pins.SANDBOX_UID,
                         "gid=%d" % pins.SANDBOX_UID, "nosuid", "nodev", "noexec"]},
            {"destination": pins.SANDBOX_INPUT, "type": "bind", "source": str(directory / "input.zip"),
             "options": ["bind", "ro", "nosuid", "nodev", "noexec"]},
            {"destination": pins.SANDBOX_TRUST, "type": "bind", "source": str(directory / "trust.json"),
             "options": ["bind", "ro", "nosuid", "nodev", "noexec"]},
        ]
        for source, destination in job.binds:
            mounts.append({"destination": destination, "type": "bind", "source": str(source),
                           "options": ["rbind", "ro", "nosuid", "nodev"]})
        return {
            "ociVersion": "1.0.2",
            "process": {
                "user": {"uid": pins.SANDBOX_UID, "gid": pins.SANDBOX_UID},
                "args": list(job.argv), "env": environment, "cwd": pins.SANDBOX_JOB,
                "terminal": False, "noNewPrivileges": True,
                "capabilities": {key: [] for key in ("bounding", "effective", "permitted", "inheritable",
                                                     "ambient")},
                "rlimits": [
                    {"type": "RLIMIT_CPU", "soft": policy.cpu_seconds, "hard": policy.cpu_seconds},
                    {"type": "RLIMIT_NOFILE", "soft": policy.open_files, "hard": policy.open_files},
                    {"type": "RLIMIT_CORE", "soft": 0, "hard": 0},
                    {"type": "RLIMIT_FSIZE", "soft": policy.scratch_bytes, "hard": policy.scratch_bytes},
                ],
            },
            "root": {"path": str(self.rootfs), "readonly": True},
            "hostname": "validator",
            "mounts": mounts,
            "linux": {
                "namespaces": [{"type": name} for name in ("pid", "network", "ipc", "uts", "mount")],
                "cgroupsPath": "/" + CGROUP_PARENT + "/" + job_id,
                "resources": {
                    "memory": {"limit": policy.memory_bytes, "swap": policy.memory_bytes},
                    "cpu": {"quota": policy.cpus * CPU_PERIOD_US, "period": CPU_PERIOD_US},
                    "pids": {"limit": policy.processes},
                },
            },
        }

    def _cgroup(self, job_id):
        parent = self._cgroup_parent()
        path = parent / job_id
        try:
            path.mkdir()
            _write(path / "memory.max", str(self.policy.memory_bytes))
            _write(path / "memory.swap.max", "0")
            _write(path / "memory.oom.group", "1")
            _write(path / "pids.max", str(self.policy.processes))
            _write(path / "cpu.max", "%d %d" % (self.policy.cpus * CPU_PERIOD_US, CPU_PERIOD_US))
        except OSError:
            raise _unavailable("sandbox-cgroup-unavailable") from None
        return path

    def _runsc(self, *arguments):
        return [str(self.runsc), "--root", str(self.state_root / "runsc"), "--network=none",
                "--platform=" + self.platform, "--host-uds=none", "--host-fifo=none", *arguments]

    def _execute(self, job, job_id, bundle, cgroup):
        policy = self.policy
        started = time.monotonic()
        wall = policy.wall_seconds
        if type(job.wall_seconds) is int and 1 <= job.wall_seconds < wall:
            wall = job.wall_seconds
        deadline = started + wall
        process = subprocess.Popen(self._runsc("run", "--bundle", str(bundle), job_id),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={"PATH": "/usr/bin:/bin"}, cwd="/", close_fds=True,
                                   start_new_session=True)
        stdout, stderr, stderr_bytes = bytearray(), hashlib.sha256(), 0
        killed = None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map():
                    for key, _ in selector.select(POLL_SECONDS):
                        chunk = os.read(key.fileobj.fileno(), 65_536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        elif key.data == "stdout":
                            stdout.extend(chunk)
                            if len(stdout) > policy.stdout_bytes and killed is None:
                                killed = "stdout-limit"
                        else:
                            stderr.update(chunk)
                            stderr_bytes += len(chunk)
                            if stderr_bytes > policy.stderr_bytes and killed is None:
                                killed = "stderr-limit"
                    if killed is None:
                        usage = _read_int(cgroup / "cpu.stat", "usage_usec")
                        if usage is not None and usage > policy.cpu_seconds * 1_000_000:
                            killed = "cpu-limit"
                        elif time.monotonic() >= deadline:
                            killed = "wall-limit"
                    if killed is not None:
                        self._kill(cgroup, job_id)
                        if len(stdout) > policy.stdout_bytes:
                            del stdout[policy.stdout_bytes + 1:]
                    if killed is not None and time.monotonic() > deadline + KILL_GRACE_SECONDS:
                        break
            exit_code = process.wait(timeout=KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            killed = killed or "wall-limit"
            exit_code = None
        finally:
            if process.poll() is None:
                self._kill(cgroup, job_id)
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                process.wait()
            process.stdout.close()
            process.stderr.close()
        events = {"oom_kill": _read_int(cgroup / "memory.events", "oom_kill") or 0}
        if killed is None and events["oom_kill"]:
            killed = "memory-limit"
        resources = {
            "wall_ms": int((time.monotonic() - started) * 1000),
            "cpu_us": _read_int(cgroup / "cpu.stat", "usage_usec") or 0,
            "memory_peak_bytes": _read_int(cgroup / "memory.peak") or 0,
            "pids_peak": _read_int(cgroup / "pids.peak") or 0,
            "oom_kills": events["oom_kill"],
        }
        LOGGER.info("sandbox-resources", extra={"event": "sandbox-resources", "job": job_id,
                                                "kind": "memory_peak", "bytes": resources["memory_peak_bytes"]})
        LOGGER.info("sandbox-finished", extra={"event": "sandbox-finished", "job": job_id,
                                               "duration_us": resources["wall_ms"] * 1000,
                                               "reason": killed or "exited", "count": resources["pids_peak"]})
        return SandboxRun(job_id, exit_code, bytes(stdout), stderr.hexdigest(), stderr_bytes, killed, resources)

    def _kill(self, cgroup, job_id):
        try:
            _write(cgroup / "cgroup.kill", "1")
        except OSError:
            pass
        try:
            subprocess.run(self._runsc("kill", "--all", job_id, "KILL"), stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"},
                           timeout=KILL_GRACE_SECONDS, check=False)
        except (OSError, subprocess.SubprocessError):
            # The cgroup kill above already stopped every task; this only tidies runsc state.
            pass

    def _cleanup(self, job_id, directory, cgroup):
        failures = []
        try:
            subprocess.run(self._runsc("delete", "--force", job_id), stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"},
                           timeout=KILL_GRACE_SECONDS, check=False)
        except (OSError, subprocess.SubprocessError):
            failures.append("runsc")
        if cgroup is not None:
            try:
                _write(cgroup / "cgroup.kill", "1")
            except OSError:
                pass
            for _ in range(200):
                try:
                    cgroup.rmdir()
                    break
                except FileNotFoundError:
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                failures.append("cgroup")
        if directory is not None:
            try:
                shutil.rmtree(directory)
            except OSError:
                failures.append("state")
        for kind in failures:
            LOGGER.error("sandbox-cleanup-failed", extra={"event": "sandbox-cleanup-failed", "job": job_id,
                                                          "kind": kind})


def leftovers(state_root=STATE_ROOT, cgroup_root=CGROUP_ROOT):
    """Job state directories and cgroups still present; an operator's first check."""
    jobs = sorted(os.listdir(Path(state_root) / "jobs")) if (Path(state_root) / "jobs").is_dir() else []
    parent = Path(cgroup_root) / CGROUP_PARENT
    groups = sorted(entry.name for entry in os.scandir(parent) if entry.is_dir()) if parent.is_dir() else []
    return {"jobs": jobs, "cgroups": groups}
