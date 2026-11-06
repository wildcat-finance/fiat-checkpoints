"""The program a job runs inside the gVisor sandbox; it trusts only its mounts.

It reads one canonical job document from the read-only trust mount, verifies
the read-only protocol trees through the service loader, and runs the
released `verify_native` on the read-only sealed input with the private tmpfs
as its job root. It writes exactly one bounded JSON line to stdout: the
native result, or a refusal carrying the adapter's code and stage. Native
stdout and stderr stay in the job's tmpfs, which the supervisor destroys; a
command's stderr becomes a protocol code only when all of it is one class the
release lists for that stage (Skills #1647). No shell, no archive field and no
environment value from outside reaches a command line.
"""

import importlib
import json
import os
from pathlib import Path
import sys
import time


SCHEMA_JOB = "fiat-checkpoints-sandbox-job/v1"
SCHEMA_RESULT = "fiat-checkpoints-sandbox-result/v1"
JOB_FIELDS = frozenset({"schema", "job_id", "mode", "request", "approval", "tools", "case"})
MODES = ("validate", "inspect-case")
CAPABILITIES = "plugins/hexaemeron/skills/fiat/checkpoint-authority/native-capabilities.json"
INSPECT_SECONDS = 120
# A runner-derived reason, never a protocol code: see `_signer_outside_keyring`.
COVERAGE_SIGNER_UNAPPROVED = "coverage-signer-unapproved"


def _emit(job_id, status, *, native_result=None, refusal=None):
    library = _LIBRARY
    value = {"schema": SCHEMA_RESULT, "job_id": job_id, "status": status,
             "native_result": None, "native_result_sha256": None, "refusal": refusal}
    if native_result is not None:
        value["native_result"] = library.canonical.decode(native_result, require_canonical=True)
        value["native_result_sha256"] = library.canonical.digest(native_result)
    sys.stdout.buffer.write(library.canonical.canonical(value) + b"\n")
    sys.stdout.flush()


_LIBRARY = None


def _load(service, trees):
    global _LIBRARY
    sys.path.insert(0, str(Path(service) / "src"))
    trees_module = importlib.import_module("fiat_checkpoints.records.trees")
    release = trees_module.load_release(service, trees)
    _LIBRARY = release.library
    return release


def _job(library, path):
    payload = library.native_io.read(Path(path), 1_048_576)
    value = library.canonical.decode(payload, require_canonical=True)
    if (type(value) is not dict or set(value) != JOB_FIELDS or value["schema"] != SCHEMA_JOB
            or value["mode"] not in MODES or type(value["job_id"]) is not str):
        raise library.canonical.Refusal("job-document", "native")
    return value


NATIVE_RUNTIME = Path("/opt/fiat-checkpoints/native-runtime")
NATIVE_EXTRA = {"scripts/run_observation.py": "712f2afc40f7703cc64a92cd850559684a28f1b98e3241652a67ac6b48124d40"}


def _runtime(library, release):
    """The native runtime root holds exactly the profile files and the pinned extra file."""
    profile = library.canonical.decode(library.native_io.read(
        release.authority_root / "plugins/hexaemeron/skills/fiat/checkpoint-authority/native-profile.json", 65536))
    expected = {row["path"] for row in profile["files"]} | set(NATIVE_EXTRA)
    found = set()
    for current, directories, files in os.walk(NATIVE_RUNTIME, followlinks=False):
        directories.sort()
        for name in files:
            found.add(os.path.relpath(os.path.join(current, name), NATIVE_RUNTIME))
    if found != expected:
        raise library.canonical.Refusal("native-runtime-inventory", "native")
    for path, sha256 in NATIVE_EXTRA.items():
        if library.native_io.hash_file(NATIVE_RUNTIME / path)[0] != sha256:
            raise library.canonical.Refusal("native-runtime-pin", "native")
    return NATIVE_RUNTIME


def _pin(release, library, tools):
    native_tools = tuple(library.native_io.NativeTool(row["name"], row["path"], row["sha256"])
                         for row in tools)
    # NativePin.check hashes every profile file under this root on every use.
    return library.native.NativePin(_runtime(library, release), native_tools)


def _protocol_code(library, release, attempt_root, stage):
    """The stage's stderr as one allowlisted class, or None. Nothing else leaves."""
    if stage not in ("inspect", "restore", "verify", "identity"):
        return None
    try:
        capabilities = library.canonical.decode(
            library.native_io.read(release.authority_root / CAPABILITIES, 1_048_576))
        allowed = {row["name"] for row in capabilities["refusals"] if stage in row["stages"]}
        data = library.native_io.read(attempt_root / (stage + ".stderr"), 16_384)
    except Exception:
        return None
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        return None
    name = data[:-1].decode("ascii", errors="replace")
    return name if name in allowed else None


def _signer_outside_keyring(library, attempt_root, approval):
    """Whether the pinned inspect saw a commit signer the injected keys do not hold.

    The keyring holds exactly the approved history's keys, so `git verify-commit`
    cannot pass for such a commit and the coverage stage fails as a command; had
    it passed, the released check would refuse the fingerprint as unapproved.
    Only the structured inspect output is read, never a command's diagnostic.
    """
    try:
        inspected = library.native_records.inspect_result(library.canonical.decode(
            library.native_io.read(attempt_root / "inspect.stdout", 1_048_576)))
        approved = {row["key"]["fingerprint"] for row in approval["history"]}
        return any(row["fingerprint"] not in approved for row in inspected["signatures"])
    except Exception:
        return False


def _validate(release, library, job, root):
    native = library.native
    request = native.NativeInput(**job["request"])
    approval = job["approval"]
    coverage = importlib.import_module(native.__package__ + ".coverage")
    approved = coverage.ApprovedRun(approval["anchor_sha256"], approval["initial_base"],
                                    approval["start_commit"],
                                    tuple(library.canonical.canonical(row) for row in approval["history"]))
    pin = _pin(release, library, job["tools"])
    try:
        result = native.verify_native(Path("/input/checkpoint.zip"), job_root=root, pin=pin,
                                      request=request, approval=approved)
    except library.canonical.Refusal as refusal:
        code = _protocol_code(library, release, root / request.attempt_id, refusal.stage)
        if (refusal.code == "native-command-failed" and refusal.stage == "coverage"
                and _signer_outside_keyring(library, root / request.attempt_id, approval)):
            _emit(job["job_id"], "refused",
                  refusal={"code": COVERAGE_SIGNER_UNAPPROVED, "stage": "coverage", "protocol_code": None})
            return
        _emit(job["job_id"], "refused",
              refusal={"code": refusal.code, "stage": refusal.stage, "protocol_code": code})
        return
    _emit(job["job_id"], "complete", native_result=result.payload)


def _inspect_case(release, library, job, root):
    """Run only the pinned `checkpoint inspect`, for a declared hostile specimen."""
    io = library.native_io
    case, request = job["case"], job["request"]
    pin = _pin(release, library, job["tools"])
    pin.check()
    work = root / "case"
    work.mkdir(mode=0o700)
    for name in ("home", "tmp", "scratch"):
        (work / name).mkdir(mode=0o700)
    specimen = work / "specimen.zip"
    io.copy_archive(Path("/input/checkpoint.zip"), specimen, request["outer_sha256"])
    if case["sidecar"] is not None:
        io.create(work / "specimen.zip.sha256", case["sidecar"].encode("ascii"))
    environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(work / "home"),
                   "GNUPGHOME": str(work / "home"), "TMPDIR": str(work / "tmp"), "LC_ALL": "C",
                   "LANG": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_TERMINAL_PROMPT": "0"}
    controller = library.native_records.CONTROLLER
    result = io.execute(pin.tool("python"),
                        ["-I", str(pin.source_root / controller), "checkpoint", "inspect",
                         "--archive", str(specimen), "--sha256", case["sha256"],
                         "--scratch", str(work / "scratch")],
                        work, environment, stage="inspect", attempt_id=request["attempt_id"],
                        input_sha256=request["outer_sha256"],
                        deadline=time.monotonic() + INSPECT_SECONDS)
    if result.exit == 0:
        _emit(job["job_id"], "complete")
        return
    io.create(work / "inspect.stderr", result.stderr)
    code = _protocol_code(library, release, work, "inspect")
    _emit(job["job_id"], "refused",
          refusal={"code": "native-command-failed", "stage": "inspect", "protocol_code": code})


def main(argv):
    job_id = None
    try:
        service, trees, trust, job_root = argv
        release = _load(service, trees)
        library = release.library
        job = _job(library, trust)
        job_id = job["job_id"]
        root = Path(job_root)
        if job["mode"] == "validate":
            _validate(release, library, job, root)
        else:
            _inspect_case(release, library, job, root)
    except BaseException as error:
        # The type name and text never leave: either may carry archive bytes.
        library = _LIBRARY
        if library is not None and isinstance(error, library.canonical.Refusal):
            _emit(job_id, "refused", refusal={"code": error.code, "stage": error.stage, "protocol_code": None})
        else:
            sys.stdout.write(json.dumps({"job_id": job_id, "native_result": None, "native_result_sha256": None,
                                         "refusal": None, "schema": SCHEMA_RESULT, "status": "error"},
                                        ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main(sys.argv[1:]))
