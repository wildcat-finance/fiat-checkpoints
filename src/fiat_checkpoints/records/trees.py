"""Load the pinned authority and native trees read-only, after verifying their bytes.

`protocol.lock.json` is the released consumer lock with this service's
authority commit. `protocol.trees.json` lists every authority file by SHA-256
and the native tree by the release's profile digest. The authority tree is
hashed and enumerated here before any of its code is imported; afterwards the
released `lock` check and the released native profile decide the rest. No
tree is fetched, discovered from a record or read through a symlink.
"""

from dataclasses import dataclass
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import threading
from types import SimpleNamespace

from fiat_checkpoints.records.refusals import RecordRefusal, from_protocol


REPOSITORY = Path(__file__).resolve().parents[3]
DEFAULT_TREES = Path("/opt/fiat-checkpoints/protocol")
LOCK_NAME = "protocol.lock.json"
TREES_NAME = "protocol.trees.json"
TREES_SCHEMA = "fiat-checkpoints-protocol-trees/v1"
LOCK_MAX = 16_384
TREES_MAX = 65_536
FILE_MAX = 67_108_864
TREE_FILES_MAX = 4_096
PACKAGE = "plugins/hexaemeron/skills/fiat/scripts/checkpoint_authority"
NATIVE_PROFILE = "plugins/hexaemeron/skills/fiat/checkpoint-authority/native-profile.json"
MODULES = ("canonical", "schema", "records", "signatures", "trust", "native_io",
           "native_records", "native", "parents", "release", "verifier")
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
PATH = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
_LOADED = {}
_IMPORT_LOCK = threading.Lock()


@dataclass(frozen=True)
class ProtocolRelease:
    """A verified release: the lock-check event, both roots and the imported library."""
    authority_root: Path
    native_root: Path
    lock_sha256: str
    trees_sha256: str
    lock_check: dict
    library: SimpleNamespace

    @property
    def refusal_type(self):
        return self.library.canonical.Refusal


def _read(path, maximum, missing):
    """Read one bounded regular file with one link, without following a final symlink."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise RecordRefusal(missing) from None
    except OSError:
        raise RecordRefusal("protocol-file-unsafe") from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise RecordRefusal("protocol-file-unsafe")
        chunks, size = [], 0
        while chunk := os.read(descriptor, 1_048_576):
            size += len(chunk)
            if size > maximum:
                raise RecordRefusal("protocol-file-unsafe")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except OSError:
        raise RecordRefusal("protocol-file-unsafe") from None
    finally:
        os.close(descriptor)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if identity(before) != identity(after) or size != before.st_size:
        raise RecordRefusal("protocol-file-changed")
    return b"".join(chunks)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject(_value):
    raise ValueError("non-integer number")


def _json(raw, code):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_float=_reject, parse_constant=_reject)
    except (UnicodeError, ValueError, RecursionError):
        raise RecordRefusal(code) from None


def _closed(value, fields, code):
    if type(value) is not dict or set(value) != set(fields):
        raise RecordRefusal(code)
    return value


def _manifest(raw):
    """Validate the closed tree manifest; unknown fields and unsafe paths refuse."""
    code = "protocol-trees-malformed"
    value = _closed(_json(raw, code), ("schema", "authority", "native"), code)
    authority = _closed(value["authority"], ("source_commit", "files"), code)
    native = _closed(value["native"], ("source_commit", "profile_sha256", "files"), code)
    if value["schema"] != TREES_SCHEMA:
        raise RecordRefusal(code)
    for commit in (authority["source_commit"], native["source_commit"]):
        if type(commit) is not str or COMMIT.fullmatch(commit) is None:
            raise RecordRefusal(code)
    if type(native["profile_sha256"]) is not str or SHA256.fullmatch(native["profile_sha256"]) is None:
        raise RecordRefusal(code)
    if type(native["files"]) is not int or not 1 <= native["files"] <= TREE_FILES_MAX:
        raise RecordRefusal(code)
    rows = authority["files"]
    if type(rows) is not list or not 1 <= len(rows) <= TREE_FILES_MAX:
        raise RecordRefusal(code)
    for row in rows:
        _closed(row, ("path", "sha256"), code)
        if (type(row["path"]) is not str or PATH.fullmatch(row["path"]) is None
                or any(part in (".", "..") for part in row["path"].split("/"))
                or type(row["sha256"]) is not str or SHA256.fullmatch(row["sha256"]) is None):
            raise RecordRefusal(code)
    paths = [row["path"] for row in rows]
    if paths != sorted(set(paths)):
        raise RecordRefusal(code)
    return value


def _directory(path):
    """A tree root must sit at its own real path, as a directory this process cannot write."""
    if not path.is_absolute() or os.path.realpath(path) != str(path):
        raise RecordRefusal("protocol-tree-relocated")
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        raise RecordRefusal("protocol-tree-missing") from None
    except OSError:
        raise RecordRefusal("protocol-tree-unsafe") from None
    if not stat.S_ISDIR(mode):
        raise RecordRefusal("protocol-tree-unsafe")
    if os.access(path, os.W_OK):
        raise RecordRefusal("protocol-tree-writable")


def _inventory(root):
    """Every regular file below root; a link, special file or writable entry refuses."""
    found = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    if entry.is_symlink():
                        raise RecordRefusal("protocol-tree-unsafe")
                    if os.access(path, os.W_OK, follow_symlinks=False):
                        raise RecordRefusal("protocol-tree-writable")
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        found.add(path.relative_to(root).as_posix())
                    else:
                        raise RecordRefusal("protocol-tree-unsafe")
                    if len(found) + len(pending) > TREE_FILES_MAX * 2:
                        raise RecordRefusal("protocol-tree-extra")
        except OSError:
            raise RecordRefusal("protocol-tree-unsafe") from None
    return found


def _compare(found, expected):
    if found - expected:
        raise RecordRefusal("protocol-tree-extra")
    if expected - found:
        raise RecordRefusal("protocol-tree-missing")


def _verify_authority(root, manifest):
    rows = manifest["authority"]["files"]
    _compare(_inventory(root), {row["path"] for row in rows})
    for row in rows:
        data = _read(root / row["path"], FILE_MAX, "protocol-tree-missing")
        if hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise RecordRefusal("protocol-tree-drift")


def _import(root, trees_sha256):
    """Import the verified package under a private name; bytecode is neither read nor written."""
    key = (str(root), trees_sha256)
    with _IMPORT_LOCK:
        if key in _LOADED:
            return _LOADED[key]
        name = "_fiat_checkpoints_authority_" + hashlib.sha256(repr(key).encode()).hexdigest()[:16]
        package = root / PACKAGE
        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            spec = importlib.util.spec_from_file_location(
                name, package / "__init__.py", submodule_search_locations=[str(package)])
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            library = SimpleNamespace(**{part: importlib.import_module(name + "." + part) for part in MODULES})
        except Exception:
            for loaded in [item for item in sys.modules if item == name or item.startswith(name + ".")]:
                del sys.modules[loaded]
            raise RecordRefusal("protocol-import-failed") from None
        finally:
            sys.dont_write_bytecode = previous
        _LOADED[key] = library
        return library


def _verify_native(root, manifest, library, lock_check):
    """Hash the native tree against the released profile the lock check just bound."""
    Refusal = library.canonical.Refusal
    expected = manifest["native"]["profile_sha256"]
    try:
        profile_bytes = library.native_io.read(root / NATIVE_PROFILE, 65_536)
    except (Refusal, OSError):
        raise RecordRefusal("protocol-tree-drift") from None
    if (hashlib.sha256(profile_bytes).hexdigest() != expected
            or lock_check["native"]["profile_sha256"] != expected):
        raise RecordRefusal("protocol-tree-drift")
    try:
        profile = library.canonical.decode(profile_bytes, limit=65_536)
        rows = profile["files"]
    except (Refusal, TypeError, KeyError):
        raise RecordRefusal("protocol-tree-drift") from None
    if profile["source_commit"] != manifest["native"]["source_commit"] or len(rows) != manifest["native"]["files"]:
        raise RecordRefusal("protocol-tree-commit")
    return rows


def _verify_native_files(root, rows, library):
    Refusal = library.canonical.Refusal
    _compare(_inventory(root), {row["path"] for row in rows})
    for row in rows:
        try:
            observed = library.native_io.hash_file(root / row["path"])[0]
        except Refusal as error:
            raise from_protocol("protocol-tree-unsafe", error) from None
        except OSError:
            raise RecordRefusal("protocol-tree-unsafe") from None
        if observed != row["sha256"]:
            raise RecordRefusal("protocol-tree-drift")


def load_release(root=REPOSITORY, trees=DEFAULT_TREES):
    """Return a verified release or raise a RecordRefusal with a fixed code.

    Order matters: the lock and manifest are read, then the authority bytes are
    checked before import, then the released `lock` check and native profile run.
    """
    root, trees = Path(root), Path(trees)
    lock_bytes = _read(root / LOCK_NAME, LOCK_MAX, "protocol-pin-missing")
    lock = _json(lock_bytes, "protocol-lock-malformed")
    try:
        commits = (lock["authority"]["source_commit"], lock["native"]["source_commit"])
    except (TypeError, KeyError):
        raise RecordRefusal("protocol-lock-malformed") from None
    trees_bytes = _read(root / TREES_NAME, TREES_MAX, "protocol-trees-missing")
    manifest = _manifest(trees_bytes)
    if commits != (manifest["authority"]["source_commit"], manifest["native"]["source_commit"]):
        raise RecordRefusal("protocol-tree-commit")
    authority, native = trees / "authority", trees / "native"
    for directory in (trees, authority, native):
        _directory(directory)
    _verify_authority(authority, manifest)
    trees_sha256 = hashlib.sha256(trees_bytes).hexdigest()
    library = _import(authority, trees_sha256)
    Refusal = library.canonical.Refusal
    try:
        lock_check = library.release.lock_check(
            lock_bytes, authority, source_commit=manifest["authority"]["source_commit"])
    except Refusal as error:
        raise from_protocol("protocol-lock-refused", error) from None
    except (OSError, ValueError, TypeError, KeyError):
        raise RecordRefusal("protocol-lock-refused") from None
    if lock_check["tools"]["python"] != platform.python_version():
        raise RecordRefusal("protocol-python-mismatch")
    rows = _verify_native(authority, manifest, library, lock_check)
    _verify_native_files(native, rows, library)
    return ProtocolRelease(authority, native, hashlib.sha256(lock_bytes).hexdigest(),
                           trees_sha256, lock_check, library)
