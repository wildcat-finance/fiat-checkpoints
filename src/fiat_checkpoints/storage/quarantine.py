"""The quarantine store: conditional create, full read, delete and lifecycle listing.

Only the upload gateway writes quarantine, and only to a fresh attempt key; a
key that already exists is never overwritten. Nothing a store reports about
an object, whether metadata, a length or an ETag, stands in for reading the
bytes back: `read_back` counts and hashes every byte. The quarantine sweeper
deletes, and nothing else does.

`DirectoryQuarantine` is the local-profile store: one directory opened once,
each object an exclusive file created without following links and made
read-only once complete. `R2Quarantine` is the live adapter's place; it
refuses to start until issue #863 supplies and proves its credentials.
See adr/seal-uploads-in-bounded-quarantine.
"""

import errno
import hashlib
import os
import re
import stat
import time

from fiat_checkpoints.api.app import StartupRefusal, production_refusals
from fiat_checkpoints.config import Settings
from fiat_checkpoints.records.trees import DEFAULT_TREES, REPOSITORY


CHUNK_BYTES = 1_048_576
KEY = re.compile(r"quarantine/([0-9a-f]{32})/([0-9]{2})-([0-9a-f]{32})")
FILE_NAME = re.compile(r"([0-9a-f]{32})\.([0-9]{2})\.([0-9a-f]{32})")
FULL = frozenset({errno.ENOSPC, errno.EDQUOT, errno.EFBIG})
READ_BACK_ATTEMPTS = 5
READ_BACK_PAUSE_SECONDS = 0.05


class QuarantineError(Exception):
    """One fixed code: `quarantine_conflict`, `quarantine_missing`, `quarantine_full` or `quarantine_unavailable`."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class QuarantineStore:
    """The operations the gateway and sweeper need; a store grants no list or read to contributors."""

    def put_new(self, key, source_fd, size):
        """Create `key` with exactly `size` bytes read from `source_fd` at offset 0, or refuse if it exists."""
        raise NotImplementedError

    def read(self, key, chunk_bytes=CHUNK_BYTES):
        """Yield the object's bytes in chunks of at most `chunk_bytes`."""
        raise NotImplementedError

    def delete(self, key):
        """Remove `key`; a key already gone is not an error."""
        raise NotImplementedError

    def older_than(self, cutoff_epoch_seconds, limit):
        """Keys of objects created before the cutoff, at most `limit`, for the 24-hour lifecycle."""
        raise NotImplementedError


def _file_name(key):
    match = KEY.fullmatch(key) if type(key) is str else None
    if match is None:
        raise QuarantineError("quarantine_unavailable")
    return "{}.{}.{}".format(*match.groups())


def _key(name):
    match = FILE_NAME.fullmatch(name)
    return None if match is None else "quarantine/{}/{}-{}".format(*match.groups())


def _write_all(descriptor, view):
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError(errno.EIO, "short-write")
        view = view[written:]


class DirectoryQuarantine(QuarantineStore):
    """Quarantine objects as read-only files in one directory held open by descriptor.

    Every name is derived from a checked key, and every open uses the held
    directory with `O_NOFOLLOW`, so neither a crafted key nor a link planted
    in the directory redirects a write or a read.
    """

    def __init__(self, directory):
        try:
            self._directory = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise StartupRefusal(("quarantine-unavailable",)) from None
        status = os.fstat(self._directory)
        if not stat.S_ISDIR(status.st_mode) or status.st_mode & 0o022:
            os.close(self._directory)
            raise StartupRefusal(("quarantine-unavailable",))

    def close(self):
        if self._directory is not None:
            os.close(self._directory)
            self._directory = None

    def _open_new(self, name):
        try:
            return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                           dir_fd=self._directory)
        except FileExistsError:
            raise QuarantineError("quarantine_conflict") from None
        except OSError as error:
            raise QuarantineError("quarantine_full" if error.errno in FULL else "quarantine_unavailable") from None

    def _copy(self, source_fd, target, size):
        offset = 0
        while offset < size:
            chunk = os.pread(source_fd, min(CHUNK_BYTES, size - offset), offset)
            if not chunk:
                raise OSError(errno.EIO, "source-short")
            self._write(target, chunk)
            offset += len(chunk)

    def _write(self, target, chunk):
        _write_all(target, memoryview(chunk))

    def put_new(self, key, source_fd, size):
        name = _file_name(key)
        target = self._open_new(name)
        try:
            self._copy(source_fd, target, size)
            os.fsync(target)
            os.fchmod(target, 0o400)
        except OSError as error:
            os.close(target)
            try:
                self._remove(name)
            except OSError:
                pass
            raise QuarantineError("quarantine_full" if error.errno in FULL else "quarantine_unavailable") from None
        try:
            os.close(target)
        except OSError:
            raise QuarantineError("quarantine_unavailable") from None

    def read(self, key, chunk_bytes=CHUNK_BYTES):
        name = _file_name(key)
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=self._directory)
        except FileNotFoundError:
            raise QuarantineError("quarantine_missing") from None
        except OSError:
            # A link planted at the object's name fails here with ELOOP.
            raise QuarantineError("quarantine_unavailable") from None
        try:
            try:
                regular = stat.S_ISREG(os.fstat(descriptor).st_mode)
            except OSError:
                regular = False
            if not regular:
                raise QuarantineError("quarantine_unavailable")
            while True:
                try:
                    chunk = os.read(descriptor, chunk_bytes)
                except OSError:
                    raise QuarantineError("quarantine_unavailable") from None
                if not chunk:
                    return
                yield chunk
        finally:
            os.close(descriptor)

    def _remove(self, name):
        try:
            os.unlink(name, dir_fd=self._directory)
        except FileNotFoundError:
            pass

    def delete(self, key):
        try:
            self._remove(_file_name(key))
        except OSError:
            raise QuarantineError("quarantine_unavailable") from None

    def older_than(self, cutoff_epoch_seconds, limit):
        found = []
        try:
            with os.scandir(self._directory) as entries:
                for entry in entries:
                    key = _key(entry.name)
                    if key is None:
                        continue
                    status = entry.stat(follow_symlinks=False)
                    if status.st_mtime < cutoff_epoch_seconds:
                        found.append(key)
                        if len(found) >= limit:
                            break
        except OSError:
            raise QuarantineError("quarantine_unavailable") from None
        return found


class R2Quarantine(QuarantineStore):
    """The live R2 quarantine adapter. It refuses to start: no credential or account is provisioned here.

    Production refuses with the same startup codes as every other role, and
    a local profile refuses as `scaffold-only`; issue #863 owns the adapter
    and its live proof.
    """

    def __init__(self, settings, root=REPOSITORY, trees=DEFAULT_TREES):
        if not isinstance(settings, Settings):
            raise StartupRefusal(("configuration-fields",))
        raise StartupRefusal(production_refusals(settings, root, trees) or ("scaffold-only",))


def read_back(store, key, size, attempts=READ_BACK_ATTEMPTS, pause=READ_BACK_PAUSE_SECONDS, sleep=time.sleep):
    """Count and hash every byte of `key`, stopping one chunk past `size`.

    A store whose writes become visible late gets `attempts` reads, with a
    growing pause between them, before the object counts as missing. Returns
    the byte count and SHA-256 actually read.
    """
    for attempt in range(attempts):
        digest, count, chunks = hashlib.sha256(), 0, None
        try:
            chunks = store.read(key)
            for chunk in chunks:
                count += len(chunk)
                if count > size:
                    return count, None
                digest.update(chunk)
        except QuarantineError as error:
            if error.code != "quarantine_missing" or attempt == attempts - 1:
                raise
            sleep(pause * (attempt + 1))
            continue
        finally:
            # An early return leaves the reader open until it is closed here.
            getattr(chunks, "close", lambda: None)()
        return count, digest.hexdigest()
    raise QuarantineError("quarantine_missing")
