"""Bounded staging for the gateway, and the immutable job input the staging broker hands on.

`StagingArea` is one directory on the gateway host, opened once and used only
through that descriptor. Before a stream reads a byte it reserves its exact
declared size against the area's capacity, and the filesystem must still keep
`floor_bytes` free once every live stream has written its whole declared size.
A staged file is created exclusively, without following a link, and never
grows past its declared size; it is removed when its stream ends, however it
ends. Files left by a process that stopped are removed when the area opens
again and by `sweep`. One gateway process owns one area.

`stage_sealed` is the staging broker's read: the sealed quarantine object, by
its recorded key, copied into an exclusive read-only job file whose bytes are
counted and hashed against the recorded size and digest. The returned input
keeps its descriptor, so a later reader gets the bytes that were checked even
if the path is replaced. See adr/seal-uploads-in-bounded-quarantine.
"""

from dataclasses import dataclass, field
import errno
import hashlib
import hmac
import os
import re
import secrets
import stat
import threading

from fiat_checkpoints.api.app import StartupRefusal
from fiat_checkpoints.storage.quarantine import CHUNK_BYTES, FULL, QuarantineError


NAME = re.compile(r"[0-9a-f]{32}\.part")
JOB_NAME = re.compile(r"[0-9a-f]{32}\.input")


class StagingRefusal(Exception):
    """One fixed code: `staging_full`, `staging_unavailable`, `body_extra` or `staging_mismatch`."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _open_directory(directory):
    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise StartupRefusal(("staging-unavailable",)) from None
    status = os.fstat(descriptor)
    # Another local user who can write here could plant or swap entries.
    if not stat.S_ISDIR(status.st_mode) or status.st_mode & 0o022:
        os.close(descriptor)
        raise StartupRefusal(("staging-unavailable",))
    return descriptor


def _write_all(descriptor, data):
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError(errno.EIO, "short-write")
        view = view[written:]


class StagingArea:
    """Reserve, create and remove staged files in one directory held by descriptor."""

    def __init__(self, directory, *, capacity_bytes, floor_bytes=0, free_bytes=None):
        if type(capacity_bytes) is not int or capacity_bytes < 1 or type(floor_bytes) is not int or floor_bytes < 0:
            raise StartupRefusal(("configuration-value",))
        self._directory = _open_directory(directory)
        self.capacity_bytes = capacity_bytes
        self.floor_bytes = floor_bytes
        self._free_bytes = free_bytes or self._statvfs_free
        self._lock = threading.Lock()
        self._reserved = 0
        self._active = {}
        # No stream survives the process that ran it.
        self.sweep()

    def _statvfs_free(self):
        status = os.fstatvfs(self._directory)
        return status.f_bavail * status.f_frsize

    def close(self):
        if self._directory is not None:
            os.close(self._directory)
            self._directory = None

    def reserve(self, size):
        """Reserve `size` bytes for one stream, or refuse before any byte is read.

        Free space already shows what live streams have written, not what they
        have yet to write, so that remainder is counted as used. It is read
        before the free space, so a chunk written in between is counted twice
        rather than not at all.
        """
        if type(size) is not int or size < 1:
            raise StagingRefusal("staging_unavailable")
        with self._lock:
            unwritten = sum(max(0, held.size - held.count) for held in self._active.values())
            try:
                free = self._free_bytes()
            except OSError:
                raise StagingRefusal("staging_unavailable") from None
            if self._reserved + size > self.capacity_bytes or free - unwritten - size < self.floor_bytes:
                raise StagingRefusal("staging_full")
            reservation = Reservation(self, secrets.token_hex(16) + ".part", size)
            self._reserved += size
            self._active[reservation.name] = reservation
        return reservation

    def _release(self, reservation):
        with self._lock:
            if self._active.get(reservation.name) is reservation:
                del self._active[reservation.name]
                self._reserved -= reservation.size

    def _unlink(self, name):
        try:
            os.unlink(name, dir_fd=self._directory)
        except FileNotFoundError:
            pass

    def sweep(self):
        """Remove staged files no live reservation holds; return how many went."""
        removed = 0
        with self._lock:
            active = set(self._active)
        try:
            with os.scandir(self._directory) as entries:
                names = [entry.name for entry in entries if NAME.fullmatch(entry.name)]
        except OSError:
            raise StagingRefusal("staging_unavailable") from None
        for name in names:
            if name not in active:
                try:
                    self._unlink(name)
                except OSError:
                    raise StagingRefusal("staging_unavailable") from None
                removed += 1
        return removed

    def usage(self):
        """Reserved bytes, live streams and free filesystem bytes, with no candidate or actor detail."""
        with self._lock:
            reserved, streams = self._reserved, len(self._active)
        try:
            free = self._free_bytes()
        except OSError:
            free = None
        return {"reserved_bytes": reserved, "streams": streams, "free_bytes": free}


@dataclass(eq=False)
class Reservation:
    """Room for one stream's staged file; `close` removes the file and gives the room back."""
    area: StagingArea
    name: str
    size: int
    descriptor: int | None = None
    count: int = 0
    _digest: object = field(default_factory=hashlib.sha256, repr=False)
    closed: bool = False

    def create(self):
        """Create the staged file exclusively in the held directory, never through a link."""
        try:
            self.descriptor = os.open(self.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      0o600, dir_fd=self.area._directory)
        except OSError:
            raise StagingRefusal("staging_unavailable") from None

    def write(self, chunk):
        """Hash, count and write one chunk; a chunk that would pass the declared size writes nothing."""
        if self.count + len(chunk) > self.size:
            raise StagingRefusal("body_extra")
        try:
            _write_all(self.descriptor, chunk)
        except OSError as error:
            raise StagingRefusal("staging_full" if error.errno in FULL else "staging_unavailable") from None
        self._digest.update(chunk)
        self.count += len(chunk)

    def finish(self):
        """Flush the staged bytes to disk; return the count and SHA-256 of what was written."""
        try:
            os.fsync(self.descriptor)
            length = os.fstat(self.descriptor).st_size
        except OSError as error:
            raise StagingRefusal("staging_full" if error.errno in FULL else "staging_unavailable") from None
        if length != self.count:
            raise StagingRefusal("staging_mismatch")
        return self.count, self._digest.hexdigest()

    def close(self):
        """Remove the file this reservation created, never one another writer put at its name.

        Closing never raises: a file it could not remove is a leftover that
        `StagingArea.sweep` or the next start removes.
        """
        if self.closed:
            return
        self.closed = True
        try:
            if self.descriptor is not None:
                ours = os.fstat(self.descriptor)
                try:
                    found = os.stat(self.name, dir_fd=self.area._directory, follow_symlinks=False)
                except FileNotFoundError:
                    found = None
                if found is not None and (found.st_dev, found.st_ino) == (ours.st_dev, ours.st_ino):
                    self.area._unlink(self.name)
        except OSError:
            pass
        finally:
            if self.descriptor is not None:
                try:
                    os.close(self.descriptor)
                except OSError:
                    pass
            self.area._release(self)


@dataclass(eq=False)
class StagedInput:
    """One job's immutable input, read only through the descriptor that was checked."""
    descriptor: int = field(repr=False)
    size: int
    sha256: str

    def chunks(self, chunk_bytes=CHUNK_BYTES):
        offset = 0
        while offset < self.size:
            chunk = os.pread(self.descriptor, min(chunk_bytes, self.size - offset), offset)
            if not chunk:
                return
            yield chunk
            offset += len(chunk)

    def close(self):
        os.close(self.descriptor)


def stage_sealed(store, sealed, job_directory):
    """Copy one sealed quarantine object into a job file and check it byte for byte.

    `sealed` carries the recorded key, size and digest. Any other length or
    digest refuses as `staging_mismatch`, which the caller treats as a
    storage-integrity failure, and no job file remains.
    """
    try:
        directory = _open_directory(job_directory)
    except StartupRefusal:
        raise StagingRefusal("staging_unavailable") from None
    name = secrets.token_hex(16) + ".input"
    writer = None
    try:
        try:
            writer = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                             dir_fd=directory)
        except OSError:
            raise StagingRefusal("staging_unavailable") from None
        digest, count, chunks = hashlib.sha256(), 0, None
        try:
            chunks = store.read(sealed.object_key)
            for chunk in chunks:
                count += len(chunk)
                if count > sealed.sealed_size:
                    raise StagingRefusal("staging_mismatch")
                digest.update(chunk)
                _write_all(writer, chunk)
        except QuarantineError:
            raise StagingRefusal("staging_unavailable") from None
        except OSError as error:
            raise StagingRefusal("staging_full" if error.errno in FULL else "staging_unavailable") from None
        finally:
            getattr(chunks, "close", lambda: None)()
        if count != sealed.sealed_size or not hmac.compare_digest(digest.hexdigest(), sealed.sealed_sha256):
            raise StagingRefusal("staging_mismatch")
        try:
            os.fsync(writer)
            os.fchmod(writer, 0o400)
            reader = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            written, opened = os.fstat(writer), os.fstat(reader)
        except OSError as error:
            raise StagingRefusal("staging_full" if error.errno in FULL else "staging_unavailable") from None
        if (written.st_dev, written.st_ino) != (opened.st_dev, opened.st_ino) or opened.st_size != count:
            os.close(reader)
            raise StagingRefusal("staging_mismatch")
        return StagedInput(reader, count, digest.hexdigest())
    except BaseException:
        try:
            os.unlink(name, dir_fd=directory)
        except OSError:
            pass
        raise
    finally:
        if writer is not None:
            os.close(writer)
        os.close(directory)
