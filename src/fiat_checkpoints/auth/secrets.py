"""Name a credential by reference; read its value only from the runtime secret mount.

Configuration carries `secret:<name>` and never a value (specification section
18). The value is read at the moment of use from one bounded regular file
under a fixed mount directory, without following a link, and is never logged,
repeated in an error or kept in a representation. An adapter that needs a
credential, such as the login App's client secret, holds only the reference.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat


DEFAULT_MOUNT = Path("/run/secrets/fiat-checkpoints")
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
PREFIX = "secret:"
MAX_SECRET_BYTES = 4096


class SecretUnavailable(Exception):
    """A fixed code; neither the name's value nor the mount path is carried."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class Secret:
    """A resolved value. Its representation never shows the bytes."""

    __slots__ = ("_value",)

    def __init__(self, value):
        self._value = value

    def reveal(self):
        return self._value

    def __repr__(self):
        return "Secret(<redacted>)"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("secret-not-serializable")


@dataclass(frozen=True)
class SecretReference:
    name: str

    @classmethod
    def parse(cls, value):
        """Accept only `secret:<name>`; a literal value, a path or a URL refuses."""
        if type(value) is not str or not value.startswith(PREFIX):
            raise SecretUnavailable("secret-reference-invalid")
        name = value[len(PREFIX):]
        if NAME.fullmatch(name) is None:
            raise SecretUnavailable("secret-reference-invalid")
        return cls(name)

    def resolve(self, mount=DEFAULT_MOUNT):
        """Read the value from `<mount>/<name>`: one link, regular, bounded, unchanged while read."""
        if NAME.fullmatch(self.name or "") is None:
            raise SecretUnavailable("secret-reference-invalid")
        mount = Path(mount)
        if not mount.is_absolute():
            raise SecretUnavailable("secret-mount-invalid")
        try:
            directory = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise SecretUnavailable("secret-unavailable") from None
        try:
            try:
                descriptor = os.open(self.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                     dir_fd=directory)
            except OSError:
                raise SecretUnavailable("secret-unavailable") from None
            try:
                before = os.fstat(descriptor)
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                        or not 0 < before.st_size <= MAX_SECRET_BYTES):
                    raise SecretUnavailable("secret-unavailable")
                raw = os.read(descriptor, MAX_SECRET_BYTES + 1)
                after = os.fstat(descriptor)
            except OSError:
                raise SecretUnavailable("secret-unavailable") from None
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)
        identity = lambda value: (value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or len(raw) != before.st_size:
            raise SecretUnavailable("secret-unavailable")
        # One trailing newline is how secret files are usually written; it is not part of the value.
        value = raw[:-1] if raw.endswith(b"\n") else raw
        if not value or b"\n" in value or b"\x00" in value:
            raise SecretUnavailable("secret-unavailable")
        return Secret(value)
