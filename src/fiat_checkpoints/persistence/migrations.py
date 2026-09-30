"""Apply numbered SQL migrations, each in its own transaction under one advisory lock.

A migration either commits together with its ledger row or leaves nothing, so
a process that dies part-way reruns from the last committed version. Applied
migrations are compared by SHA-256 on every run: a changed or unknown one
refuses before anything new is applied.
"""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat

from fiat_checkpoints.persistence.database import PersistenceRefusal


NAME = re.compile(r"(\d{4})_([a-z0-9_]{1,64})\.sql")
MAX_MIGRATION_BYTES = 262_144
MAX_MIGRATIONS = 512
# An arbitrary constant naming this service's migration lock.
LOCK_KEY = 862_0003
DEFAULT_DIRECTORY = Path(__file__).resolve().parents[3] / "migrations"

LEDGER = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version integer PRIMARY KEY CHECK (version > 0),
    name text NOT NULL,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
)
"""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str
    sha256: str


def _read_regular(directory_fd, name):
    """Read one regular file by name inside an open directory, never through a link."""
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    except OSError:
        # A symbolic link fails here with ELOOP; nothing is read through it.
        raise PersistenceRefusal("migration-set-invalid") from None
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_size > MAX_MIGRATION_BYTES:
            raise PersistenceRefusal("migration-set-invalid")
        chunks, total = [], 0
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_MIGRATION_BYTES:
                raise PersistenceRefusal("migration-set-invalid")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load_migrations(directory=DEFAULT_DIRECTORY):
    """Return the contiguous migration list, refusing links, gaps and stray files."""
    try:
        directory_fd = os.open(Path(directory), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise PersistenceRefusal("migration-set-unavailable") from None
    try:
        names = sorted(os.listdir(directory_fd))
        if len(names) > MAX_MIGRATIONS:
            raise PersistenceRefusal("migration-set-invalid")
        migrations = []
        for name in names:
            match = NAME.fullmatch(name)
            if match is None:
                raise PersistenceRefusal("migration-set-invalid")
            raw = _read_regular(directory_fd, name)
            try:
                sql = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise PersistenceRefusal("migration-set-invalid") from None
            migrations.append(Migration(int(match.group(1)), match.group(2), sql,
                                        hashlib.sha256(raw).hexdigest()))
    except OSError:
        raise PersistenceRefusal("migration-set-unavailable") from None
    finally:
        os.close(directory_fd)
    if not migrations or [item.version for item in migrations] != list(range(1, len(migrations) + 1)):
        raise PersistenceRefusal("migration-set-invalid")
    return migrations


def _check_ledger(connection, migrations):
    rows = connection.execute("SELECT version, name, sha256 FROM schema_migrations ORDER BY version").fetchall()
    known = {item.version: item for item in migrations}
    for row in rows:
        item = known.get(row["version"])
        if item is None:
            raise PersistenceRefusal("migration-unknown")
        if (item.name, item.sha256) != (row["name"], row["sha256"]):
            raise PersistenceRefusal("migration-drift")
    if [row["version"] for row in rows] != list(range(1, len(rows) + 1)):
        raise PersistenceRefusal("migration-drift")
    return len(rows)


def migrate(database, directory=DEFAULT_DIRECTORY):
    """Bring the database to the newest migration; return the versions applied now."""
    migrations = load_migrations(directory)
    applied = []

    def status(connection):
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (LOCK_KEY,))
        connection.execute(LEDGER)
        return _check_ledger(connection, migrations)

    current = database.transaction(status)
    while current < len(migrations):
        item = migrations[current]

        def apply(connection, item=item):
            connection.execute("SELECT pg_advisory_xact_lock(%s)", (LOCK_KEY,))
            # A concurrent runner may have applied it while this one waited.
            done = _check_ledger(connection, migrations)
            if done >= item.version:
                return done, False
            connection.execute(item.sql)
            connection.execute("INSERT INTO schema_migrations (version, name, sha256) VALUES (%s, %s, %s)",
                               (item.version, item.name, item.sha256))
            return item.version, True

        current, applied_now = database.transaction(apply)
        if applied_now:
            applied.append(item.version)
    return tuple(applied)
