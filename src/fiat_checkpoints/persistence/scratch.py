"""Disposable databases for checks against the pinned local PostgreSQL 16.

Checks reach the server only through the Unix socket directory named by
`FIAT_TEST_POSTGRES`; `scripts/test-postgres.sh` starts that server with no
network. Each scratch database has a random name and is dropped on close.
"""

import os
import secrets

from psycopg import sql

from fiat_checkpoints.persistence.database import Database, PersistenceRefusal


ENVIRONMENT = "FIAT_TEST_POSTGRES"
SERVER_MAJOR = 16


def socket_directory():
    value = os.environ.get(ENVIRONMENT)
    if not value or not os.path.isabs(value):
        raise PersistenceRefusal("database_unavailable")
    return value


class ScratchDatabase:
    """Create one empty database; use as a context manager or call `close`."""

    def __init__(self):
        self.socket = socket_directory()
        self.name = "fiat_check_" + secrets.token_hex(8)
        self.admin = Database(self.socket, "postgres")

        def create(connection):
            version = connection.execute("SHOW server_version_num").fetchone()["server_version_num"]
            if int(version) // 10_000 != SERVER_MAJOR:
                raise PersistenceRefusal("database_version_mismatch")
            return version

        self.server_version_num = self.admin.transaction(create)
        connection = self.admin.connect()
        try:
            # CREATE DATABASE cannot run inside a transaction block.
            connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(self.name)))
        except Exception:
            raise PersistenceRefusal("database_unavailable") from None
        finally:
            connection.close()
        self.database = Database(self.socket, self.name)

    def close(self):
        connection = self.admin.connect()
        try:
            connection.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(self.name)))
        except Exception:
            raise PersistenceRefusal("database_unavailable") from None
        finally:
            connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False
