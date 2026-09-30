"""One transaction per call, with every library failure mapped to a fixed code.

Nothing from psycopg or PostgreSQL leaves this module: its exception text can
name tables, values or the server, so each failure becomes a `PersistenceRefusal`
raised without a chained cause.
"""

import os
import random
import threading
import time

import psycopg
from psycopg import errors
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row

from fiat_checkpoints.domain.coordination import CoordinationRefusal


# Transient conflicts between concurrent transactions; the whole call is retried.
RETRYABLE = (errors.SerializationFailure, errors.DeadlockDetected)
MAX_ATTEMPTS = 8
DATABASE_NAME_LIMIT = 63


class PersistenceRefusal(CoordinationRefusal):
    """A fixed persistence code; see `CoordinationRefusal`."""


class Database:
    """Connect over a local Unix socket to one named database.

    Only a socket directory is accepted in this packet, so no host name or
    password reaches a connection string. Every statement and lock wait is
    bounded, and a transaction left idle is ended by the server.
    """

    def __init__(self, socket_directory, dbname, *, user="postgres",
                 statement_timeout_ms=10_000, lock_timeout_ms=10_000):
        if type(socket_directory) is not str or not os.path.isabs(socket_directory):
            raise PersistenceRefusal("database_config_invalid")
        for value in (dbname, user):
            if (type(value) is not str or not 1 <= len(value) <= DATABASE_NAME_LIMIT
                    or not value.replace("_", "").isalnum() or not value.isascii()):
                raise PersistenceRefusal("database_config_invalid")
        for value in (statement_timeout_ms, lock_timeout_ms):
            if type(value) is not int or not 1 <= value <= 600_000:
                raise PersistenceRefusal("database_config_invalid")
        self.dbname = dbname
        self._conninfo = make_conninfo(
            host=socket_directory, dbname=dbname, user=user, connect_timeout=5,
            application_name="fiat-checkpoints",
            options=(f"-c statement_timeout={statement_timeout_ms} "
                     f"-c lock_timeout={lock_timeout_ms} "
                     "-c idle_in_transaction_session_timeout=60000 -c TimeZone=UTC"))
        self._random = random.Random()
        self._random_lock = threading.Lock()

    def connect(self):
        """Open one autocommit connection; the caller owns closing it."""
        try:
            return psycopg.connect(self._conninfo, autocommit=True, row_factory=dict_row)
        except Exception:
            raise PersistenceRefusal("database_unavailable") from None

    def transaction(self, work):
        """Run `work(connection)` in one transaction and return its result.

        A serialization failure or deadlock reruns the whole call up to
        MAX_ATTEMPTS times. A `CoordinationRefusal` from `work` rolls back and
        propagates unchanged. Every other failure rolls back and becomes
        `database_unavailable` or `persistence_failed`.
        """
        for attempt in range(MAX_ATTEMPTS):
            try:
                connection = self.connect()
                try:
                    with connection.transaction():
                        return work(connection)
                finally:
                    connection.close()
            except CoordinationRefusal:
                raise
            except RETRYABLE:
                with self._random_lock:
                    pause = self._random.uniform(0.001, 0.005 * (attempt + 1))
                time.sleep(pause)
            except (psycopg.OperationalError, psycopg.InterfaceError):
                raise PersistenceRefusal("database_unavailable") from None
            except Exception:
                raise PersistenceRefusal("persistence_failed") from None
        raise PersistenceRefusal("persistence_contention")
