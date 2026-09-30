"""Login state, browser sessions, CLI access tokens and CSRF (specification section 8).

Every secret here is shown once and stored only as its SHA-256. Login state
lives five minutes, is used once and binds the browser that started it. A
session lives at most eight hours. An access token lives at most fifteen
minutes, names one audience and environment, and dies with its session.
Logout revokes the session and every token paired from it.

Each call is one transaction. A session row is locked before its tokens, and
the actor row before that actor's sessions, so no two calls wait on each other
in a cycle. Expired or revoked sessions and tokens never count against a
ceiling. See adr/bind-uploads-to-enrolled-keys.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
import hmac
import logging
import re
import uuid

from fiat_checkpoints.auth.identity import identify
from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.auth.tokens import csrf_token, new_secret, pkce_verifier, secret_sha256, well_formed
from fiat_checkpoints.domain.coordination import positive_int, require_now


LOGIN_STATE_LIFETIME = timedelta(minutes=5)
SESSION_LIFETIME = timedelta(hours=8)
ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)
MAX_LIVE_LOGIN_STATES = 10_000
MAX_LIVE_SESSIONS_PER_ACTOR = 16
MAX_LIVE_TOKENS_PER_SESSION = 8
SWEEP_BATCH = 1000
# An arbitrary constant naming the lock that serializes login-state admission.
LOGIN_LOCK_KEY = 862_0004
AUDIENCE = re.compile(r"[a-z][a-z0-9-]{0,63}")
LOGGER = logging.getLogger("fiat_checkpoints")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


def _event(name, **fields):
    # Session ids, actor ids and secrets never become fields; counts do.
    LOGGER.info(name, extra={"event": name, **fields})


@dataclass(frozen=True)
class LoginStart:
    state: str
    binding: str
    expires_at: datetime


@dataclass(frozen=True)
class Actor:
    """An authenticated numeric actor and the session or token that proved it."""
    actor_id: int
    session_id: uuid.UUID
    via: str
    session_expires_at: datetime
    token_sha256: str | None = None


@dataclass(frozen=True)
class NewSession:
    secret: str
    csrf_token: str
    actor: Actor


@dataclass(frozen=True)
class AccessToken:
    token: str
    expires_at: datetime


def _revoke_session(connection, session_id, now):
    connection.execute("UPDATE sessions SET revoked_at = %s WHERE session_id = %s AND revoked_at IS NULL",
                       (now, session_id))
    connection.execute("UPDATE access_tokens SET revoked_at = %s WHERE session_id = %s AND revoked_at IS NULL",
                       (now, session_id))


class SessionStore:
    """Sessions for one service audience and environment."""

    def __init__(self, database, *, audience, environment):
        for value in (audience, environment):
            if type(value) is not str or AUDIENCE.fullmatch(value) is None:
                raise AuthRefusal("authority_unavailable", "session-config-invalid")
        self.database = database
        self.audience = audience
        self.environment = environment

    def _run(self, work):
        """One transaction; work that must commit before refusing returns the refusal."""
        result = self.database.transaction(work)
        if isinstance(result, AuthRefusal):
            raise result
        return result

    # Login ------------------------------------------------------------------

    def begin_login(self, now):
        """Record a new single-use login state bound to a new browser binding secret."""
        now = require_now(now)
        state, binding = new_secret(), new_secret()

        def work(connection):
            connection.execute("SELECT pg_advisory_xact_lock(%s)", (LOGIN_LOCK_KEY,))
            connection.execute(
                "DELETE FROM login_states WHERE ctid IN (SELECT ctid FROM login_states "
                "WHERE expires_at <= %s LIMIT %s)", (now, SWEEP_BATCH))
            live = connection.execute(
                "SELECT count(*) AS n FROM login_states WHERE consumed_at IS NULL AND expires_at > %s",
                (now,)).fetchone()["n"]
            if live >= MAX_LIVE_LOGIN_STATES:
                raise AuthRefusal("quota_exceeded", "login-state-limit")
            connection.execute(
                "INSERT INTO login_states (state_sha256, binding_sha256, created_at, expires_at) "
                "VALUES (%s, %s, %s, %s)",
                (secret_sha256(state), secret_sha256(binding), now, now + LOGIN_STATE_LIFETIME))

        self._run(work)
        return LoginStart(state, binding, now + LOGIN_STATE_LIFETIME)

    def _consume(self, state, binding, now):
        """Spend the login state once, whatever else is wrong, then check it."""
        if not well_formed(state) or not well_formed(binding):
            raise AuthRefusal("auth_required", "login-state-malformed")

        def work(connection):
            row = connection.execute("SELECT * FROM login_states WHERE state_sha256 = %s FOR UPDATE",
                                     (secret_sha256(state),)).fetchone()
            if row is None:
                return AuthRefusal("auth_required", "login-state-unknown")
            if row["consumed_at"] is not None:
                return AuthRefusal("auth_required", "login-state-replayed")
            connection.execute("UPDATE login_states SET consumed_at = %s WHERE state_sha256 = %s",
                               (now, row["state_sha256"]))
            if row["expires_at"] <= now:
                return AuthRefusal("auth_required", "login-state-expired")
            if not hmac.compare_digest(row["binding_sha256"], secret_sha256(binding)):
                return AuthRefusal("auth_required", "login-binding-mismatch")
            return None

        self._run(work)

    def complete_login(self, state, binding, code, provider, now):
        """Spend the state, exchange the code through the adapter, and open a session.

        No lock is held while the provider is called. The session belongs to
        the numeric id `GET /user` returned, never to a login name.
        """
        now = require_now(now)
        self._consume(state, binding, now)
        actor_id = identify(provider, code, pkce_verifier(state, binding))
        return self.open_session(actor_id, now)

    def open_session(self, actor_id, now):
        """Open one session; beyond the per-actor ceiling the oldest live session is revoked."""
        positive_int(actor_id)
        now = require_now(now)
        secret, session_id = new_secret(), uuid.uuid4()
        expires_at = now + SESSION_LIFETIME

        def work(connection):
            connection.execute("INSERT INTO actors (actor_id, first_seen_at) VALUES (%s, %s) "
                               "ON CONFLICT DO NOTHING", (actor_id, now))
            connection.execute("SELECT 1 FROM actors WHERE actor_id = %s FOR UPDATE", (actor_id,))
            live = connection.execute(
                "SELECT session_id FROM sessions WHERE actor_id = %s AND revoked_at IS NULL AND expires_at > %s "
                "ORDER BY created_at, session_id FOR UPDATE", (actor_id, now)).fetchall()
            evicted = live[:max(0, len(live) - MAX_LIVE_SESSIONS_PER_ACTOR + 1)]
            for row in evicted:
                _revoke_session(connection, row["session_id"], now)
            connection.execute(
                "INSERT INTO sessions (session_id, secret_sha256, actor_id, created_at, expires_at) "
                "VALUES (%s, %s, %s, %s, %s)", (session_id, secret_sha256(secret), actor_id, now, expires_at))
            return len(evicted)

        _event("session-opened", count=self._run(work))
        return NewSession(secret, csrf_token(secret), Actor(actor_id, session_id, "session", expires_at))

    # Authentication ---------------------------------------------------------

    def session(self, secret, now):
        """Authenticate one session secret; unknown, revoked and expired are one refusal."""
        now = require_now(now)
        if not well_formed(secret):
            raise AuthRefusal("auth_required", "session-malformed")

        def work(connection):
            return connection.execute(
                "SELECT session_id, actor_id, expires_at, revoked_at FROM sessions WHERE secret_sha256 = %s",
                (secret_sha256(secret),)).fetchone()

        row = self._run(work)
        if row is None:
            raise AuthRefusal("auth_required", "session-unknown")
        if row["revoked_at"] is not None:
            raise AuthRefusal("auth_required", "session-revoked")
        if row["expires_at"] <= now:
            raise AuthRefusal("auth_required", "session-expired")
        return Actor(row["actor_id"], row["session_id"], "session", row["expires_at"])

    def token(self, token, now):
        """Authenticate one access token for this audience and environment, and its session."""
        now = require_now(now)
        if not well_formed(token):
            raise AuthRefusal("auth_required", "token-malformed")
        token_sha256 = secret_sha256(token)

        def work(connection):
            return connection.execute(
                "SELECT t.session_id, t.audience, t.environment, t.expires_at, t.revoked_at, s.actor_id, "
                "s.expires_at AS session_expires_at, s.revoked_at AS session_revoked_at "
                "FROM access_tokens t JOIN sessions s USING (session_id) WHERE t.token_sha256 = %s",
                (token_sha256,)).fetchone()

        row = self._run(work)
        if row is None:
            raise AuthRefusal("auth_required", "token-unknown")
        if (row["audience"], row["environment"]) != (self.audience, self.environment):
            raise AuthRefusal("auth_required", "token-audience")
        if row["revoked_at"] is not None or row["session_revoked_at"] is not None:
            raise AuthRefusal("auth_required", "token-revoked")
        if row["expires_at"] <= now or row["session_expires_at"] <= now:
            raise AuthRefusal("auth_required", "token-expired")
        return Actor(row["actor_id"], row["session_id"], "token", row["session_expires_at"], token_sha256)

    # Tokens and logout ------------------------------------------------------

    def issue_token(self, actor, now):
        """Pair or renew: a new token under the actor's unrevoked session.

        Renewal by token spends the presented token, so one token renews once.
        The new token never outlives its session. The caller checks current
        run grants first (specification section 8).
        """
        if not isinstance(actor, Actor):
            raise AuthRefusal("auth_required", "actor-missing")
        now = require_now(now)
        token = new_secret()

        def work(connection):
            session = connection.execute("SELECT * FROM sessions WHERE session_id = %s FOR UPDATE",
                                         (actor.session_id,)).fetchone()
            if (session is None or session["actor_id"] != actor.actor_id or session["revoked_at"] is not None
                    or session["expires_at"] <= now):
                return AuthRefusal("auth_required", "session-revoked")
            if actor.token_sha256 is not None:
                spent = connection.execute(
                    "UPDATE access_tokens SET revoked_at = %s WHERE token_sha256 = %s AND session_id = %s "
                    "AND revoked_at IS NULL AND expires_at > %s RETURNING token_sha256",
                    (now, actor.token_sha256, actor.session_id, now)).fetchone()
                if spent is None:
                    return AuthRefusal("auth_required", "token-revoked")
            live = connection.execute(
                "SELECT token_sha256 FROM access_tokens WHERE session_id = %s AND revoked_at IS NULL "
                "AND expires_at > %s ORDER BY created_at, token_sha256 FOR UPDATE",
                (actor.session_id, now)).fetchall()
            evicted = live[:max(0, len(live) - MAX_LIVE_TOKENS_PER_SESSION + 1)]
            for row in evicted:
                connection.execute("UPDATE access_tokens SET revoked_at = %s WHERE token_sha256 = %s",
                                   (now, row["token_sha256"]))
            expires_at = min(now + ACCESS_TOKEN_LIFETIME, session["expires_at"])
            connection.execute(
                "INSERT INTO access_tokens (token_sha256, session_id, audience, environment, created_at, "
                "expires_at) VALUES (%s, %s, %s, %s, %s, %s)",
                (secret_sha256(token), actor.session_id, self.audience, self.environment, now, expires_at))
            return AccessToken(token, expires_at), len(evicted)

        issued, evicted = self._run(work)
        _event("access-token-issued", kind="renewal" if actor.token_sha256 else "pairing", count=evicted)
        return issued

    def logout(self, actor, now):
        """Revoke the actor's session and every token paired from it."""
        if not isinstance(actor, Actor):
            raise AuthRefusal("auth_required", "actor-missing")
        now = require_now(now)

        def work(connection):
            row = connection.execute("SELECT session_id FROM sessions WHERE session_id = %s AND actor_id = %s "
                                     "FOR UPDATE", (actor.session_id, actor.actor_id)).fetchone()
            if row is None:
                return AuthRefusal("auth_required", "session-unknown")
            _revoke_session(connection, actor.session_id, now)
            return None

        self._run(work)
        _event("session-revoked")

    def sweep(self, now, limit=SWEEP_BATCH):
        """Delete expired login state and expired or revoked tokens and sessions."""
        now = require_now(now)
        positive_int(limit, 10_000)

        def work(connection):
            removed = 0
            for statement in (
                "DELETE FROM login_states WHERE ctid IN (SELECT ctid FROM login_states "
                "WHERE expires_at <= %(now)s LIMIT %(limit)s)",
                "DELETE FROM access_tokens WHERE ctid IN (SELECT ctid FROM access_tokens "
                "WHERE expires_at <= %(now)s OR revoked_at IS NOT NULL LIMIT %(limit)s)",
                "DELETE FROM sessions WHERE ctid IN (SELECT ctid FROM sessions "
                "WHERE expires_at <= %(now)s OR revoked_at IS NOT NULL LIMIT %(limit)s)",
            ):
                removed += connection.execute(statement, {"now": now, "limit": limit}).rowcount
            return removed

        return self._run(work)
