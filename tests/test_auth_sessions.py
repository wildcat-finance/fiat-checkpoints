"""Login state, numeric identity, sessions, access tokens and CSRF against the test server."""

from datetime import timedelta
import threading
import time
import unittest
from unittest import mock

from psycopg import errors

from fiat_checkpoints.auth import sessions as sessions_module
from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.auth.sessions import SessionStore
from fiat_checkpoints.auth.tokens import (csrf_matches, csrf_token, new_secret, pkce_challenge, pkce_verifier,
                                          secret_sha256)
from tests.auth_support import SETTINGS, FakeProvider, T0, at, user_document
from tests.persistence_support import DatabaseCase, recorded_events


class SessionCase(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.provider = FakeProvider()
        self.sessions = self.store()

    def store(self, audience=SETTINGS.service_id, environment=SETTINGS.environment_id):
        return SessionStore(self.database, audience=audience, environment=environment)

    def start(self, document, now=T0):
        """Begin one login and approve it at the provider; return (start, state, code)."""
        begun = self.sessions.begin_login(now)
        url = self.provider.authorization_url(begun.state, pkce_challenge(pkce_verifier(begun.state, begun.binding)))
        state, code = self.provider.authorize(url, document)
        self.assertEqual(state, begun.state)
        return begun, code

    def login(self, document, now=T0):
        begun, code = self.start(document, now)
        return self.sessions.complete_login(begun.state, begun.binding, code, self.provider, now)

    def refusal(self, call):
        with self.assertRaises(AuthRefusal) as caught:
            call()
        self.assertIsNone(caught.exception.__cause__)
        return caught.exception.code, caught.exception.reason

    def dump(self):
        """Every text and byte value in every table, to look for a secret that should not be there."""
        values = []
        for table in [row["tablename"] for row in self.query(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'")]:
            for row in self.query(f"SELECT * FROM {table}"):
                values.extend(str(value) if not isinstance(value, bytes) else value.decode("latin-1")
                              for value in row.values())
        return "\n".join(values)


class NumericIdentityTests(SessionCase):
    def test_numeric_identity_survives_a_rename_and_a_reused_login_is_another_actor(self):
        first = self.login(user_document(41, "contributor-old"))
        renamed = self.login(user_document(41, "contributor-new"))
        reused = self.login(user_document(99, "contributor-old"))
        self.assertEqual((first.actor.actor_id, renamed.actor.actor_id, reused.actor.actor_id), (41, 41, 99))
        stored = self.dump()
        for name in ("contributor-old", "contributor-new"):
            self.assertNotIn(name, stored)

    def test_a_user_document_that_is_not_one_numeric_id_refuses(self):
        documents = (b'{"login":"someone"}', b'{"id":"41"}', b'{"id":true}', b'{"id":41.0}', b'{"id":0}',
                     b'{"id":-1}', b'{"id":9223372036854775808}', b'{"id":1,"id":2}', b'[41]', b'"41"',
                     b"\xff\xfe", b"", b'{"id":41', b'{"id":NaN}', b'{"id":1e3}',
                     b'{"id":41,"login":"x"}' + b" " * 65_536)
        for document in documents:
            with self.subTest(length=len(document)):
                begun, code = self.start(document)
                self.assertEqual(self.refusal(lambda: self.sessions.complete_login(
                    begun.state, begun.binding, code, self.provider, T0)), ("auth_required", "identity-malformed"))
        self.assertEqual(self.scalar("SELECT count(*) FROM sessions"), 0)


class LoginStateTests(SessionCase):
    def test_login_state_is_single_use(self):
        begun, code = self.start(user_document(41, "a"))
        self.sessions.complete_login(begun.state, begun.binding, code, self.provider, T0)
        _, fresh = self.start(user_document(41, "a"))
        self.assertEqual(self.refusal(lambda: self.sessions.complete_login(
            begun.state, begun.binding, fresh, self.provider, T0)), ("auth_required", "login-state-replayed"))

    def test_login_state_expires_after_five_minutes(self):
        begun, code = self.start(user_document(41, "a"))
        self.assertEqual(self.refusal(lambda: self.sessions.complete_login(
            begun.state, begun.binding, code, self.provider, at(300))), ("auth_required", "login-state-expired"))
        begun, code = self.start(user_document(41, "a"))
        self.assertEqual(self.sessions.complete_login(begun.state, begun.binding, code, self.provider,
                                                      at(299)).actor.actor_id, 41)

    def test_login_state_cannot_authorize_another_browser(self):
        begun, code = self.start(user_document(41, "a"))
        self.assertEqual(self.refusal(lambda: self.sessions.complete_login(
            begun.state, new_secret(), code, self.provider, T0)), ("auth_required", "login-binding-mismatch"))
        # The state was spent by that attempt, so its own browser cannot use it afterwards either.
        self.assertEqual(self.refusal(lambda: self.sessions.complete_login(
            begun.state, begun.binding, code, self.provider, T0)), ("auth_required", "login-state-replayed"))
        self.assertEqual(self.provider.exchanged, [])
        self.assertEqual(self.scalar("SELECT count(*) FROM sessions"), 0)

    def test_a_code_issued_to_one_login_cannot_complete_another(self):
        victim, victim_code = self.start(user_document(41, "victim"))
        attacker, _attacker_code = self.start(user_document(66, "attacker"))
        # The attacker replays the victim's code in the attacker's own browser: PKCE ties it to the victim's login.
        self.assertEqual(self.refusal(lambda: self.sessions.complete_login(
            attacker.state, attacker.binding, victim_code, self.provider, T0)), ("auth_required", "provider-refused"))
        self.assertEqual(self.scalar("SELECT count(*) FROM sessions"), 0)
        self.assertEqual(self.refusal(lambda: self.sessions.complete_login(
            victim.state, victim.binding, victim_code, self.provider, T0)), ("auth_required", "provider-refused"))

    def test_unknown_malformed_and_provider_failures_are_fixed_codes(self):
        self.assertEqual(self.refusal(lambda: self.sessions.complete_login(
            new_secret(), new_secret(), "code", self.provider, T0)), ("auth_required", "login-state-unknown"))
        for state in ("", "short", "ghp_" + "a" * 36, None, 7, b"x" * 43, "é" * 43):
            with self.subTest(state=repr(state)[:12]):
                self.assertEqual(self.refusal(lambda: self.sessions.complete_login(
                    state, new_secret(), "code", self.provider, T0)), ("auth_required", "login-state-malformed"))
        begun, _code = self.start(user_document(41, "a"))
        self.assertEqual(self.refusal(lambda: self.sessions.complete_login(
            begun.state, begun.binding, "bad code with spaces", self.provider, T0)),
            ("request_invalid", "login-code-malformed"))

        class Broken(FakeProvider):
            def user_document(self, code, code_verifier):
                raise RuntimeError("provider-private-marker")

        broken = Broken()
        begun = self.sessions.begin_login(T0)
        with self.assertRaises(AuthRefusal) as caught:
            self.sessions.complete_login(begun.state, begun.binding, "code", broken, T0)
        self.assertEqual((caught.exception.code, str(caught.exception)), ("auth_required", "auth_required"))
        self.assertTrue(caught.exception.__suppress_context__)

    def test_live_login_states_are_bounded_and_expired_ones_do_not_count(self):
        with mock.patch.object(sessions_module, "MAX_LIVE_LOGIN_STATES", 3):
            for _ in range(3):
                self.sessions.begin_login(T0)
            self.assertEqual(self.refusal(lambda: self.sessions.begin_login(at(299))),
                             ("quota_exceeded", "login-state-limit"))
            self.sessions.begin_login(at(300))
        self.assertEqual(self.scalar("SELECT count(*) FROM login_states"), 1)


class SessionLifetimeTests(SessionCase):
    def test_session_expires_after_eight_hours(self):
        opened = self.sessions.open_session(41, T0)
        self.assertEqual(self.sessions.session(opened.secret, T0 + timedelta(hours=8, seconds=-1)).actor_id, 41)
        self.assertEqual(self.refusal(lambda: self.sessions.session(opened.secret, T0 + timedelta(hours=8))),
                         ("auth_required", "session-expired"))

    def test_logout_revokes_the_session_and_every_paired_token(self):
        opened = self.sessions.open_session(41, T0)
        token = self.sessions.issue_token(opened.actor, T0)
        self.sessions.logout(self.sessions.session(opened.secret, T0), at(1))
        self.assertEqual(self.refusal(lambda: self.sessions.session(opened.secret, at(2))),
                         ("auth_required", "session-revoked"))
        self.assertEqual(self.refusal(lambda: self.sessions.token(token.token, at(2))),
                         ("auth_required", "token-revoked"))
        self.assertEqual(self.refusal(lambda: self.sessions.issue_token(opened.actor, at(2))),
                         ("auth_required", "session-revoked"))

    def test_access_token_lives_fifteen_minutes_and_never_outlives_its_session(self):
        opened = self.sessions.open_session(41, T0)
        token = self.sessions.issue_token(opened.actor, T0)
        self.assertEqual(token.expires_at, at(900))
        self.assertEqual(self.sessions.token(token.token, at(899)).actor_id, 41)
        self.assertEqual(self.refusal(lambda: self.sessions.token(token.token, at(900))),
                         ("auth_required", "token-expired"))
        late = self.sessions.issue_token(opened.actor, T0 + timedelta(hours=8, minutes=-5))
        self.assertEqual(late.expires_at, opened.actor.session_expires_at)

    def test_token_audience_and_environment_are_bound(self):
        opened = self.sessions.open_session(41, T0)
        token = self.sessions.issue_token(opened.actor, T0)
        for store in (self.store(audience="another-service"), self.store(environment="another-local")):
            with self.subTest(audience=store.audience, environment=store.environment):
                self.assertEqual(self.refusal(lambda: store.token(token.token, T0)),
                                 ("auth_required", "token-audience"))

    def test_renewal_spends_the_presented_token_once(self):
        opened = self.sessions.open_session(41, T0)
        first = self.sessions.issue_token(opened.actor, T0)
        holder = self.sessions.token(first.token, at(60))
        second = self.sessions.issue_token(holder, at(60))
        self.assertEqual(self.refusal(lambda: self.sessions.token(first.token, at(61))),
                         ("auth_required", "token-revoked"))
        self.assertEqual(self.refusal(lambda: self.sessions.issue_token(holder, at(61))),
                         ("auth_required", "token-revoked"))
        self.assertEqual(self.sessions.token(second.token, at(61)).session_id, opened.actor.session_id)

    def test_live_sessions_per_actor_are_bounded_and_expired_ones_do_not_count(self):
        opened = [self.sessions.open_session(41, at(index)) for index in range(16)]
        self.sessions.open_session(41, at(16))
        self.assertEqual(self.refusal(lambda: self.sessions.session(opened[0].secret, at(17))),
                         ("auth_required", "session-revoked"))
        self.assertEqual(self.sessions.session(opened[1].secret, at(17)).actor_id, 41)
        self.assertEqual(self.scalar("SELECT count(*) FROM sessions WHERE revoked_at IS NULL"), 16)
        later = T0 + timedelta(hours=9)
        self.sessions.open_session(41, later)
        # Every earlier session had expired, so none needed revoking to make room.
        self.assertEqual(self.scalar("SELECT count(*) FROM sessions WHERE revoked_at IS NOT NULL"), 1)

    def test_live_tokens_per_session_are_bounded(self):
        opened = self.sessions.open_session(41, T0)
        tokens = [self.sessions.issue_token(opened.actor, at(index)) for index in range(9)]
        self.assertEqual(self.refusal(lambda: self.sessions.token(tokens[0].token, at(10))),
                         ("auth_required", "token-revoked"))
        self.assertEqual(self.scalar("SELECT count(*) FROM access_tokens WHERE revoked_at IS NULL"), 8)

    def test_secrets_are_stored_only_as_digests(self):
        begun, code = self.start(user_document(41, "a"))
        opened = self.sessions.complete_login(begun.state, begun.binding, code, self.provider, T0)
        token = self.sessions.issue_token(opened.actor, T0)
        stored = self.dump()
        for secret in (opened.secret, opened.csrf_token, token.token, begun.state, begun.binding, code):
            with self.subTest(kind=len(secret)):
                self.assertNotIn(secret, stored)
        for secret in (opened.secret, token.token, begun.state):
            self.assertIn(secret_sha256(secret), stored)

    def test_values_that_are_not_service_secrets_refuse_before_any_lookup(self):
        opened = self.sessions.open_session(41, T0)
        for value in ("ghp_" + "a" * 36, "gho_" + "b" * 36, "github_pat_" + "c" * 30, "Bearer x", "",
                      None, 41, b"x" * 43, "x" * 42, "x" * 44):
            with self.subTest(value=repr(value)[:10]):
                self.assertEqual(self.refusal(lambda: self.sessions.token(value, T0))[0], "auth_required")
                self.assertEqual(self.refusal(lambda: self.sessions.session(value, T0))[0], "auth_required")
        # A session secret is not an access token, nor the reverse.
        self.assertEqual(self.refusal(lambda: self.sessions.token(opened.secret, T0)),
                         ("auth_required", "token-unknown"))
        token = self.sessions.issue_token(opened.actor, T0)
        self.assertEqual(self.refusal(lambda: self.sessions.session(token.token, T0)),
                         ("auth_required", "session-unknown"))

    def test_sweep_deletes_expired_and_revoked_rows_only(self):
        kept = self.sessions.open_session(41, T0)
        ended = self.sessions.open_session(42, T0)
        self.sessions.issue_token(kept.actor, T0)
        self.sessions.logout(ended.actor, T0)
        self.sessions.begin_login(T0)
        self.assertEqual(self.sessions.sweep(at(60)), 1)
        self.assertEqual(self.sessions.session(kept.secret, at(60)).actor_id, 41)
        self.assertEqual(self.sessions.sweep(at(900)), 2)
        self.assertEqual(self.scalar("SELECT count(*) FROM sessions"), 1)

    def test_a_sweep_never_holds_a_token_while_it_waits_for_that_tokens_session(self):
        # Logout and renewal lock the session, then its tokens. A sweep that
        # took the token first closed a cycle, and PostgreSQL aborted one side.
        opened = self.sessions.open_session(41, T0)
        self.sessions.issue_token(opened.actor, T0)
        holder, probe = self.database.connect(), self.database.connect()
        result = {}
        try:
            holder.execute("BEGIN")
            holder.execute("SELECT 1 FROM sessions WHERE session_id = %s FOR UPDATE", (opened.actor.session_id,))
            sweeper = threading.Thread(target=lambda: result.setdefault(
                "removed", self.sessions.sweep(T0 + timedelta(hours=8, seconds=1))))
            sweeper.start()
            deadline = time.monotonic() + 30
            while sweeper.is_alive() and time.monotonic() < deadline and not probe.execute(
                    "SELECT count(*) AS n FROM pg_stat_activity WHERE datname = %s AND wait_event_type = 'Lock'",
                    (self.database.dbname,)).fetchone()["n"]:
                time.sleep(0.02)
            unlocked = probe.execute("SELECT token_sha256 FROM access_tokens FOR UPDATE SKIP LOCKED").fetchall()
            try:
                holder.execute("UPDATE access_tokens SET revoked_at = %s WHERE session_id = %s "
                               "AND revoked_at IS NULL", (T0, opened.actor.session_id))
                holder.execute("COMMIT")
            except errors.DeadlockDetected:
                holder.execute("ROLLBACK")
            sweeper.join(30)
        finally:
            holder.close()
            probe.close()
        self.assertEqual(len(unlocked), 1)
        self.assertEqual(result.get("removed"), 2)
        self.assertEqual(self.scalar("SELECT count(*) FROM sessions"), 0)

    def test_session_events_are_counts_without_ids_or_secrets(self):
        with recorded_events() as events:
            opened = self.sessions.open_session(41, T0)
            paired = self.sessions.issue_token(opened.actor, T0)
            self.sessions.issue_token(self.sessions.token(paired.token, T0), T0)
            self.sessions.logout(opened.actor, T0)
        self.assertEqual([(event["event"], event.get("kind"), event.get("count")) for event in events], [
            ("session-opened", None, 0), ("access-token-issued", "pairing", 0),
            ("access-token-issued", "renewal", 0), ("session-revoked", None, None)])
        text = repr(events)
        for value in (opened.secret, opened.csrf_token, paired.token, str(opened.actor.session_id), "41"):
            self.assertNotIn(value, text)

    def test_malformed_calls_to_every_store_entry_point_are_fixed_codes(self):
        opened = self.sessions.open_session(41, T0)
        calls = (
            lambda: self.sessions.begin_login(None),
            lambda: self.sessions.begin_login("2026-09-30T12:00:00Z"),
            lambda: self.sessions.open_session("41", T0),
            lambda: self.sessions.open_session(True, T0),
            lambda: self.sessions.open_session(0, T0),
            lambda: self.sessions.issue_token(None, T0),
            lambda: self.sessions.issue_token(opened.actor, T0.replace(tzinfo=None)),
            lambda: self.sessions.logout("session", T0),
            lambda: self.sessions.sweep(T0, 0),
            lambda: SessionStore(self.database, audience="Bad Audience", environment="x"),
        )
        for index, call in enumerate(calls):
            with self.subTest(call=index), self.assertRaises(Exception) as caught:
                call()
            self.assertIn(getattr(caught.exception, "code", None),
                          {"request_invalid", "auth_required", "authority_unavailable"})


class CsrfTests(unittest.TestCase):
    def test_csrf_token_is_derived_from_its_session_only(self):
        secret, other = new_secret(), new_secret()
        token = csrf_token(secret)
        self.assertTrue(csrf_matches(secret, token))
        self.assertFalse(csrf_matches(other, token))
        self.assertNotEqual(token, secret)
        for presented in (None, "", token[:-1], token + "x", token.upper(), b"x"):
            with self.subTest(presented=repr(presented)[:8]):
                self.assertFalse(csrf_matches(secret, presented))
