"""The HTTP adapters for login, sessions and tokens, with credentials that start no verifier process."""

import asyncio
from dataclasses import replace
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fiat_checkpoints.api.app import StartupRefusal, production_refusals
from fiat_checkpoints.api.intake import LOGIN_COOKIE, SESSION_COOKIE, IntakeServices, create_intake_app
from fiat_checkpoints.auth import sessions as sessions_module
from fiat_checkpoints.auth.refusals import PUBLIC_STATUS
from fiat_checkpoints.auth.sessions import SessionStore
from fiat_checkpoints.auth.tokens import csrf_token, new_secret
from fiat_checkpoints.domain.transitions import Evidence
from fiat_checkpoints.grants.endorsement import EndorsementStore
from fiat_checkpoints.grants.intake import Intake
from fiat_checkpoints.persistence.coordinator import Unavailable
from tests.auth_support import (SETTINGS, Clock, FakeProvider, StubProjections, T0, build, request, session_headers,
                                set_cookies, user_document)
from tests.persistence_support import ACTOR, IDENTITIES, DatabaseCase, at, recorded_events


class ApiCase(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        self.provider = FakeProvider()
        self.projections = StubProjections(granted={41})
        self.app, self.services = build(self.database, self.clock, provider=self.provider,
                                        projections=self.projections)

    def call(self, method, path, **options):
        return request(self.app, method, path, **options)

    def assert_refused(self, response, code):
        self.assertEqual((response.status_code, response.json()["code"]), (PUBLIC_STATUS[code], code))
        # Only a quota or dependency refusal names a wait, in the header and the body alike.
        retry = {429: 60, 503: 30}.get(response.status_code)
        self.assertEqual(set(response.json()), {"request_id", "code"} | ({"retry_after_seconds"} if retry else set()))
        self.assertEqual((response.headers.get("retry-after"), response.json().get("retry_after_seconds")),
                         (None if retry is None else str(retry), retry))
        self.assertEqual(response.headers["cache-control"], "no-store")

    def browser_login(self, user_id=41, login="contributor"):
        started = self.call("POST", "/v1/login")
        self.assertEqual(started.status_code, 200)
        binding = set_cookies(started)[LOGIN_COOKIE][0]
        state, code = self.provider.authorize(started.json()["authorization_url"], user_document(user_id, login))
        finished = self.call("GET", f"/v1/login/callback?code={code}&state={state}",
                             cookies={LOGIN_COOKIE: binding})
        return started, finished


class LoginRouteTests(ApiCase):
    def test_login_sets_host_prefixed_cookies_and_returns_a_csrf_token(self):
        started, finished = self.browser_login()
        _, login_attributes = set_cookies(started)[LOGIN_COOKIE]
        for attribute in ("Max-Age=300", "Path=/", "Secure", "HttpOnly", "SameSite=lax"):
            self.assertIn(attribute, login_attributes)
        self.assertEqual(finished.status_code, 200)
        secret, attributes = set_cookies(finished)[SESSION_COOKIE]
        for attribute in ("Max-Age=28800", "Path=/", "Secure", "HttpOnly", "SameSite=strict"):
            self.assertIn(attribute, attributes)
        self.assertNotIn("Domain", attributes)
        self.assertEqual(finished.json()["csrf_token"], csrf_token(secret))
        self.assertEqual((finished.headers["referrer-policy"], finished.headers["cache-control"]),
                         ("no-referrer", "no-store"))
        self.assertIn("Max-Age=0", set_cookies(finished)[LOGIN_COOKIE][1])
        self.assertIn("code_challenge_method=S256", started.json()["authorization_url"])
        self.assertEqual(self.call("GET", "/v1/session", cookies={SESSION_COOKIE: secret}).json()["csrf_token"],
                         csrf_token(secret))

    def test_callback_query_names_exactly_code_and_state(self):
        started = self.call("POST", "/v1/login")
        binding = set_cookies(started)[LOGIN_COOKIE][0]
        state, code = self.provider.authorize(started.json()["authorization_url"], user_document(41, "a"))
        for query in (f"code={code}", f"state={state}", f"code={code}&state={state}&user_id=99",
                      f"code={code}&state={state}&login=someone", f"code={code}&state={state}&state={state}",
                      f"code={code}&state={state}&access_token=x", "code&state", "%ff=1",
                      f"code={code}&state={state}&" + "x" * 2000):
            with self.subTest(query=query[:30]):
                self.assert_refused(self.call("GET", "/v1/login/callback?" + query, cookies={LOGIN_COOKIE: binding}),
                                    "request_invalid")
        self.assertEqual(self.scalar("SELECT count(*) FROM sessions"), 0)
        self.assertEqual(self.call("GET", f"/v1/login/callback?code={code}&state={state}",
                                   cookies={LOGIN_COOKIE: binding}).status_code, 200)

    def test_callback_needs_its_own_browser_binding(self):
        started = self.call("POST", "/v1/login")
        binding = set_cookies(started)[LOGIN_COOKIE][0]
        state, code = self.provider.authorize(started.json()["authorization_url"], user_document(41, "a"))
        path = f"/v1/login/callback?code={code}&state={state}"
        self.assert_refused(self.call("GET", path), "auth_required")
        self.assert_refused(self.call("GET", path, headers={"cookie": f"{LOGIN_COOKIE}={binding}; "
                                                                      f"{LOGIN_COOKIE}={new_secret()}"}),
                            "auth_required")
        self.assert_refused(self.call("GET", path, cookies={LOGIN_COOKIE: new_secret()}), "auth_required")
        self.assertEqual(self.scalar("SELECT count(*) FROM sessions"), 0)

    def test_login_start_takes_no_body(self):
        self.assert_refused(self.call("POST", "/v1/login", content=b'{"user_id":41}'), "request_invalid")


class CredentialTests(ApiCase):
    def setUp(self):
        super().setUp()
        self.opened = self.services.sessions.open_session(41, T0)

    def test_unsafe_browser_requests_need_the_csrf_token(self):
        cookie = {SESSION_COOKIE: self.opened.secret}
        self.assert_refused(self.call("POST", "/v1/access-tokens", cookies=cookie), "auth_required")
        for token in (new_secret(), csrf_token(new_secret()), "", self.opened.secret):
            with self.subTest(token=token[:4]):
                self.assert_refused(self.call("POST", "/v1/access-tokens", cookies=cookie,
                                              headers={"x-csrf-token": token}), "auth_required")
        self.assertEqual(self.call("POST", "/v1/access-tokens", headers=session_headers(self.opened)).status_code,
                         200)

    def test_a_request_carries_exactly_one_credential(self):
        token = self.services.sessions.issue_token(self.opened.actor, T0).token
        both = session_headers(self.opened) | {"authorization": "Bearer " + token}
        cases = (both, {"authorization": "Basic " + token}, {"authorization": "bearer " + token},
                 {"authorization": "Bearer"}, {"cookie": f"{SESSION_COOKIE}={self.opened.secret}; "
                                                         f"{SESSION_COOKIE}={self.opened.secret}",
                                               "x-csrf-token": self.opened.csrf_token},
                 {"cookie": "x=" + "y" * 5000}, {})
        for headers in cases:
            with self.subTest(headers=sorted(headers)):
                self.assert_refused(self.call("GET", "/v1/session", headers=headers), "auth_required")

    def test_provider_and_personal_tokens_are_not_credentials(self):
        for token in ("ghp_" + "a" * 36, "gho_" + "b" * 36, "github_pat_" + "c" * 30, self.opened.secret,
                      "v1." + "d" * 40, new_secret()):
            with self.subTest(prefix=token[:4]):
                self.assert_refused(self.call("POST", "/v1/access-tokens",
                                              headers={"authorization": "Bearer " + token}), "auth_required")

    def test_pairing_needs_a_current_grant_and_renewal_spends_the_token(self):
        paired = self.call("POST", "/v1/access-tokens", headers=session_headers(self.opened))
        token = paired.json()["access_token"]
        self.assertEqual(paired.json()["expires_at"], "2026-09-30T12:15:00Z")
        renewed = self.call("POST", "/v1/access-tokens", headers={"authorization": "Bearer " + token})
        self.assertEqual(renewed.status_code, 200)
        self.assert_refused(self.call("POST", "/v1/access-tokens", headers={"authorization": "Bearer " + token}),
                            "auth_required")
        self.projections.granted.clear()
        self.assert_refused(self.call("POST", "/v1/access-tokens",
                                      headers={"authorization": "Bearer " + renewed.json()["access_token"]}),
                            "not_found")

    def test_logout_clears_the_cookie_and_ends_every_paired_token(self):
        token = self.call("POST", "/v1/access-tokens", headers=session_headers(self.opened)).json()["access_token"]
        ended = self.call("POST", "/v1/logout", headers=session_headers(self.opened))
        self.assertEqual((ended.status_code, ended.json()["state"]), (200, "revoked"))
        self.assertIn("Max-Age=0", set_cookies(ended)[SESSION_COOKIE][1])
        self.assert_refused(self.call("GET", "/v1/session", cookies={SESSION_COOKIE: self.opened.secret}),
                            "auth_required")
        self.assert_refused(self.call("POST", "/v1/access-tokens", headers={"authorization": "Bearer " + token}),
                            "auth_required")

    def test_session_expiry_is_the_service_clock(self):
        self.clock.advance(8 * 3600)
        self.assert_refused(self.call("GET", "/v1/session", cookies={SESSION_COOKIE: self.opened.secret}),
                            "auth_required")


class BoundaryTests(ApiCase):
    def test_bodies_are_bounded_and_framed(self):
        opened = self.services.sessions.open_session(41, T0)
        headers = session_headers(opened) | {"idempotency-key": "k" * 16}
        cases = (
            (b"x" * 65_537, {}),
            (b"{}", {"content-length": "70000"}),
            (b"{}", {"content-encoding": "gzip"}),
            (b"[]", {}), (b'{"a":1,"a":1}', {}), (b'{"a":1.5}', {}), (b'{"a":NaN}', {}), (b"\xff", {}),
            (b"[" * 5000 + b"]" * 5000, {}), (b"", {}),
        )
        for body, extra in cases:
            with self.subTest(size=len(body), extra=sorted(extra)):
                self.assert_refused(self.call("POST", "/v1/candidates", content=body, headers=headers | extra),
                                    "request_invalid")

    def test_an_oversized_stream_is_refused_after_at_most_one_chunk_past_the_limit(self):
        opened = self.services.sessions.open_session(41, T0)
        delivered = {"bytes": 0}
        chunk, total = b"{" + b" " * 16_383, 1_048_576
        messages = []

        async def receive():
            if delivered["bytes"] >= total:
                return {"type": "http.disconnect"}
            delivered["bytes"] += len(chunk)
            return {"type": "http.request", "body": chunk, "more_body": delivered["bytes"] < total}

        async def send(message):
            messages.append(message)

        cookie = f"{SESSION_COOKIE}={opened.secret}".encode()
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
                 "scheme": "https", "path": "/v1/candidates", "raw_path": b"/v1/candidates", "query_string": b"",
                 "root_path": "", "server": ("testserver", 443), "client": ("127.0.0.1", 1),
                 "headers": [(b"host", b"testserver"), (b"cookie", cookie),
                             (b"x-csrf-token", opened.csrf_token.encode()), (b"idempotency-key", b"k" * 16),
                             (b"transfer-encoding", b"chunked")]}
        asyncio.run(self.app(scope, receive, send))
        status = next(message["status"] for message in messages if message["type"] == "http.response.start")
        self.assertEqual(status, 400)
        # The limit is 65,536 bytes; the refusal comes within one 16 KiB chunk of it.
        self.assertLessEqual(delivered["bytes"], 65_536 + len(chunk))
        self.assertLess(delivered["bytes"], total)

    def test_unknown_routes_and_methods_read_as_not_found(self):
        for method, path in (("GET", "/v1/unknown"), ("DELETE", "/v1/login"), ("PUT", "/v1/session"),
                             ("GET", "/internal/v1/authority-records"), ("GET", "/v1/runs/1/x/frontier")):
            with self.subTest(method=method, path=path):
                self.assert_refused(self.call(method, path), "not_found")

    def test_unexpected_failures_are_one_fixed_code_without_their_text(self):
        class Failing(SessionStore):
            def begin_login(self, now):
                raise RuntimeError("private-failure-marker")

        failing = Failing(self.database, audience=SETTINGS.service_id, environment=SETTINGS.environment_id)
        app = create_intake_app(SETTINGS, replace(self.services, sessions=failing))
        with recorded_events() as events:
            response = request(app, "POST", "/v1/login")
        self.assert_refused(response, "authority_unavailable")
        self.assertNotIn("private-failure-marker", response.text + json.dumps(events))

    def test_quota_and_dependency_refusals_carry_a_bounded_retry_after(self):
        with mock.patch.object(sessions_module, "MAX_LIVE_LOGIN_STATES", 1):
            self.assertEqual(self.call("POST", "/v1/login").status_code, 200)
            limited = self.call("POST", "/v1/login")
        self.assertEqual((limited.status_code, limited.headers.get("retry-after"),
                          limited.json().get("retry_after_seconds")), (429, "60", 60))

        class Failing(SessionStore):
            def begin_login(self, now):
                raise RuntimeError("private-failure-marker")

        failing = Failing(self.database, audience=SETTINGS.service_id, environment=SETTINGS.environment_id)
        failed = request(create_intake_app(SETTINGS, replace(self.services, sessions=failing)), "POST", "/v1/login")
        self.assertEqual((failed.status_code, failed.headers.get("retry-after"),
                          failed.json().get("retry_after_seconds")), (503, "30", 30))
        for response in (self.call("GET", "/v1/session"), self.call("GET", "/v1/unknown")):
            self.assertEqual((response.headers.get("retry-after"), response.json().get("retry_after_seconds")),
                             (None, None))

    def test_events_are_fixed_fields_without_credentials(self):
        with recorded_events() as events:
            started, finished = self.browser_login()
            secret = set_cookies(finished)[SESSION_COOKIE][0]
            token = self.call("POST", "/v1/access-tokens", headers={
                "cookie": f"{SESSION_COOKIE}={secret}", "x-csrf-token": finished.json()["csrf_token"]}).json()
            self.call("POST", "/v1/access-tokens", headers={"authorization": "Bearer ghp_" + "a" * 36})
        text = json.dumps(events)
        for value in (secret, finished.json()["csrf_token"], token["access_token"],
                      set_cookies(started)[LOGIN_COOKIE][0], "ghp_", "contributor"):
            self.assertNotIn(value, text)
        allowed = {"event", "request_id", "route", "status", "duration_us", "code", "reason", "protocol_code",
                   "kind", "count"}
        self.assertTrue(events)
        for event in events:
            self.assertLessEqual(set(event), allowed)
        self.assertEqual(events[-1]["reason"], "token-malformed")

    def test_production_wiring_refuses_with_the_fixed_startup_codes(self):
        production = replace(SETTINGS, profile="production")
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(StartupRefusal) as caught:
                create_intake_app(production, self.services, Path(temporary))
            self.assertEqual(caught.exception.codes, production_refusals(production, Path(temporary)))
        self.assertIn("scaffold-only", caught.exception.codes)
        for services, code in (
            (replace(self.services, sessions=SessionStore(self.database, audience="another-service",
                                                          environment=SETTINGS.environment_id)),
             "configuration-value"),
            (replace(self.services, projections=type("Production", (StubProjections,),
                                                     {"environment": "production"})()),
             "configuration-local-identity"),
            (object(), "scaffold-only"),
        ):
            with self.subTest(code=code), self.assertRaises(StartupRefusal) as caught:
                create_intake_app(SETTINGS, services)
            self.assertEqual(caught.exception.codes, (code,))


class MalformedEntryPointTests(ApiCase):
    """Every intake entry point answers malformed input with a fixed code before any library call."""

    def test_intake_operations_refuse_malformed_arguments(self):
        intake = Intake(self.database, self.coordinator, self.projections)
        bodies = (None, [], {}, {"run": 1}, {"run": {}, "identities": {}, "carrier_length": 1, "parent": {}},
                  {"run": {"repository_id": True, "run_id": "r"}, "identities": {}, "carrier_length": 1,
                   "parent": {}})
        calls = [lambda body=body: intake.announce(41, "k" * 16, body, T0) for body in bodies]
        calls += [lambda: intake.announce("41", "k" * 16, {}, T0), lambda: intake.announce(41, "k", {}, "now"),
                  lambda: intake.endorse(41, "c", "not-bytes", T0), lambda: intake.endorse(41, "c", b"", T0),
                  lambda: intake.endorse(41, "c", b"x" * 65_537, T0), lambda: intake.status(0, "c", T0),
                  lambda: intake.prove_enrollment(41, 7, "r", [], T0),
                  lambda: intake.prove_enrollment(41, 7, "r", {"challenge": {}, "signature": ""}, T0),
                  lambda: intake.prove_enrollment(41, 7, "r", {"challenge": {"type": "enrollment-challenge",
                                                                             "sha256": "A" * 64},
                                                               "signature": "x"}, T0)]
        for index, call in enumerate(calls):
            with self.subTest(call=index), self.assertRaises(Exception) as caught:
                call()
            self.assertIn(getattr(caught.exception, "code", None), {"request_invalid", "not_found"})

    def test_routes_answer_malformed_paths_and_headers_with_fixed_codes(self):
        opened = self.services.sessions.open_session(41, T0)
        headers = session_headers(opened)
        cases = (
            ("POST", "/v1/candidates/not-a-uuid/endorsement", headers, b"{}", "not_found"),
            ("GET", "/v1/candidates/00000000-0000-0000-0000-00000000000G", headers, b"", "not_found"),
            ("POST", "/v1/runs/0/run/enrollment-proofs", headers, b"{}", "not_found"),
            ("POST", "/v1/runs/99999999999999999999/run/enrollment-proofs", headers, b"{}", "not_found"),
            ("POST", "/v1/runs/7/run/enrollment-proofs", headers | {"content-length": "x"}, b"", "request_invalid"),
            ("POST", "/v1/candidates", headers, b"{}", "request_invalid"),
            ("POST", "/v1/logout", headers, b"abc", "request_invalid"),
            ("POST", "/v1/access-tokens", headers | {"transfer-encoding": "chunked", "content-length": "0"}, b"",
             "request_invalid"),
        )
        for method, path, extra, content, code in cases:
            with self.subTest(path=path, code=code):
                response = self.call(method, path, headers=extra, content=content)
                self.assertEqual((response.status_code, response.json()["code"]), (PUBLIC_STATUS[code], code))
        self.assertEqual(self.services.sessions.session(opened.secret, T0).actor_id, 41)


class GrantingProjections:
    """Every read is granted; the status checks start no verifier process."""

    environment = "test"

    def run_for(self, scope):
        return SimpleNamespace(scope=scope)

    def current(self, _run):
        return SimpleNamespace(grant=lambda *_arguments: None)

    def any_grant(self, _actor_id, _now):
        return True


class StatusRetryTests(DatabaseCase):
    def test_a_candidate_retrying_a_dependency_reports_a_bounded_wait(self):
        clock = Clock(at(1))
        app, services = build(self.database, clock, projections=GrantingProjections())
        candidate = self.quarantined()
        EndorsementStore(self.database).bind(candidate, IDENTITIES, "5" * 64, T0)
        path = f"/v1/candidates/{candidate}"
        headers = session_headers(services.sessions.open_session(ACTOR, T0))
        quiet = request(app, "GET", path, headers=headers)
        self.assertEqual((quiet.status_code, quiet.json().get("retry_after_seconds")), (200, None))
        claim = self.coordinator.claim_validation({Evidence.ISOLATED_WORKER}, at(1))
        self.coordinator.complete_validation(claim.lease, Unavailable("sandbox_unavailable"), at(1))
        retrying = request(app, "GET", path, headers=headers)
        self.assertEqual((retrying.status_code, retrying.json()["state"], retrying.json().get("retry_after_seconds")),
                         (200, "validating", 30))
        self.assertIsNone(retrying.headers.get("retry-after"))
