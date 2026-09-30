"""The API role's upload routes: a new attempt's capability, completion and their fixed refusals."""

import json
import uuid

from fiat_checkpoints.auth.refusals import PUBLIC_STATUS
from fiat_checkpoints.domain.coordination import QuotaPolicy
from fiat_checkpoints.upload.capability import IssuedCapability
from tests.auth_support import build, request, session_headers
from tests.persistence_support import T0, recorded_events
from tests.upload_support import ACTOR, CHUNK, OTHER_ACTOR, UploadCase, body_steps, payload, sha256


class RouteCase(UploadCase):
    def setUp(self):
        super().setUp()
        self.app, self.api = build(self.database, self.clock, projections=self.grants, quotas=self.quotas)
        self.session = self.api.sessions.open_session(ACTOR, T0)

    def call(self, method, path, session=None, headers=None, **options):
        merged = session_headers(session or self.session) | (headers or {})
        return request(self.app, method, path, headers=merged, **options)

    def attempt(self, candidate, key="attempt-key-0001", session=None, **options):
        return self.call("POST", f"/v1/candidates/{candidate}/upload-attempts", session,
                         headers={"idempotency-key": key}, **options)

    def complete(self, candidate, body, content_type="application/json", session=None):
        return self.call("POST", f"/v1/candidates/{candidate}/complete", session,
                         headers={"content-type": content_type}, content=json.dumps(body).encode())

    def assert_code(self, response, code):
        self.assertEqual((response.status_code, response.json()["code"]), (PUBLIC_STATUS[code], code), response.text)
        retry = {429: 60, 503: 30}.get(response.status_code)
        self.assertEqual(response.headers.get("retry-after"), None if retry is None else str(retry))


class UploadAttemptRouteTests(RouteCase):
    def capability_of(self, response):
        upload = response.json()["upload"]
        return IssuedCapability(upload["capability"], uuid.UUID(response.json()["candidate_id"]), upload["attempt"],
                                None, upload["length"], upload["sha256"], False)

    def test_a_new_attempt_is_issued_renewed_and_then_answered_with_the_sealed_result(self):
        data = payload(2 * CHUNK)
        candidate = self.announce(data)
        self.endorse(candidate, data)
        created = self.attempt(candidate)
        self.assertEqual(created.status_code, 201, created.text)
        body = created.json()
        self.assertEqual((body["state"], body["upload"]["attempt"], body["upload"]["length"], body["upload"]["sha256"],
                          body["upload"]["expires_at"]), ("uploading", 1, len(data), sha256(data),
                                                          "2026-09-30T12:02:00Z"))
        self.assertEqual(created.headers["cache-control"], "no-store")
        renewed = self.attempt(candidate, "attempt-key-0002")
        self.assertEqual((renewed.status_code, renewed.json()["upload"]["attempt"]), (200, 1))
        self.assertNotEqual(renewed.json()["upload"]["capability"], body["upload"]["capability"])
        self.assertEqual(self.upload(candidate, self.capability_of(renewed), data).status, 202)
        done = self.attempt(candidate)
        self.assertEqual((done.status_code, done.json()["state"], done.json()["upload"]), (200, "quarantined", None))

    def test_the_route_needs_its_session_csrf_key_and_an_empty_body(self):
        data = payload(CHUNK)
        candidate = self.announce(data)
        self.endorse(candidate, data)
        path = f"/v1/candidates/{candidate}/upload-attempts"
        cookie_only = {"cookie": session_headers(self.session)["cookie"], "idempotency-key": "attempt-key-0001"}
        self.assert_code(request(self.app, "POST", path, headers=cookie_only), "auth_required")
        for headers in ({}, {"idempotency-key": "short"}):
            with self.subTest(headers=headers):
                self.assert_code(self.call("POST", path, headers=headers), "request_invalid")
        self.assert_code(self.call("POST", path, headers={"idempotency-key": "attempt-key-0001"}, content=b"{}"),
                         "request_invalid")
        other = self.api.sessions.open_session(OTHER_ACTOR, T0)
        self.assert_code(self.attempt(candidate, session=other), "not_found")
        self.assert_code(self.attempt(uuid.uuid4()), "not_found")
        self.assert_code(self.attempt("not-a-uuid"), "not_found")
        self.assertEqual(self.scalar("SELECT count(*) FROM upload_attempts"), 0)

    def test_the_capability_never_reaches_an_event(self):
        data = payload(CHUNK)
        candidate = self.announce(data)
        self.endorse(candidate, data)
        with recorded_events() as events:
            created = self.attempt(candidate)
        self.assertNotIn(created.json()["upload"]["capability"], json.dumps(events))


class QuotaRouteTests(RouteCase):
    quotas = QuotaPolicy(streams_per_actor=1)

    def test_a_stream_quota_refusal_carries_a_bounded_retry_after(self):
        items = [payload(CHUNK, bytes([index])) for index in range(2)]
        candidates = [self.announce(data, f"route-quota-{index}") for index, data in enumerate(items)]
        for candidate, data in zip(candidates, items):
            self.endorse(candidate, data)
        self.assertEqual(self.attempt(candidates[0]).status_code, 201)
        limited = self.attempt(candidates[1])
        self.assert_code(limited, "quota_exceeded")
        self.assertEqual(limited.json()["retry_after_seconds"], 60)


class CompleteRouteTests(RouteCase):
    def test_complete_confirms_only_what_the_gateway_sealed(self):
        data = payload(2 * CHUNK)
        candidate, capability = self.ready(data)
        claim = {"attempt": 1, "length": len(data), "sha256": sha256(data)}
        self.assert_code(self.complete(candidate, claim), "upload_in_progress")
        self.assertEqual(self.upload(candidate, capability, data).status, 202)
        done = self.complete(candidate, claim)
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual({key: done.json()[key] for key in ("state", "attempt", "length", "sha256")},
                         {"state": "quarantined", "attempt": 1, "length": len(data), "sha256": sha256(data)})
        for changed in ({"attempt": 2}, {"length": len(data) - 1}, {"sha256": "0" * 64}):
            with self.subTest(changed=changed):
                self.assert_code(self.complete(candidate, claim | changed), "upload_integrity")

    def test_a_failed_attempt_never_completes_and_malformed_claims_refuse(self):
        data = payload(2 * CHUNK)
        candidate, capability = self.ready(data)
        self.put(candidate, capability, body_steps(data)[:1] + [("chunk", b"", False)])
        claim = {"attempt": 1, "length": len(data), "sha256": sha256(data)}
        self.assert_code(self.complete(candidate, claim), "upload_integrity")
        for body in ({}, {"attempt": 1}, claim | {"extra": 1}, claim | {"attempt": "1"}, claim | {"attempt": 17},
                     claim | {"length": 0}, claim | {"sha256": "A" * 64}, claim | {"length": True}):
            with self.subTest(body=sorted(body)):
                self.assert_code(self.complete(candidate, body), "request_invalid")
        for content_type in ("text/plain", "application/json; charset=latin-1", "application/jsonx"):
            with self.subTest(content_type=content_type):
                self.assert_code(self.complete(candidate, claim, content_type), "request_invalid")
        self.assert_code(self.call("POST", f"/v1/candidates/{candidate}/complete",
                                   headers={"content-type": "application/json"}, content=b"{"), "request_invalid")
        other = self.api.sessions.open_session(OTHER_ACTOR, T0)
        self.assert_code(self.complete(candidate, claim, session=other), "not_found")
        accepted = self.complete(candidate, claim, "application/json; charset=utf-8")
        self.assert_code(accepted, "upload_integrity")
