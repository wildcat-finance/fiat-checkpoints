"""Strict framing at the gateway: exact length, no ambiguity, and bytes the gateway counted and hashed itself."""

import hashlib
import json
import uuid
from unittest import mock

from fiat_checkpoints.persistence.transfer import Transfers
from tests.persistence_support import recorded_events
from tests.upload_support import (CHUNK, UploadCase, body_steps, chunk, disconnect, exchange, payload, run,
                                  sha256)


class ExactBytesTests(UploadCase):
    def test_exact_bytes_seal_once_and_a_replay_returns_the_same_result(self):
        data = payload(3 * CHUNK + 17)
        candidate, capability = self.ready(data)
        with recorded_events() as events:
            sealed = self.upload(candidate, capability, data)
        self.assertEqual(sealed.status, 202, sealed.text)
        self.assertEqual({key: sealed.body[key] for key in ("state", "attempt", "length", "sha256", "replayed")},
                         {"state": "quarantined", "attempt": 1, "length": len(data), "sha256": sha256(data),
                          "replayed": False})
        self.assertEqual(self.attempts(candidate), [(1, "sealed")])
        self.assertEqual(self.state(candidate), "quarantined")
        [name] = self.stored()
        stored = (self.root / "quarantine" / name).read_bytes()
        self.assertEqual(stored, data)
        self.assertEqual((self.root / "quarantine" / name).stat().st_mode & 0o777, 0o400)
        self.assertEqual(self.staged(), [])
        self.assertEqual(self.streams(), 0)
        row = self.query("SELECT state, sealed_size, sealed_sha256 FROM quarantine_objects")[0]
        self.assertEqual((row["state"], row["sealed_size"], row["sealed_sha256"]), ("sealed", len(data), sha256(data)))
        self.assertEqual(self.scalar("SELECT count(*) FROM outbox_jobs WHERE kind = 'validate-candidate'"), 1)
        # The same capability replays the recorded result and never reads or stores its body.
        replayed = self.put(candidate, capability, body_steps(payload(len(data), b"other bytes")))
        self.assertEqual((replayed.status, replayed.body["replayed"], replayed.body["sha256"]),
                         (200, True, sha256(data)))
        self.assertEqual((self.root / "quarantine" / name).read_bytes(), stored)
        self.assertEqual(self.stored(), [name])
        text = json.dumps(events) + sealed.text + replayed.text
        self.assertNotIn(capability.value, text)
        names = {event["event"] for event in events}
        self.assertLessEqual({"stream-started", "upload-sealed", "gateway-request"}, names)
        request_event = [event for event in events if event["event"] == "gateway-request"][0]
        self.assertEqual((request_event["route"], request_event["bytes"], request_event["attempt"]),
                         ("/v1/candidates/{candidate_id}/content", len(data), 1))

    def test_one_byte_and_one_chunk_bodies_seal(self):
        for size in (1, CHUNK):
            with self.subTest(size=size):
                data = payload(size, str(size).encode())
                candidate, capability = self.ready(data, label=f"size-{size}")
                self.assertEqual(self.upload(candidate, capability, data).status, 202)


class AmbiguousFramingTests(UploadCase):
    def test_missing_duplicate_and_ambiguous_framing_refuse_before_any_byte_is_read(self):
        data = payload(2 * CHUNK)
        candidate, capability = self.ready(data)
        length = str(len(data))
        base = self.headers(capability, len(data))
        without = lambda *names: [pair for pair in base if pair[0] not in names]  # noqa: E731
        cases = (
            ("missing length", without("content-length"), 411, "length_required"),
            ("chunked", without("content-length") + [("transfer-encoding", "chunked")], 411, "length_required"),
            ("chunk extension", without("content-length") + [("transfer-encoding", "chunked;ext=1")], 411,
             "length_required"),
            ("length and chunked", base + [("transfer-encoding", "chunked")], 400, "request_invalid"),
            ("two lengths", base + [("content-length", length)], 400, "request_invalid"),
            ("signed length", without("content-length") + [("content-length", "+" + length)], 400,
             "request_invalid"),
            ("spaced length", without("content-length") + [("content-length", " " + length)], 400,
             "request_invalid"),
            ("exponent", without("content-length") + [("content-length", "1e5")], 400, "request_invalid"),
            ("encoding", base + [("content-encoding", "gzip")], 400, "request_invalid"),
            ("identity encoding", base + [("content-encoding", "identity")], 400, "request_invalid"),
            ("range", base + [("content-range", "bytes 0-9/131072")], 400, "request_invalid"),
            ("no type", without("content-type"), 400, "request_invalid"),
            ("json type", without("content-type") + [("content-type", "application/json")], 400,
             "request_invalid"),
            ("two types", base + [("content-type", "application/octet-stream")], 400, "request_invalid"),
            ("expectation", base + [("expect", "something-else")], 400, "request_invalid"),
            ("too many headers", base + [("x-filler", str(index)) for index in range(64)], 400, "request_invalid"),
        )
        for label, headers, status, code in cases:
            with self.subTest(case=label):
                response = self.put(candidate, capability, body_steps(data), headers=headers)
                self.assert_refused(response, status, code)
        self.assert_refused(self._with_query(candidate, base, data), 400, "request_invalid")
        # Nothing started: the same capability still seals the exact bytes.
        self.assertEqual(self.attempts(candidate), [(1, "open")])
        self.assertIsNone(self.scalar("SELECT stream_started_at FROM upload_attempts"))
        self.assertEqual(self.upload(candidate, capability, data).status, 202)

    def _with_query(self, candidate, headers, data):
        """The same request with a query string, which the fixed route never takes."""
        async def with_query(scope, receive, send):
            await self.gateway(dict(scope, query_string=b"part=2"), receive, send)

        return run(exchange(with_query, "PUT", f"/v1/candidates/{candidate}/content", headers, body_steps(data)))

    def test_a_declared_length_over_the_ceiling_or_other_than_the_capability_refuses(self):
        data = payload(CHUNK)
        candidate, capability = self.ready(data)
        over = self.put(candidate, capability, body_steps(data), length=1_073_741_825)
        self.assert_refused(over, 413, "upload_too_large")
        huge = self.put(candidate, capability, body_steps(data), length=10**18)
        self.assert_refused(huge, 413, "upload_too_large")
        for length in (0, len(data) - 1, len(data) + 1):
            with self.subTest(length=length):
                self.assert_refused(self.put(candidate, capability, body_steps(data), length=length), 422,
                                    "upload_integrity")
        self.assertEqual(self.attempts(candidate), [(1, "open")])
        self.assertEqual(self.upload(candidate, capability, data).status, 202)


class WrongBytesTests(UploadCase):
    def assert_failed(self, candidate, response):
        self.assert_refused(response, 422, "upload_integrity")
        self.assertEqual(self.attempts(candidate), [(1, "failed")])
        self.assert_nothing_held(candidate)
        self.assertEqual(self.stored(), [])
        failed = self.query("SELECT code FROM audit_events WHERE event = 'upload-failed'")
        self.assertEqual([row["code"] for row in failed], ["upload_integrity"])

    def test_extra_bytes_refuse_and_fail_the_attempt(self):
        data = payload(2 * CHUNK)
        candidate, capability = self.ready(data)
        steps = body_steps(data)[:-1] + [chunk(data[CHUNK:] + b"x", False)]
        with recorded_events() as events:
            response = self.put(candidate, capability, steps)
        self.assert_failed(candidate, response)
        self.assertIn(("gateway-request", "body-extra"), [(event["event"], event.get("reason")) for event in events])
        # A trailing chunk after the declared bytes is extra too.
        second = self.issuer.issue(41, candidate, self.clock_now)
        response = self.put(candidate, second, body_steps(data)[:-1] + [chunk(data[CHUNK:]), chunk(b"y", False)])
        self.assert_refused(response, 422, "upload_integrity")
        self.assertEqual(self.attempts(candidate), [(1, "failed"), (2, "failed")])
        third = self.issuer.issue(41, candidate, self.clock_now)
        self.assertEqual(self.upload(candidate, third, data).status, 202)
        self.assertEqual(self.attempts(candidate), [(1, "failed"), (2, "failed"), (3, "sealed")])

    def test_a_short_body_and_an_early_disconnect_refuse(self):
        data = payload(3 * CHUNK)
        candidate, capability = self.ready(data)
        short = body_steps(data)[:-1] + [chunk(b"", False)]
        self.assert_failed(candidate, self.put(candidate, capability, short))
        second = self.issuer.issue(41, candidate, self.clock_now)
        response = self.put(candidate, second, body_steps(data)[:1] + [disconnect()])
        self.assert_refused(response, 422, "upload_integrity")
        self.assertEqual(self.attempts(candidate), [(1, "failed"), (2, "failed")])
        self.assert_nothing_held(candidate)

    def test_a_changed_digest_refuses_and_stores_nothing(self):
        data = payload(2 * CHUNK)
        candidate, capability = self.ready(data)
        changed = bytearray(data)
        changed[CHUNK] ^= 1
        with recorded_events() as events:
            response = self.put(candidate, capability, body_steps(bytes(changed)))
        self.assert_failed(candidate, response)
        self.assertIn("digest-mismatch", [event.get("reason") for event in events])
        self.assertEqual(self.state(candidate), "uploading")


class CredentialTests(UploadCase):
    def test_missing_malformed_foreign_and_replaced_capabilities_refuse(self):
        data = payload(CHUNK)
        candidate, capability = self.ready(data)
        base = self.headers(capability, len(data))
        others = [pair for pair in base if pair[0] != "authorization"]
        cases = (
            ("none", others, 401, "auth_required"),
            ("bearer", others + [("authorization", "Bearer " + capability.value)], 401, "auth_required"),
            ("two", base + [("authorization", "Upload " + capability.value)], 401, "auth_required"),
            ("short", others + [("authorization", "Upload " + capability.value[:-1])], 401, "auth_required"),
            ("no value", others + [("authorization", "Upload")], 401, "auth_required"),
            ("unknown", others + [("authorization", "Upload " + "A" * 43)], 401, "auth_required"),
        )
        for label, headers, status, code in cases:
            with self.subTest(case=label):
                self.assert_refused(self.put(candidate, capability, body_steps(data), headers=headers), status, code)
        for path in (f"/v1/candidates/{uuid.uuid4()}/content", "/v1/candidates/not-a-uuid/content",
                     f"/v1/candidates/{str(candidate).upper()}/content", f"/v1/candidates/{candidate}/content/x",
                     "/v1/candidates/../content", "/v1/other"):
            with self.subTest(path=path):
                response = run(exchange(self.gateway, "PUT", path, base, body_steps(data)))
                self.assert_refused(response, 404, "not_found")
        self.assert_refused(run(exchange(self.gateway, "POST", f"/v1/candidates/{candidate}/content", base,
                                         body_steps(data))), 404, "not_found")
        # A second issue replaces the first capability; the first stops working.
        renewed = self.issuer.issue(41, candidate, self.clock_now)
        self.assertEqual(renewed.attempt_number, capability.attempt_number)
        self.assert_refused(self.upload(candidate, capability, data), 401, "auth_required")
        self.assertEqual(self.upload(candidate, renewed, data).status, 202)

    def test_the_capability_never_reaches_a_response_event_or_representation(self):
        data = payload(CHUNK)
        candidate, capability = self.ready(data)
        self.assertNotIn(capability.value, repr(capability))
        self.assertNotIn(capability.value, str(self.query("SELECT * FROM upload_capabilities")))
        with recorded_events() as events:
            responses = [self.put(uuid.uuid4(), capability, body_steps(data)),
                         self.put(candidate, capability, body_steps(data), length=len(data) + 1),
                         self.upload(candidate, capability, data)]
        text = json.dumps(events) + "".join(response.text for response in responses)
        self.assertNotIn(capability.value, text)
        self.assertNotIn(hashlib.sha256(capability.value.encode()).hexdigest(), text)

    def test_an_unexpected_failure_is_a_fixed_refusal_without_its_message(self):
        data = payload(CHUNK)
        candidate, capability = self.ready(data)
        with mock.patch.object(Transfers, "capability", side_effect=RuntimeError("private-failure-marker")):
            with recorded_events() as events:
                response = self.upload(candidate, capability, data)
        self.assert_refused(response, 503, "authority_unavailable")
        self.assertNotIn("private-failure-marker", response.text + json.dumps(events))
        self.assertEqual(self.upload(candidate, capability, data).status, 202)


class HealthTests(UploadCase):
    def test_the_gateway_answers_liveness_and_stays_unready(self):
        live = run(exchange(self.gateway, "GET", "/health/live", [], []))
        ready = run(exchange(self.gateway, "GET", "/health/ready", [], []))
        self.assertEqual((live.status, live.body["status"]), (200, "live"))
        self.assertEqual((ready.status, ready.body["code"]), (503, "intake-closed"))
        self.assertEqual(live.header("cache-control"), "no-store")

    def test_lifespan_messages_are_answered(self):
        sent, messages = [], [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]

        async def receive():
            return messages.pop(0)

        async def send(message):
            sent.append(message["type"])

        run(self.gateway({"type": "lifespan"}, receive, send))
        self.assertEqual(sent, ["lifespan.startup.complete", "lifespan.shutdown.complete"])
