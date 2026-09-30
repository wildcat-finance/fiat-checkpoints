"""Upload capabilities: bound to the latest endorsement and its grant, short-lived, single-stream and renewable."""

import asyncio
from datetime import timedelta
import json

from fiat_checkpoints.auth.refusals import AuthRefusal
from fiat_checkpoints.domain.coordination import CoordinationRefusal, QuotaPolicy
from fiat_checkpoints.persistence.transfer import Completed
from fiat_checkpoints.upload.capability import capability_sha256, presented
from fiat_checkpoints.upload.issuer import UploadIssuer
from tests.persistence_support import T0, recorded_events, run_threads
from unittest import mock

from fiat_checkpoints.persistence import transfer as transfer_module
from tests.upload_support import (ACTOR, CHUNK, OTHER_ACTOR, SCOPE, SETTINGS, UploadCase, body_steps, effect,
                                  exchange, pause, payload, revoked, run)


class IssueTests(UploadCase):
    def test_a_capability_names_one_attempt_and_closes_with_its_endorsement(self):
        data = payload(CHUNK)
        candidate, capability = self.ready(data, lifetime=120)
        self.assertEqual((capability.candidate_id, capability.attempt_number, capability.declared_size,
                          capability.archive_sha256, capability.renewed),
                         (candidate, 1, len(data), capability.archive_sha256, False))
        # The start window closes at the earliest of 15 minutes and the endorsement's expiry.
        self.assertEqual(capability.expires_at, T0 + timedelta(seconds=120))
        row = self.query("SELECT * FROM upload_capabilities")[0]
        self.assertEqual((row["capability_sha256"], row["actor_id"], row["environment"], row["declared_size"],
                          row["endorsement_sequence"], row["issues"]),
                         (capability_sha256(capability.value), ACTOR, SETTINGS.environment_id, len(data), 1, 1))
        self.assertEqual(self.state(candidate), "uploading")
        self.assertEqual(self.streams(), 1)
        long_lived = self.announce(payload(CHUNK, b"long"), "long")
        self.endorse(long_lived, payload(CHUNK, b"long"), lifetime=300)
        self.assertEqual(self.issuer.issue(ACTOR, long_lived, T0).expires_at, T0 + timedelta(seconds=300))

    def test_the_start_window_is_at_most_fifteen_minutes(self):
        data = payload(CHUNK)
        candidate = self.announce(data)
        self.endorse(candidate, data, lifetime=300)
        self.clock_now = T0 + timedelta(seconds=10)
        issued = self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual(issued.expires_at, T0 + timedelta(seconds=300))
        bound = self.endorsements.bound(ACTOR, candidate, self.clock_now)
        for until in (self.clock_now + timedelta(minutes=15, seconds=1), self.clock_now,
                      self.clock_now + timedelta(seconds=291)):
            with self.subTest(until=until), self.assertRaises(CoordinationRefusal) as caught:
                self.transfers.issue(SCOPE, ACTOR, candidate, bound, "0" * 64, SETTINGS.environment_id, until,
                                     self.clock_now)
            # Past the window, not after now, or past the endorsement it came from.
            self.assertIn(caught.exception.code, {"request_invalid", "endorsement_expired"})

    def test_an_expired_capability_refuses_and_its_stream_comes_back(self):
        data = payload(CHUNK)
        candidate, capability = self.ready(data, lifetime=60)
        self.advance(60)
        self.assert_refused(self.upload(candidate, capability, data), 410, "candidate_expired")
        self.assertEqual(self.attempts(candidate), [(1, "open")])
        self.assertEqual(self.transfers.reclaim_streams(self.clock_now), 1)
        self.assertEqual((self.attempts(candidate), self.streams()), ([(1, "abandoned")], 0))
        self.assert_refused(self.upload(candidate, capability, data), 410, "candidate_expired")
        # An expired endorsement cannot issue again; a fresh one can.
        with self.assertRaises(AuthRefusal) as caught:
            self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual(caught.exception.code, "endorsement_invalid")
        self.endorse(candidate, data)
        fresh = self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual((fresh.attempt_number, self.upload(candidate, fresh, data).status), (2, 202))

    def test_a_capability_from_a_superseded_endorsement_refuses(self):
        data = payload(CHUNK)
        candidate, capability = self.ready(data)
        self.endorse(candidate, data)
        self.assert_refused(self.upload(candidate, capability, data), 422, "endorsement_invalid")
        self.assertEqual(self.attempts(candidate), [(1, "open")])
        renewed = self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual((renewed.attempt_number, renewed.renewed), (1, True))
        self.assertEqual(self.scalar("SELECT endorsement_sequence FROM upload_capabilities"), 2)
        self.assertEqual(self.upload(candidate, renewed, data).status, 202)

    def test_a_revoked_grant_refuses_the_issue_and_the_stream(self):
        data = payload(CHUNK)
        candidate = self.announce(data)
        self.endorse(candidate, data)
        self.grants.refusal = revoked()
        with self.assertRaises(AuthRefusal):
            self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual((self.attempts(candidate), self.streams()), ([], 0))
        self.grants.refusal = None
        capability = self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.grants.refusal = revoked()
        self.assert_refused(self.upload(candidate, capability, data), 422, "endorsement_invalid")
        self.assertEqual(self.attempts(candidate), [(1, "open")])
        self.grants.refusal = None
        self.assertEqual(self.upload(candidate, capability, data).status, 202)
        # Each check named the endorsement's own grant, for `upload`, for this actor.
        self.assertEqual({(grant, actor, permission) for grant, actor, permission, _now in self.grants.checked},
                         {("6" * 64, ACTOR, "upload")})

    def test_a_revocation_during_the_transfer_stops_the_seal(self):
        data = payload(4 * CHUNK)
        candidate, capability = self.ready(data)
        steps = body_steps(data)
        steps.insert(2, effect(lambda: setattr(self.grants, "refusal", revoked())))
        self.assert_refused(self.put(candidate, capability, steps), 422, "endorsement_invalid")
        self.assertEqual(self.attempts(candidate), [(1, "failed")])
        self.assert_nothing_held(candidate)
        self.assertEqual(self.stored(), [])

    def test_issue_is_refused_for_another_actor_and_answers_a_sealed_upload(self):
        data = payload(CHUNK)
        candidate, capability = self.ready(data)
        with self.assertRaises(AuthRefusal) as caught:
            self.issuer.issue(OTHER_ACTOR, candidate, self.clock_now)
        self.assertEqual(caught.exception.code, "not_found")
        self.assertEqual(self.upload(candidate, capability, data).status, 202)
        self.endorse(candidate, data)
        done = self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertIsInstance(done, Completed)
        self.assertEqual((done.state, done.attempt_number, done.sealed_size), ("quarantined", 1, len(data)))
        self.assertEqual(self.scalar("SELECT count(*) FROM upload_attempts"), 1)

    def test_a_capability_for_another_environment_is_unknown_here(self):
        data = payload(CHUNK)
        candidate = self.announce(data)
        self.endorse(candidate, data)
        intake = type("IntakeView", (), {"coordinator": self.coordinator, "endorsements": self.endorsements,
                                         "projections": self.grants})()
        elsewhere = UploadIssuer(intake, environment="fiat-checkpoints-other").issue(ACTOR, candidate,
                                                                                     self.clock_now)
        self.assert_refused(self.upload(candidate, elsewhere, data), 401, "auth_required")

    def test_only_a_well_formed_upload_scheme_is_presented(self):
        value = "A" * 43
        self.assertEqual(presented(["Upload " + value]), value)
        self.assertEqual(presented(["upload " + value]), value)
        for values in ([], ["Upload " + value] * 2, ["Bearer " + value], ["Upload"], ["Upload  " + value],
                       ["Upload " + value + "="], ["Upload " + value[:-1]]):
            with self.subTest(values=len(values)):
                self.assertIsNone(presented(values))


class ReplayTests(UploadCase):
    def test_a_replayed_issue_renews_the_same_attempt_and_retires_the_earlier_capability(self):
        data = payload(CHUNK)
        candidate, first = self.ready(data)
        second = self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual((second.attempt_number, second.renewed, self.streams()), (1, True, 1))
        self.assertEqual(self.scalar("SELECT issues FROM upload_capabilities"), 2)
        self.assert_refused(self.upload(candidate, first, data), 401, "auth_required")
        self.assertEqual(self.upload(candidate, second, data).status, 202)
        self.assertEqual(self.upload(candidate, first, data).status, 401)

    def test_concurrent_issues_open_one_attempt_and_one_capability_works(self):
        data = payload(CHUNK)
        candidate = self.announce(data)
        self.endorse(candidate, data)
        results = run_threads(6, lambda _index: self.issuer.issue(ACTOR, candidate, self.clock_now))
        self.assertTrue(all(not isinstance(result, Exception) for result in results), results)
        self.assertEqual({result.attempt_number for result in results}, {1})
        self.assertEqual((self.scalar("SELECT count(*) FROM upload_attempts"), self.streams()), (1, 1))
        stored = self.scalar("SELECT capability_sha256 FROM upload_capabilities")
        working = [result for result in results if capability_sha256(result.value) == stored]
        self.assertEqual(len(working), 1)
        self.assertEqual(self.scalar("SELECT issues FROM upload_capabilities"), 6)
        self.assertEqual(self.upload(candidate, working[0], data).status, 202)

    def test_a_second_stream_on_the_same_capability_is_upload_in_progress(self):
        data = payload(4 * CHUNK)
        candidate, capability = self.ready(data)
        path = f"/v1/candidates/{candidate}/content"
        headers = self.headers(capability, len(data))
        steps = body_steps(data)
        slow = steps[:1] + [pause(0.5)] + steps[1:]

        async def both():
            first = asyncio.create_task(exchange(self.gateway, "PUT", path, headers, slow))
            await asyncio.sleep(0.2)
            second = await exchange(self.gateway, "PUT", path, headers, body_steps(data))
            return await first, second

        first, second = run(both())
        self.assertEqual(first.status, 202, first.text)
        self.assert_refused(second, 409, "upload_in_progress")
        self.assertEqual(self.attempts(candidate), [(1, "sealed")])
        # While the stream owned the attempt no second capability could be issued either.
        self.assertIsInstance(self.issuer.issue(ACTOR, candidate, self.clock_now), Completed)

    def test_issue_during_a_live_stream_is_upload_in_progress(self):
        data = payload(4 * CHUNK)
        candidate, capability = self.ready(data)
        seen = []

        def issue_again():
            try:
                self.issuer.issue(ACTOR, candidate, self.clock_now)
            except Exception as error:
                seen.append(getattr(error, "code", None))

        steps = body_steps(data)
        steps.insert(1, effect(issue_again))
        self.assertEqual(self.put(candidate, capability, steps).status, 202)
        self.assertEqual(seen, ["upload_in_progress"])


class QuotaTests(UploadCase):
    quotas = QuotaPolicy(streams_per_actor=2, streams_global=3)

    def test_streams_are_reserved_per_actor_and_globally_when_the_capability_is_issued(self):
        items = [payload(CHUNK, bytes([index])) for index in range(4)]
        candidates = [self.announce(data, f"quota-{index}") for index, data in enumerate(items)]
        for candidate, data in zip(candidates, items):
            self.endorse(candidate, data)
        issued = [self.issuer.issue(ACTOR, candidate, self.clock_now) for candidate in candidates[:2]]
        with recorded_events() as events:
            with self.assertRaises(CoordinationRefusal) as caught:
                self.issuer.issue(ACTOR, candidates[2], self.clock_now)
        self.assertEqual(caught.exception.code, "quota_exceeded")
        self.assertIn(("quota-refused", "actor"), [(event["event"], event.get("scope")) for event in events])
        # A sealed upload gives its stream back at once.
        self.assertEqual(self.upload(candidates[0], issued[0], items[0]).status, 202)
        self.assertEqual(self.issuer.issue(ACTOR, candidates[2], self.clock_now).attempt_number, 1)
        self.assertEqual(self.streams(), 2)
        self.assert_quota_consistent()

    def test_renewals_of_one_attempt_are_bounded(self):
        data = payload(CHUNK)
        candidate, _capability = self.ready(data)
        with mock.patch.object(transfer_module, "MAX_ISSUES", 2):
            self.issuer.issue(ACTOR, candidate, self.clock_now)
            with self.assertRaises(CoordinationRefusal) as caught:
                self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual((caught.exception.code, self.scalar("SELECT issues FROM upload_capabilities")),
                         ("quota_exceeded", 2))
        # The counter only ever steps by one, so no statement can reset it.
        connection = self.database.connect()
        try:
            with self.assertRaises(Exception):
                connection.execute("UPDATE upload_capabilities SET issues = 1")
        finally:
            connection.close()


class EventTests(UploadCase):
    def test_issue_and_stream_events_carry_fixed_fields_only(self):
        data = payload(CHUNK)
        with recorded_events() as events:
            candidate, capability = self.ready(data)
            self.issuer.issue(ACTOR, candidate, self.clock_now)
            self.upload(candidate, capability, data)
        text = json.dumps(events)
        self.assertNotIn(capability.value, text)
        issued = [event for event in events if event["event"] == "capability-issued"]
        self.assertEqual([event["kind"] for event in issued], ["new", "renewed"])
        for event in events:
            self.assertNotIn(str(ACTOR), [str(event.get(name)) for name in
                                          ("candidate", "attempt", "fence", "kind", "code", "reason", "scope")])
            self.assertLessEqual(set(event), {"event", "request_id", "route", "status", "duration_us", "code",
                                              "reason", "candidate", "attempt", "fence", "kind", "count", "scope",
                                              "from_state", "to_state", "age_ms", "job", "bytes"})
