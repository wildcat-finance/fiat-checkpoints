"""Upload capabilities: bound to the latest endorsement and its grant, short-lived, single-stream and renewable."""

import asyncio
from datetime import timedelta
import json
import secrets
from types import SimpleNamespace

from fiat_checkpoints.auth.refusals import AuthRefusal, public
from fiat_checkpoints.domain.coordination import CoordinationRefusal, QuotaPolicy
from fiat_checkpoints.domain.identities import CheckpointIdentities
from fiat_checkpoints.grants.endorsement import Terms
from fiat_checkpoints.persistence.transfer import Completed, object_key
from fiat_checkpoints.upload.capability import capability_sha256, presented
from fiat_checkpoints.upload.issuer import UploadIssuer
from tests.persistence_support import T0, recorded_events, run_threads
from unittest import mock

from fiat_checkpoints.persistence import transfer as transfer_module
from tests.upload_support import (ACTOR, CHUNK, OTHER_ACTOR, PARENT, SCOPE, SETTINGS, UploadCase, body_steps, effect,
                                  disconnect, exchange, pause, payload, revoked, run, sha256)


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


class LiveStreamEndorsementTests(UploadCase):
    """A new endorsement waits while a stream holds its candidate (Laurence, 2026-10-01).

    Endorsements go through `EndorsementStore.record`, as the endorsement route
    records them after the library has verified the envelope.
    """

    def setUp(self):
        super().setUp()
        self.head = None

    def recorded(self, candidate, data, label, actor=ACTOR, nonce=None, lifetime=120):
        """Bind the candidate's current challenge and record one synthetic verified endorsement for it."""
        now = self.clock_now
        if self.head is None:
            # `record` compares the stored trust head it was given; nothing here verifies the row.
            policy = b"synthetic-policy"
            run_key = self.scalar("SELECT run_key FROM candidates WHERE candidate_id = %s", (candidate,))
            connection = self.database.connect()
            try:
                connection.execute("INSERT INTO trust_records (run_key, sequence, record_type, envelope, "
                                   "envelope_sha256, ingested_at) VALUES (%s, 1, 'authority-policy', %s, %s, %s)",
                                   (run_key, policy, sha256(policy), now))
            finally:
                connection.close()
            self.head = (1, sha256(policy))
        self.endorsements.bind(candidate, CheckpointIdentities("1" * 64, "2" * 64, sha256(data)), PARENT, now)
        binding = self.endorsements.binding(actor, candidate)
        if nonce is not None:
            binding = self.endorsements.named(binding, nonce)
        envelope = ("synthetic-endorsement-" + label).encode()
        verified = SimpleNamespace(envelope=envelope, envelope_sha256=sha256(envelope), key_fingerprint="f" * 64)
        terms = Terms("7" * 64, "8" * 64, {"type": "run-grant", "sha256": "6" * 64}, now,
                      now + timedelta(seconds=lifetime))
        return self.endorsements.record(binding, verified, terms, self.head, now)

    def first(self, data, label="one", actor=ACTOR):
        """An announced candidate with one recorded endorsement and a capability; returns both and the nonce."""
        candidate = self.announce(data, label, actor)
        nonce = self.endorsements.binding(actor, candidate).challenge.nonce
        self.recorded(candidate, data, label, actor)
        return candidate, self.issuer.issue(actor, candidate, self.clock_now), nonce

    def stored(self, candidate):
        return self.scalar("SELECT count(*) FROM upload_endorsements WHERE candidate_id = %s", (candidate,))

    def test_a_new_endorsement_during_a_live_stream_is_refused_and_not_recorded(self):
        data = payload(4 * CHUNK)
        candidate, capability, nonce = self.first(data)
        seen = []

        def endorse_again():
            for label, named in (("two", None), ("one", nonce)):
                try:
                    done = self.recorded(candidate, data, label, nonce=named)
                    seen.append(("replayed" if done.replayed else "recorded", label))
                except AuthRefusal as refusal:
                    seen.append((refusal.status, refusal.code, label))

        steps = body_steps(data)
        steps.insert(1, effect(endorse_again))
        response = self.put(candidate, capability, steps)
        # The new envelope waits; an exact replay of the bound one still answers.
        self.assertEqual(seen, [(409, "upload_in_progress", "two"), ("replayed", "one")])
        self.assertEqual(response.status, 202, response.text)
        self.assertEqual(self.stored(candidate), 1)
        self.assertEqual(self.scalar("SELECT count(*) FROM audit_events WHERE event = 'endorsement-verified'"), 1)
        self.assertEqual(self.endorsements.bound(ACTOR, candidate, self.clock_now).sequence, 1)
        # Once the stream has sealed, the contributor endorses again, as acceptance may need.
        self.assertFalse(self.recorded(candidate, data, "two").replayed)
        self.assertEqual(self.endorsements.bound(ACTOR, candidate, self.clock_now).sequence, 2)

    def test_an_endorsement_is_possible_again_once_a_dead_stream_lease_expires(self):
        data = payload(2 * CHUNK)
        candidate, capability, _nonce = self.first(data)
        self.transfers.start(capability_sha256(capability.value), object_key(candidate, 1, "a" * 32),
                             SETTINGS.environment_id, self.clock_now)
        # The gateway that started this stream stopped without ending it.
        self.advance(1799)
        with self.assertRaises(AuthRefusal) as caught:
            self.recorded(candidate, data, "two")
        self.assertEqual((caught.exception.code, caught.exception.reason), ("upload_in_progress", "stream-active"))
        self.assertEqual(self.stored(candidate), 1)
        self.advance(1)
        self.assertFalse(self.recorded(candidate, data, "two", lifetime=300).replayed)
        retry = self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual((retry.attempt_number, self.attempts(candidate)), (2, [(1, "abandoned"), (2, "open")]))
        self.assertEqual(self.upload(candidate, retry, data).status, 202)

    def test_an_endorsement_before_the_stream_starts_supersedes_its_capability(self):
        data = payload(2 * CHUNK)
        candidate, capability, _nonce = self.first(data)
        self.assertFalse(self.recorded(candidate, data, "two").replayed)
        self.assert_refused(self.upload(candidate, capability, data), 422, "endorsement_invalid")
        renewed = self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual((renewed.attempt_number, renewed.renewed), (1, True))
        self.assertEqual(self.upload(candidate, renewed, data).status, 202)

    def test_a_stream_start_racing_an_endorsement_never_lets_both_through(self):
        outcomes = set()
        for index in range(6):
            actor = ACTOR + 100 + index
            data = payload(CHUNK, bytes([index]))
            candidate, capability, _nonce = self.first(data, f"race-{index}", actor)
            hashed = capability_sha256(capability.value)
            key = object_key(candidate, 1, secrets.token_hex(16))

            def either(which):
                if which == 0:
                    return self.transfers.start(hashed, key, SETTINGS.environment_id, self.clock_now)
                return self.recorded(candidate, data, f"race-{index}-two", actor)

            started, endorsed = run_threads(2, either)
            pair = (type(started).__name__, getattr(started, "code", None),
                    type(endorsed).__name__, getattr(endorsed, "code", None))
            self.assertIn(pair, {("Stream", None, "AuthRefusal", "upload_in_progress"),
                                 ("CoordinationRefusal", "endorsement_superseded", "Endorsed", None)})
            outcomes.add(pair[0])
            self.assertEqual(self.stored(candidate), 1 if pair[0] == "Stream" else 2)


class SpentAttemptTests(UploadCase):
    """Once all 16 attempts have failed no retry can succeed (Laurence, 2026-10-01)."""

    def fail_attempts(self, data, count):
        candidate, capability = self.ready(data, lifetime=300)
        for number in range(count):
            self.assert_refused(self.put(candidate, capability, body_steps(data)[:1] + [disconnect()]), 422,
                                "upload_integrity")
            if number < count - 1:
                capability = self.issuer.issue(ACTOR, candidate, self.clock_now)
        return candidate

    def issuer_refusal(self, candidate):
        with self.assertRaises(CoordinationRefusal) as caught:
            self.issuer.issue(ACTOR, candidate, self.clock_now)
        return caught.exception

    def test_a_candidate_whose_sixteen_attempts_failed_answers_expired_without_a_retry(self):
        data = payload(2 * CHUNK)
        candidate = self.fail_attempts(data, 16)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.issuer.issue(ACTOR, candidate, self.clock_now)
        refusal = public(caught.exception)
        self.assertEqual((refusal.status, refusal.code, refusal.retry_after_seconds), (410, "candidate_expired", None))
        self.assertEqual([state for _number, state in self.attempts(candidate)], ["failed"] * 16)
        # Its quota stays reserved until the deadline, and nothing about it changed.
        self.assertEqual(self.state(candidate), "uploading")
        self.assertEqual(self.scalar("SELECT count(*) FROM reservations WHERE candidate_id = %s AND kind = "
                                     "'candidate' AND released_at IS NULL", (candidate,)), 1)
        self.assert_quota_consistent()

    def test_a_candidate_with_an_attempt_left_keeps_its_answers(self):
        data = payload(2 * CHUNK)
        candidate = self.fail_attempts(data, 15)
        last = self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual((last.attempt_number, last.renewed), (16, False))
        # An unstarted last attempt is renewed rather than refused.
        renewed = self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual((renewed.attempt_number, renewed.renewed), (16, True))
        self.assertEqual(self.upload(candidate, renewed, data).status, 202)

    def test_a_last_stream_that_died_answers_expired_once_its_lease_ends(self):
        data = payload(2 * CHUNK)
        candidate = self.fail_attempts(data, 15)
        last = self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.transfers.start(capability_sha256(last.value), object_key(candidate, 16, "b" * 32),
                             SETTINGS.environment_id, self.clock_now)
        self.assertEqual(self.issuer_refusal(candidate).code, "upload_in_progress")
        # Past the lease, with an endorsement the contributor could still record then.
        self.advance(1800)
        self.endorse(candidate, data, lifetime=300)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual((public(caught.exception).status, public(caught.exception).retry_after_seconds), (410, None))
