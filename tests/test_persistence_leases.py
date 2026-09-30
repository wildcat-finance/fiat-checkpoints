"""Fenced upload and validation leases, immutable intents, the outbox and their events."""

from dataclasses import replace
import uuid

from fiat_checkpoints.domain.coordination import CoordinationRefusal, LeasePolicy
from fiat_checkpoints.domain.identities import CheckpointIdentities
from fiat_checkpoints.domain.transitions import Evidence, State
from fiat_checkpoints.persistence.coordinator import (
    PASS_CALLER_EVIDENCE, SEAL_CALLER_EVIDENCE, IntentRecorded, Passed, Refused, RetryScheduled, Unavailable,
)
from tests.persistence_support import (
    ACTOR, DIGEST, EVIDENCE, IDENTITIES, SCOPE, SIZE, T0, DatabaseCase, at, passed, recorded_events, refused,
)


GRANT = {Evidence.RUN_GRANT}
WORKER = {Evidence.ISOLATED_WORKER}


def outcome(call):
    """The call's result, or its refusal code, so a wrong refusal fails an assertion."""
    try:
        return call()
    except CoordinationRefusal as error:
        return error.code


class UploadLeaseTests(DatabaseCase):
    def begin(self, candidate, now=T0):
        return self.coordinator.begin_upload(SCOPE, ACTOR, candidate, GRANT, now)

    def test_first_lease_moves_to_uploading_and_reserves_a_stream(self):
        candidate = self.announce().candidate_id
        lease = self.begin(candidate)
        self.assertEqual((lease.attempt_number, lease.fence), (1, 1))
        self.assertEqual(lease.expires_at, at(1800))
        self.assertEqual(self.coordinator.candidate(SCOPE, ACTOR, str(candidate)).state, State.UPLOADING)
        self.assertEqual(self.coordinator.usage()["streams"], 1)
        self.assert_quota_consistent()

    def test_live_lease_refuses_a_second_stream_and_an_expired_one_is_replaced(self):
        candidate = self.announce().candidate_id
        first = self.begin(candidate)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.begin(candidate, at(1799))
        self.assertEqual(caught.exception.code, "upload_in_progress")
        with recorded_events() as events:
            second = self.begin(candidate, at(1800))
        self.assertEqual((second.attempt_number, second.fence), (2, 2))
        self.assertIn("lease-expired", [event["event"] for event in events])
        self.assertEqual(self.coordinator.usage()["streams"], 1)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.seal_upload(first, SIZE, DIGEST, SEAL_CALLER_EVIDENCE, at(1801))
        self.assertEqual(caught.exception.code, "lease_stale")
        self.coordinator.seal_upload(second, SIZE, DIGEST, SEAL_CALLER_EVIDENCE, at(1801))
        self.assertEqual(self.coordinator.candidate(SCOPE, ACTOR, str(candidate)).state, State.QUARANTINED)
        self.assert_quota_consistent()

    def test_the_lease_holder_cannot_seal_after_expiry(self):
        candidate = self.announce().candidate_id
        lease = self.begin(candidate)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.seal_upload(lease, SIZE, DIGEST, SEAL_CALLER_EVIDENCE, at(1800))
        self.assertEqual(caught.exception.code, "lease_stale")
        self.assertEqual(self.coordinator.candidate(SCOPE, ACTOR, str(candidate)).state, State.UPLOADING)

    def test_sealing_needs_the_declared_bytes_and_both_evidence_items(self):
        candidate = self.announce().candidate_id
        lease = self.begin(candidate)
        for evidence in (set(), {Evidence.STREAM_COUNT_AND_HASH}, SEAL_CALLER_EVIDENCE | {Evidence.RUN_GRANT}):
            with self.subTest(evidence=sorted(item.value for item in evidence)):
                with self.assertRaises(CoordinationRefusal) as caught:
                    self.coordinator.seal_upload(lease, SIZE, DIGEST, evidence, at(1))
                self.assertEqual(caught.exception.code, "transition-evidence")
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.seal_upload(lease, SIZE, "d" * 64, SEAL_CALLER_EVIDENCE, at(1))
        self.assertEqual(caught.exception.code, "upload_integrity")
        # The failed attempt is closed and its stream released; the lease is spent.
        self.assertEqual(self.scalar("SELECT state FROM upload_attempts"), "failed")
        self.assertEqual(self.coordinator.usage()["streams"], 0)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.seal_upload(lease, SIZE, DIGEST, SEAL_CALLER_EVIDENCE, at(2))
        self.assertEqual(caught.exception.code, "lease_stale")
        retry = self.begin(candidate, at(3))
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.seal_upload(retry, SIZE - 1, DIGEST, SEAL_CALLER_EVIDENCE, at(4))
        self.assertEqual(caught.exception.code, "upload_integrity")
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.begin_upload(SCOPE, ACTOR, candidate, set(), at(5))
        self.assertEqual(caught.exception.code, "transition-evidence")
        self.assert_quota_consistent()

    def test_a_repeated_seal_returns_the_same_result_and_enqueues_once(self):
        candidate = self.announce().candidate_id
        lease = self.begin(candidate)
        self.assertEqual(self.coordinator.seal_upload(lease, SIZE, DIGEST, SEAL_CALLER_EVIDENCE, at(1)), 1)
        self.assertEqual(self.coordinator.seal_upload(lease, SIZE, DIGEST, SEAL_CALLER_EVIDENCE, at(2)), 1)
        self.assertEqual(self.scalar("SELECT count(*) FROM outbox_jobs WHERE kind = 'validate-candidate'"), 1)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.begin(candidate, at(3))
        self.assertEqual(caught.exception.code, "state_conflict")

    def test_the_attempt_count_is_bounded(self):
        candidate = self.announce().candidate_id
        for index in range(16):
            self.begin(candidate, at(index * 1800))
        with self.assertRaises(CoordinationRefusal) as caught:
            self.begin(candidate, at(16 * 1800))
        self.assertEqual(caught.exception.code, "attempt_limit")

    def test_the_third_concurrent_stream_for_one_actor_is_refused(self):
        leases = [self.begin(self.announce(label=str(index), archive=f"{index:064x}").candidate_id)
                  for index in range(2)]
        third = self.announce(label="third", archive="3" * 64).candidate_id
        with self.assertRaises(CoordinationRefusal) as caught:
            self.begin(third)
        self.assertEqual(caught.exception.code, "quota_exceeded")
        self.assertEqual(self.coordinator.candidate(SCOPE, ACTOR, str(third)).state, State.ANNOUNCED)
        self.coordinator.seal_upload(leases[0], SIZE, f"{0:064x}", SEAL_CALLER_EVIDENCE, at(1))
        self.begin(third, at(2))
        self.assert_quota_consistent()

    def test_expired_upload_leases_give_their_streams_to_the_actors_next_candidate(self):
        stale = [self.begin(self.announce(label=str(index), archive=f"{index:064x}").candidate_id)
                 for index in range(2)]
        third = self.announce(label="third", archive="3" * 64).candidate_id
        with recorded_events() as events:
            lease = outcome(lambda: self.begin(third, at(1800)))
        self.assertEqual(getattr(lease, "attempt_number", lease), 1)
        self.assertEqual([event["event"] for event in events].count("lease-expired"), 2)
        self.assertEqual(self.scalar("SELECT count(*) FROM upload_attempts WHERE state = 'abandoned'"), 2)
        self.assertEqual(self.coordinator.usage()["streams"], 1)
        for index, old in enumerate(stale):
            with self.subTest(stale=index):
                self.assertEqual(outcome(lambda: self.coordinator.seal_upload(
                    old, SIZE, f"{index:064x}", SEAL_CALLER_EVIDENCE, at(1801))), "lease_stale")
        self.assert_quota_consistent()

    def test_abandoned_uploads_of_other_actors_do_not_hold_the_global_streams(self):
        for actor in range(4):
            for index in range(2):
                candidate = self.announce(label=f"g{actor}-{index}", actor=500 + actor,
                                          archive=f"{actor * 2 + index:064x}").candidate_id
                self.coordinator.begin_upload(SCOPE, 500 + actor, candidate, GRANT, T0)
        fresh = self.announce(label="fresh", archive="f" * 64).candidate_id
        # While those eight leases live, the global ceiling holds.
        self.assertEqual(outcome(lambda: self.begin(fresh, at(1799))), "quota_exceeded")
        lease = outcome(lambda: self.begin(fresh, at(1800)))
        self.assertEqual(getattr(lease, "attempt_number", lease), 1)
        self.assertEqual(self.coordinator.usage()["streams"], 1)
        self.assert_quota_consistent()


class ValidationLeaseTests(DatabaseCase):
    def claim(self, now=T0, coordinator=None):
        return (coordinator or self.coordinator).claim_validation(WORKER, now)

    def test_claim_needs_an_isolated_worker_and_returns_the_sealed_input(self):
        candidate = self.quarantined()
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.claim_validation(set(), T0)
        self.assertEqual(caught.exception.code, "transition-evidence")
        claim = self.claim()
        self.assertEqual((claim.lease.candidate_id, claim.lease.fence, claim.lease.attempt_number),
                         (candidate, 2, 1))
        self.assertEqual((claim.archive_sha256, claim.declared_size, claim.input_attempt), (DIGEST, SIZE, 1))
        self.assertEqual(claim.lease.expires_at, at(900))
        self.assertIsNone(self.claim())

    def test_a_pass_records_one_immutable_intent_and_a_hand_off_job(self):
        candidate = self.quarantined()
        claim = self.claim()
        result = self.coordinator.complete_validation(claim.lease, passed(), at(1))
        self.assertIsInstance(result, IntentRecorded)
        self.assertFalse(result.replayed)
        view = self.coordinator.candidate(SCOPE, ACTOR, str(candidate))
        self.assertEqual(view.state, State.PUBLISHING)
        row = self.query("SELECT * FROM publication_intents")[0]
        self.assertEqual((row["intent_id"], row["fence"], row["archive_sha256"], bytes(row["evidence"])),
                         (result.intent_id, 2, DIGEST, EVIDENCE))
        self.assertEqual(self.scalar("SELECT count(*) FROM outbox_jobs WHERE kind = 'publish-intent' "
                                     "AND state = 'pending'"), 1)
        # The candidate still holds its quota: an intent is not acceptance.
        self.assertEqual(self.coordinator.usage()["candidates"], 1)
        again = self.coordinator.complete_validation(claim.lease, passed(), at(2))
        self.assertEqual((again.intent_id, again.replayed), (result.intent_id, True))
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_validation(claim.lease, passed(evidence=b"{}"), at(2))
        self.assertEqual(caught.exception.code, "lease_stale")
        self.assertEqual(self.scalar("SELECT count(*) FROM publication_intents"), 1)

    def test_a_pass_for_other_bytes_or_with_missing_evidence_records_nothing(self):
        self.quarantined()
        claim = self.claim()
        other = CheckpointIdentities("b" * 64, "c" * 64, "d" * 64)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_validation(claim.lease, passed(identities=other), at(1))
        self.assertEqual(caught.exception.code, "identity_mismatch")
        for evidence in (set(), PASS_CALLER_EVIDENCE - {Evidence.DENIAL_CHECK}):
            with self.subTest(size=len(evidence)):
                with self.assertRaises(CoordinationRefusal) as caught:
                    self.coordinator.complete_validation(claim.lease, Passed(IDENTITIES, EVIDENCE, evidence), at(1))
                self.assertEqual(caught.exception.code, "transition-evidence")
        for evidence in (b"", b"x" * 65_537, "text"):
            with self.subTest(evidence=len(evidence)):
                with self.assertRaises(CoordinationRefusal) as caught:
                    self.coordinator.complete_validation(claim.lease, passed(evidence=evidence), at(1))
                self.assertEqual(caught.exception.code, "request_invalid")
        self.assertEqual(self.scalar("SELECT count(*) FROM publication_intents"), 0)
        self.assertEqual(self.scalar("SELECT state FROM candidates"), "validating")

    def test_a_deterministic_refusal_rejects_and_releases_quota(self):
        candidate = self.quarantined()
        claim = self.claim()
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_validation(claim.lease, Refused("protocol_refused", set()), at(1))
        self.assertEqual(caught.exception.code, "transition-evidence")
        self.assertIsNone(self.coordinator.complete_validation(claim.lease, refused(), at(1)))
        view = self.coordinator.candidate(SCOPE, ACTOR, str(candidate))
        self.assertEqual((view.state, view.terminal_code), (State.REJECTED, "protocol_refused"))
        self.assertEqual(self.coordinator.usage(), {"candidates": 0, "reserved_bytes": 0, "streams": 0})
        self.assertEqual(self.scalar("SELECT count(*) FROM publication_intents"), 0)
        self.assert_quota_consistent()

    def test_dependency_outage_keeps_the_phase_and_retries_with_a_higher_fence(self):
        candidate = self.quarantined()
        claim = self.claim()
        with recorded_events() as events:
            retry = self.coordinator.complete_validation(claim.lease, Unavailable("sandbox_unavailable"), at(1))
        self.assertIsInstance(retry, RetryScheduled)
        self.assertFalse(retry.held)
        self.assertTrue(500 <= retry.delay_ms < 1000)
        view = self.coordinator.candidate(SCOPE, ACTOR, str(candidate))
        self.assertEqual((view.state, view.retry_reason), (State.VALIDATING, "sandbox_unavailable"))
        event = next(event for event in events if event["event"] == "retry-scheduled")
        self.assertEqual((event["code"], event["count"], event["delay_ms"]), ("sandbox_unavailable", 1, retry.delay_ms))
        self.assertIsNone(self.claim(at(1)))
        again = self.claim(at(2))
        self.assertEqual((again.lease.fence, again.lease.attempt_number, again.input_attempt), (3, 2, 1))
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_validation(claim.lease, passed(), at(3))
        self.assertEqual(caught.exception.code, "lease_stale")
        self.coordinator.complete_validation(again.lease, passed(), at(3))
        self.assertIsNone(self.coordinator.candidate(SCOPE, ACTOR, str(candidate)).retry_reason)

    def test_tool_failures_hold_for_an_operator_after_the_retry_cap(self):
        self.coordinator = self.make_coordinator(leases=LeasePolicy(tool_retry_limit=2))
        self.quarantined()
        first = self.claim()
        self.coordinator.complete_validation(first.lease, Unavailable("validation_failed"), at(1))
        second = self.claim(at(600))
        held = self.coordinator.complete_validation(second.lease, Unavailable("validation_failed"), at(601))
        self.assertEqual(held, RetryScheduled(0, True))
        self.assertEqual(self.scalar("SELECT state FROM outbox_jobs"), "held")
        self.assertIsNone(self.claim(at(10_000)))
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_validation(second.lease, Unavailable("free text"), at(602))
        self.assertEqual(caught.exception.code, "request_invalid")

    def test_an_expired_lease_is_stale_even_when_nobody_replaced_it(self):
        self.quarantined()
        claim = self.claim()
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_validation(claim.lease, passed(), at(900))
        self.assertEqual(caught.exception.code, "lease_stale")
        forged = replace(claim.lease, fence=claim.lease.fence + 1)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_validation(forged, passed(), at(1))
        self.assertEqual(caught.exception.code, "lease_stale")
        wrong_job = replace(claim.lease, job_id=claim.lease.job_id + 100)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_validation(wrong_job, passed(), at(1))
        self.assertEqual(caught.exception.code, "lease_stale")
        absent = replace(claim.lease, candidate_id=uuid.uuid4())
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_validation(absent, passed(), at(1))
        self.assertEqual(caught.exception.code, "lease_stale")
        self.assertEqual(self.scalar("SELECT count(*) FROM publication_intents"), 0)

    def test_completion_after_the_candidate_deadline_is_refused(self):
        self.quarantined()
        claim = self.claim(at(86_000))
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_validation(claim.lease, passed(), at(86_400))
        self.assertEqual(caught.exception.code, "candidate_expired")
        self.assertEqual(self.coordinator.expire_due(at(86_400)), 1)
        self.assertEqual(self.scalar("SELECT count(*) FROM publication_intents"), 0)

    def test_expiry_leaves_a_candidate_with_an_intent_to_its_publication_owner(self):
        self.quarantined()
        claim = self.claim()
        self.coordinator.complete_validation(claim.lease, passed(), at(1))
        self.assertEqual(self.coordinator.expire_due(at(90_000)), 0)
        self.assertEqual(self.scalar("SELECT state FROM candidates"), "publishing")


class HandOffJobTests(DatabaseCase):
    def published(self):
        self.quarantined()
        claim = self.coordinator.claim_validation(WORKER, T0)
        self.coordinator.complete_validation(claim.lease, passed(), at(1))

    def test_hand_off_job_is_fenced_retried_and_completed_once(self):
        self.published()
        with self.assertRaises(CoordinationRefusal):
            self.coordinator.claim_job("validate-candidate", at(2))
        first = self.coordinator.claim_job("publish-intent", at(2))
        self.assertEqual((first.kind, first.fence), ("publish-intent", 3))
        self.assertIsNone(self.coordinator.claim_job("publish-intent", at(3)))
        retry = self.coordinator.retry_job(first, "replica_unavailable", at(4))
        self.assertFalse(retry.held)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_job(first, at(5))
        self.assertEqual(caught.exception.code, "lease_stale")
        second = self.coordinator.claim_job("publish-intent", at(10))
        self.assertEqual(second.fence, 4)
        self.coordinator.complete_job(second, at(11))
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_job(second, at(12))
        self.assertEqual(caught.exception.code, "lease_stale")
        self.assertEqual(self.scalar("SELECT state FROM candidates"), "publishing")

    def test_an_abandoned_hand_off_lease_is_reclaimed_after_expiry(self):
        self.published()
        first = self.coordinator.claim_job("publish-intent", at(2))
        self.assertIsNone(self.coordinator.claim_job("publish-intent", at(301)))
        second = self.coordinator.claim_job("publish-intent", at(302))
        self.assertGreater(second.fence, first.fence)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.complete_job(first, at(303))
        self.assertEqual(caught.exception.code, "lease_stale")


class EventTests(DatabaseCase):
    def test_events_are_fields_without_actor_digest_or_evidence(self):
        with recorded_events() as events:
            candidate = self.quarantined()
            claim = self.coordinator.claim_validation(WORKER, T0)
            self.coordinator.complete_validation(claim.lease, passed(), at(1))
        names = [event["event"] for event in events]
        for name in ("candidate-announced", "upload-started", "lease-granted", "upload-sealed", "job-enqueued",
                     "validation-started", "intent-recorded", "quota-released"):
            self.assertIn(name, names)
        text = "\n".join(str(event) for event in events)
        for secret in (str(ACTOR), DIGEST, "b" * 64, "c" * 64, EVIDENCE.decode()):
            self.assertNotIn(secret, text)
        started = next(event for event in events if event["event"] == "validation-started")
        self.assertEqual((started["candidate"], started["from_state"], started["to_state"], started["fence"]),
                         (str(candidate), "quarantined", "validating", 2))
        self.assertIsInstance(started["age_ms"], int)
        audit = [row["event"] for row in self.query("SELECT event FROM audit_events ORDER BY event_id")]
        self.assertEqual(audit, ["candidate-announced", "upload-started", "upload-sealed", "validation-started",
                                 "intent-recorded"])

    def test_a_rolled_back_call_logs_only_its_refusal(self):
        for index in range(5):
            self.announce(label=str(index), archive=f"{index:064x}")
        with recorded_events() as events:
            with self.assertRaises(CoordinationRefusal):
                self.announce(label="over", archive="9" * 64)
        self.assertEqual(events, [{"event": "quota-refused", "scope": "actor", "kind": "candidate"}])
