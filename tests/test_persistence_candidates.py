"""Announce, idempotency scope, cross-run hiding, quota reservations and expiry."""

from datetime import timedelta
import unittest
import uuid

from fiat_checkpoints.domain.coordination import (
    GIB, AnnounceRequest, CoordinationRefusal, LeasePolicy, QuotaPolicy, RunScope, retry_delay_ms,
)
from fiat_checkpoints.domain.transitions import Evidence, State
from fiat_checkpoints.persistence.coordinator import SEAL_CALLER_EVIDENCE
from tests.persistence_support import (
    ACTOR, DIGEST, OTHER_ACTOR, OTHER_SCOPE, SCOPE, SIZE, T0, DatabaseCase, at, key, recorded_events, request,
)


class AnnounceTests(DatabaseCase):
    def test_announce_creates_one_candidate_with_a_24_hour_deadline(self):
        announced = self.announce()
        self.assertFalse(announced.replayed)
        self.assertEqual(announced.expires_at, T0 + timedelta(hours=24))
        view = self.coordinator.candidate(SCOPE, ACTOR, str(announced.candidate_id))
        self.assertEqual((view.state, view.archive_sha256, view.declared_size), (State.ANNOUNCED, DIGEST, SIZE))
        self.assertEqual(announced.candidate_id.version, 4)

    def test_same_key_and_request_replays_the_existing_candidate(self):
        first = self.announce()
        again = self.announce(now=at(3600))
        self.assertEqual((again.candidate_id, again.replayed), (first.candidate_id, True))
        self.assertEqual(self.scalar("SELECT count(*) FROM candidates"), 1)
        self.assertEqual(self.coordinator.usage()["candidates"], 1)

    def test_a_changed_request_under_one_key_is_a_conflict(self):
        self.announce()
        changes = {
            "size": dict(size=SIZE + 1),
            "digest": dict(archive="d" * 64),
            "field": dict(parents=["e" * 64]),
        }
        for label, change in changes.items():
            with self.subTest(change=label):
                with recorded_events() as events:
                    with self.assertRaises(CoordinationRefusal) as caught:
                        self.coordinator.announce(SCOPE, ACTOR, key("one"), request(**change), T0)
                self.assertEqual(str(caught.exception), "idempotency_conflict")
                self.assertEqual([event["event"] for event in events], ["idempotency-conflict"])
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.announce(OTHER_SCOPE, ACTOR, key("one"), request(), T0)
        self.assertEqual(caught.exception.code, "idempotency_conflict")
        self.assertEqual(self.scalar("SELECT count(*) FROM candidates"), 1)

    def test_keys_are_scoped_to_their_actor(self):
        mine = self.announce()
        theirs = self.announce(actor=OTHER_ACTOR, archive="f" * 64)
        self.assertNotEqual(mine.candidate_id, theirs.candidate_id)
        self.assertFalse(theirs.replayed)

    def test_a_key_past_its_retention_no_longer_answers(self):
        first = self.announce()
        later = T0 + timedelta(hours=24, days=7)
        self.assertEqual(self.coordinator.expire_due(later), 1)
        self.assertEqual(self.coordinator.sweep_idempotency(later), 1)
        again = self.announce(now=later)
        self.assertNotEqual(again.candidate_id, first.candidate_id)
        self.assertFalse(again.replayed)
        # A mapping still inside its retention replays even after its candidate expired.
        replay = self.announce(now=later + timedelta(days=1, hours=23))
        self.assertEqual(replay.candidate_id, again.candidate_id)

    def test_malformed_inputs_refuse_before_any_write(self):
        for label, value in (("short", "k" * 15), ("long", "k" * 129), ("space", "key with spaces!!"),
                             ("unicode", "ключ-идемпотентности"), ("type", 12345678901234567)):
            with self.subTest(key=label):
                with self.assertRaises(CoordinationRefusal) as caught:
                    self.coordinator.announce(SCOPE, ACTOR, value, request(), T0)
                self.assertEqual(caught.exception.code, "request_invalid")
        for label, build in (
            ("size", lambda: AnnounceRequest(DIGEST, GIB + 1, {})),
            ("zero", lambda: AnnounceRequest(DIGEST, 0, {})),
            ("digest", lambda: AnnounceRequest("A" * 64, SIZE, {})),
            ("float", lambda: AnnounceRequest(DIGEST, SIZE, {"x": 1.5})),
            ("shadow", lambda: AnnounceRequest(DIGEST, SIZE, {"declared_size": 1})),
            ("huge", lambda: AnnounceRequest(DIGEST, SIZE, {"x": "y" * 70_000})),
            ("scope", lambda: RunScope("fiat-checkpoints", 0, "run")),
            ("run", lambda: RunScope("fiat-checkpoints", 1, "../run")),
        ):
            with self.subTest(request=label):
                with self.assertRaises(CoordinationRefusal) as caught:
                    build()
                self.assertEqual(caught.exception.code, "request_invalid")
        naive = T0.replace(tzinfo=None)
        with self.assertRaises(CoordinationRefusal):
            self.coordinator.announce(SCOPE, ACTOR, key("naive"), request(), naive)
        self.assertEqual(self.scalar("SELECT count(*) FROM candidates"), 0)


class ExistenceHidingTests(DatabaseCase):
    def test_other_runs_actors_and_ids_all_read_as_not_found(self):
        mine = self.announce().candidate_id
        probes = {
            "other run": (OTHER_SCOPE, ACTOR, str(mine)),
            "other actor": (SCOPE, OTHER_ACTOR, str(mine)),
            "other repository": (RunScope("fiat-checkpoints", 102, "run-alpha"), ACTOR, str(mine)),
            "absent id": (SCOPE, ACTOR, str(uuid.uuid4())),
            "malformed": (SCOPE, ACTOR, "not-a-candidate"),
            "upper case": (SCOPE, ACTOR, str(mine).upper()),
        }
        for label, arguments in probes.items():
            with self.subTest(probe=label):
                with self.assertRaises(CoordinationRefusal) as caught:
                    self.coordinator.candidate(*arguments)
                self.assertEqual((caught.exception.code, str(caught.exception)), ("not_found", "not_found"))
                with self.assertRaises(CoordinationRefusal) as caught:
                    self.coordinator.begin_upload(*arguments, {Evidence.RUN_GRANT}, T0)
                self.assertEqual(caught.exception.code, "not_found")
        self.assertEqual(self.scalar("SELECT state FROM candidates"), "announced")

    def test_one_digest_in_two_runs_is_two_unrelated_candidates(self):
        first = self.announce(label="one")
        second = self.announce(label="two", actor=OTHER_ACTOR, scope=OTHER_SCOPE)
        self.assertNotEqual(first.candidate_id, second.candidate_id)
        self.assertFalse(second.replayed)
        with self.assertRaises(CoordinationRefusal):
            self.coordinator.candidate(OTHER_SCOPE, OTHER_ACTOR, str(first.candidate_id))


class QuotaTests(DatabaseCase):
    quotas = QuotaPolicy()

    def test_the_sixth_outstanding_candidate_for_one_actor_is_refused(self):
        for index in range(5):
            self.announce(label=str(index), archive=f"{index:064x}")
        with recorded_events() as events:
            with self.assertRaises(CoordinationRefusal) as caught:
                self.announce(label="5", archive="5" * 64)
        self.assertEqual(caught.exception.code, "quota_exceeded")
        self.assertIn({"event": "quota-refused", "scope": "actor", "kind": "candidate"}, events)
        self.assertEqual(self.scalar("SELECT count(*) FROM idempotency_keys"), 5)
        self.announce(label="other", actor=OTHER_ACTOR)
        self.assert_quota_consistent()

    def test_reserved_bytes_are_bounded_at_announce(self):
        self.coordinator = self.make_coordinator(quotas=QuotaPolicy(bytes_per_actor=3 * SIZE))
        self.announce(label="a", size=2 * SIZE)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.announce(label="b", size=SIZE + 1)
        self.assertEqual(caught.exception.code, "quota_exceeded")
        # Reaching the ceiling exactly is allowed.
        self.announce(label="c", size=SIZE)
        self.assertEqual(self.coordinator.usage()["reserved_bytes"], 3 * SIZE)
        self.assert_quota_consistent()

    def test_specification_ceilings_admit_five_one_gib_candidates_per_actor(self):
        for index in range(5):
            self.announce(label=str(index), size=GIB, archive=f"{index:064x}")
        with self.assertRaises(CoordinationRefusal) as caught:
            self.announce(label="over", size=1, archive="9" * 64)
        self.assertEqual(caught.exception.code, "quota_exceeded")
        self.assertEqual(self.coordinator.usage()["reserved_bytes"], 5 * GIB)
        self.assert_quota_consistent()

    def test_lowered_policy_limits_hold_and_cannot_exceed_the_specification(self):
        coordinator = self.make_coordinator(quotas=QuotaPolicy(candidates_per_run=2))
        coordinator.announce(SCOPE, ACTOR, key("a"), request(), T0)
        coordinator.announce(SCOPE, OTHER_ACTOR, key("b"), request(), T0)
        with self.assertRaises(CoordinationRefusal) as caught:
            coordinator.announce(SCOPE, 9003, key("c"), request(), T0)
        self.assertEqual(caught.exception.code, "quota_exceeded")
        coordinator.announce(OTHER_SCOPE, 9003, key("c"), request(), T0)
        for field in ("candidates_per_actor", "bytes_global", "streams_global"):
            with self.subTest(field=field):
                with self.assertRaises(CoordinationRefusal):
                    QuotaPolicy(**{field: QuotaPolicy.__dataclass_fields__[field].default + 1})
        with self.assertRaises(CoordinationRefusal):
            LeasePolicy(upload_seconds=1801)
        self.assert_quota_consistent()


class ExpiryTests(DatabaseCase):
    def test_deadline_expires_pre_intent_candidates_and_releases_everything(self):
        announced = self.announce(label="a").candidate_id
        uploading = self.announce(label="b").candidate_id
        self.coordinator.begin_upload(SCOPE, ACTOR, uploading, {Evidence.RUN_GRANT}, T0)
        quarantined = self.quarantined(label="c")
        self.assertEqual(self.coordinator.expire_due(at(86_399)), 0)
        with recorded_events() as events:
            self.assertEqual(self.coordinator.expire_due(at(86_400)), 3)
        for candidate in (announced, uploading, quarantined):
            view = self.coordinator.candidate(SCOPE, ACTOR, str(candidate))
            self.assertEqual((view.state, view.terminal_code), (State.EXPIRED, "candidate_expired"))
        self.assertEqual(self.coordinator.usage(), {"candidates": 0, "reserved_bytes": 0, "streams": 0})
        self.assertEqual(self.scalar("SELECT count(*) FROM outbox_jobs WHERE state IN ('pending', 'leased')"), 0)
        self.assertEqual(self.scalar("SELECT count(*) FROM upload_attempts WHERE state = 'open'"), 0)
        self.assertEqual(sum(1 for event in events if event["event"] == "candidate-expired"), 3)
        self.assert_quota_consistent()
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.begin_upload(SCOPE, ACTOR, announced, {Evidence.RUN_GRANT}, at(86_401))
        self.assertEqual(caught.exception.code, "state_conflict")

    def test_expired_but_unswept_candidate_takes_no_new_work(self):
        candidate = self.announce().candidate_id
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.begin_upload(SCOPE, ACTOR, candidate, {Evidence.RUN_GRANT}, at(86_400))
        self.assertEqual(caught.exception.code, "candidate_expired")
        self.quarantined(label="late")
        self.assertIsNone(self.coordinator.claim_validation({Evidence.ISOLATED_WORKER}, at(86_400)))

    def test_lost_upload_state_can_only_expire_the_candidate(self):
        candidate = self.announce().candidate_id
        lease = self.coordinator.begin_upload(SCOPE, ACTOR, candidate, {Evidence.RUN_GRANT}, T0)
        # Upload state is disposable. Losing it cannot seal, validate or accept.
        connection = self.database.connect()
        try:
            connection.execute("DELETE FROM upload_attempts")
        finally:
            connection.close()
        with self.assertRaises(CoordinationRefusal) as caught:
            self.coordinator.seal_upload(lease, SIZE, DIGEST, SEAL_CALLER_EVIDENCE, at(1))
        self.assertEqual(caught.exception.code, "lease_stale")
        self.assertIsNone(self.coordinator.claim_validation({Evidence.ISOLATED_WORKER}, at(2)))
        self.assertEqual(self.coordinator.expire_due(at(86_400)), 1)
        self.assertEqual(self.coordinator.candidate(SCOPE, ACTOR, str(candidate)).state, State.EXPIRED)
        self.assertEqual(self.scalar("SELECT count(*) FROM publication_intents"), 0)
        self.assertEqual(self.scalar("SELECT count(*) FROM candidates WHERE state = 'accepted'"), 0)
        self.assertEqual(self.coordinator.usage(), {"candidates": 0, "reserved_bytes": 0, "streams": 0})
        self.assert_quota_consistent()


class RetryTimingTests(unittest.TestCase):
    def test_backoff_doubles_with_jitter_and_never_passes_five_minutes(self):
        self.assertEqual([retry_delay_ms(n, 0.0) for n in (1, 2, 3, 4)], [500, 1000, 2000, 4000])
        self.assertEqual(retry_delay_ms(1, 0.999999), 999)
        self.assertEqual(retry_delay_ms(9, 0.0), 128_000)
        for attempts in (10, 50, 100_000):
            with self.subTest(attempts=attempts):
                self.assertEqual(retry_delay_ms(attempts, 0.0), 150_000)
                self.assertLess(retry_delay_ms(attempts, 0.999999), 300_000)
        for bad in ((0, 0.5), (1, 1.0), (1, -0.1), (1, 1)):
            with self.subTest(arguments=bad):
                with self.assertRaises(CoordinationRefusal):
                    retry_delay_ms(*bad)
