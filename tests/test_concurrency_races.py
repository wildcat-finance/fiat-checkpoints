"""Races between concurrent callers, each on its own connection and thread."""

import threading
import time

from fiat_checkpoints.domain.coordination import CoordinationRefusal, QuotaPolicy, RunScope
from fiat_checkpoints.domain.transitions import Evidence
from fiat_checkpoints.persistence.coordinator import SEAL_CALLER_EVIDENCE, IntentRecorded
from tests.persistence_support import (
    ACTOR, DIGEST, SCOPE, SIZE, T0, DatabaseCase, at, key, passed, request, run_threads,
)


GRANT = {Evidence.RUN_GRANT}
WORKER = {Evidence.ISOLATED_WORKER}


def codes(results):
    return sorted(result.code if isinstance(result, CoordinationRefusal) else type(result).__name__
                  for result in results)


class AnnounceRaceTests(DatabaseCase):
    def test_concurrent_announces_with_one_key_create_one_candidate(self):
        results = run_threads(16, lambda _index: self.coordinator.announce(SCOPE, ACTOR, key("same"), request(), T0))
        self.assertTrue(all(not isinstance(result, Exception) for result in results), codes(results))
        self.assertEqual(len({result.candidate_id for result in results}), 1)
        self.assertEqual(sum(1 for result in results if not result.replayed), 1)
        self.assertEqual(self.scalar("SELECT count(*) FROM candidates"), 1)
        self.assertEqual(self.coordinator.usage()["candidates"], 1)
        self.assert_quota_consistent()

    def test_one_key_raced_with_different_bodies_admits_exactly_one_body(self):
        results = run_threads(8, lambda index: self.coordinator.announce(
            SCOPE, ACTOR, key("same"), request(size=SIZE + index), T0))
        winners = [result for result in results if not isinstance(result, Exception)]
        self.assertEqual(len(winners), 1, codes(results))
        self.assertEqual(codes(results).count("idempotency_conflict"), 7)
        self.assertEqual(self.scalar("SELECT count(*) FROM candidates"), 1)

    def test_actor_quota_race_admits_exactly_the_ceiling(self):
        results = run_threads(12, lambda index: self.coordinator.announce(
            SCOPE, ACTOR, key(f"race-{index}"), request(archive=f"{index:064x}"), T0))
        self.assertEqual(codes(results).count("Announced"), 5, codes(results))
        self.assertEqual(codes(results).count("quota_exceeded"), 7)
        self.assertEqual(self.scalar("SELECT count(*) FROM candidates"), 5)
        self.assertEqual(self.scalar("SELECT count(*) FROM idempotency_keys"), 5)
        self.assert_quota_consistent()

    def test_run_and_global_quota_races_hold_across_actors_and_runs(self):
        self.coordinator = self.make_coordinator(quotas=QuotaPolicy(candidates_per_run=6, candidates_global=10))
        scopes = [RunScope("fiat-checkpoints", 101, f"run-{index % 3}") for index in range(24)]
        results = run_threads(24, lambda index: self.coordinator.announce(
            scopes[index], 7000 + index, key(f"g-{index}"), request(), T0))
        self.assertEqual(codes(results).count("Announced"), 10, codes(results))
        per_run = self.query("SELECT r.run_id, count(*) AS n FROM candidates c JOIN run_registrations r "
                             "USING (run_key) GROUP BY r.run_id")
        self.assertTrue(all(row["n"] <= 6 for row in per_run), per_run)
        self.assert_quota_consistent()

    def test_byte_quota_race_never_overcommits(self):
        self.coordinator = self.make_coordinator(quotas=QuotaPolicy(bytes_per_run=10 * SIZE))
        results = run_threads(12, lambda index: self.coordinator.announce(
            SCOPE, 7000 + index, key(f"b-{index}"), request(size=3 * SIZE), T0))
        self.assertEqual(codes(results).count("Announced"), 3, codes(results))
        self.assertEqual(self.coordinator.usage()["reserved_bytes"], 9 * SIZE)
        self.assert_quota_consistent()


class LeaseRaceTests(DatabaseCase):
    def test_concurrent_upload_begins_grant_one_lease(self):
        candidate = self.announce().candidate_id
        results = run_threads(8, lambda _index: self.coordinator.begin_upload(SCOPE, ACTOR, candidate, GRANT, T0))
        self.assertEqual(codes(results).count("Lease"), 1, codes(results))
        self.assertEqual(codes(results).count("upload_in_progress"), 7)
        self.assertEqual(self.coordinator.usage()["streams"], 1)
        self.assert_quota_consistent()

    def test_stream_quota_race_admits_two_streams_per_actor(self):
        candidates = [self.announce(label=str(index), archive=f"{index:064x}").candidate_id for index in range(5)]
        results = run_threads(5, lambda index: self.coordinator.begin_upload(
            SCOPE, ACTOR, candidates[index], GRANT, T0))
        self.assertEqual(codes(results).count("Lease"), 2, codes(results))
        self.assertEqual(codes(results).count("quota_exceeded"), 3)
        self.assert_quota_consistent()

    def test_concurrent_validation_claims_lease_each_job_once(self):
        candidates = {self.quarantined(label=str(index), actor=8000 + index) for index in range(3)}
        results = run_threads(8, lambda _index: self.coordinator.claim_validation(WORKER, T0))
        claims = [result for result in results if result is not None and not isinstance(result, Exception)]
        self.assertTrue(all(not isinstance(result, Exception) for result in results), codes(results))
        self.assertEqual({claim.lease.candidate_id for claim in claims}, candidates)
        self.assertEqual(len(claims), 3)
        self.assertEqual(self.scalar("SELECT count(*) FROM validation_attempts WHERE state = 'running'"), 3)

    def test_a_claim_never_holds_a_job_while_it_waits_for_that_jobs_candidate(self):
        # Completions and the sweep lock the candidate, then its job; a claim
        # holding the job while it waits for the candidate closes a cycle.
        candidate = self.quarantined()
        holder = self.database.connect()
        probe = self.database.connect()
        result = {}
        try:
            holder.execute("BEGIN")
            holder.execute("SELECT 1 FROM candidates WHERE candidate_id = %s FOR UPDATE", (candidate,))
            claimer = threading.Thread(target=lambda: result.setdefault(
                "claim", self.coordinator.claim_validation(WORKER, at(1))))
            claimer.start()
            deadline = time.monotonic() + 30
            while claimer.is_alive() and time.monotonic() < deadline and not probe.execute(
                    "SELECT count(*) AS n FROM pg_stat_activity WHERE datname = %s AND wait_event_type = 'Lock'",
                    (self.database.dbname,)).fetchone()["n"]:
                time.sleep(0.02)
            unlocked = probe.execute("SELECT job_id FROM outbox_jobs FOR UPDATE SKIP LOCKED").fetchall()
            holder.execute("ROLLBACK")
            claimer.join(30)
        finally:
            holder.close()
            probe.close()
        self.assertEqual(len(unlocked), 1)
        self.assertIsNone(result.get("claim"))
        self.assertEqual(self.coordinator.claim_validation(WORKER, at(2)).lease.candidate_id, candidate)

    def test_unique_intent_contention_between_a_stale_and_a_current_worker(self):
        self.quarantined()
        stale = self.coordinator.claim_validation(WORKER, T0)
        current = self.coordinator.claim_validation(WORKER, at(900))
        self.assertGreater(current.lease.fence, stale.lease.fence)
        leases = [stale.lease, current.lease] * 4
        results = run_threads(8, lambda index: self.coordinator.complete_validation(leases[index], passed(), at(901)))
        winners = [result for index, result in enumerate(results) if isinstance(result, IntentRecorded)]
        self.assertEqual(len({result.intent_id for result in winners}), 1)
        self.assertEqual(sum(1 for result in winners if not result.replayed), 1)
        for index, result in enumerate(results):
            if leases[index] is stale.lease:
                self.assertEqual(getattr(result, "code", None), "lease_stale")
            else:
                self.assertIsInstance(result, IntentRecorded)
        row = self.query("SELECT fence, validation_attempt FROM publication_intents")
        self.assertEqual(row, [{"fence": current.lease.fence, "validation_attempt": current.lease.attempt_number}])

    def test_deadline_sweep_and_completion_race_to_exactly_one_outcome(self):
        for round_number in range(4):
            with self.subTest(round=round_number):
                candidate = self.quarantined(label=f"r{round_number}", actor=8100 + round_number)
                claim = self.coordinator.claim_validation(WORKER, at(86_000))
                self.assertEqual(claim.lease.candidate_id, candidate)
                operations = [lambda: self.coordinator.expire_due(at(86_400)),
                              lambda: self.coordinator.complete_validation(claim.lease, passed(), at(86_399))]
                results = run_threads(2, lambda index: operations[index]())
                state = self.scalar("SELECT state FROM candidates WHERE candidate_id = %s", (candidate,))
                intents = self.scalar("SELECT count(*) FROM publication_intents WHERE candidate_id = %s",
                                      (candidate,))
                if state == "expired":
                    self.assertEqual((intents, results[0]), (0, 1))
                    self.assertEqual(getattr(results[1], "code", None), "lease_stale")
                else:
                    self.assertEqual((state, intents, results[0]), ("publishing", 1, 0))
                self.assert_quota_consistent()
        self.assertEqual(self.scalar("SELECT count(*) FROM candidates WHERE state NOT IN ('expired', 'publishing')"), 0)

    def test_concurrent_seals_of_one_lease_enqueue_one_validation(self):
        candidate = self.announce().candidate_id
        lease = self.coordinator.begin_upload(SCOPE, ACTOR, candidate, GRANT, T0)
        results = run_threads(6, lambda _index: self.coordinator.seal_upload(lease, SIZE, DIGEST,
                                                                             SEAL_CALLER_EVIDENCE, at(1)))
        self.assertEqual(results, [1] * 6)
        self.assertEqual(self.scalar("SELECT count(*) FROM outbox_jobs"), 1)
