"""The sweeper and crash retry: expiry, reclaimed streams, due deletions, lifecycle and restart."""

from datetime import timedelta
import json
import os
from unittest import mock

from fiat_checkpoints.api.gateway import UploadGateway
from fiat_checkpoints.auth.sessions import SessionStore
from fiat_checkpoints.domain.coordination import CANDIDATE_LIFETIME, IDEMPOTENCY_RETENTION
from fiat_checkpoints.persistence.database import PersistenceRefusal
from fiat_checkpoints.persistence.transfer import Completed, Transfers
from fiat_checkpoints.upload.sweeper import Sweeper
from tests.persistence_support import T0, recorded_events
from tests.upload_support import (ACTOR, CHUNK, SETTINGS, UploadCase, body_steps, disconnect, effect, payload,
                                  sha256)


class SweeperCase(UploadCase):
    def setUp(self):
        super().setUp()
        self.sessions = SessionStore(self.database, audience=SETTINGS.service_id, environment=SETTINGS.environment_id)
        self.sweeper = Sweeper(self.transfers, self.sessions, self.quarantine)

    def record_states(self):
        return sorted(row["state"] for row in self.query("SELECT state FROM quarantine_objects"))


class SweeperTests(SweeperCase):
    def test_one_pass_reclaims_expires_and_deletes_what_is_due(self):
        # A sealed upload, a stream that failed after writing, and a stream a crash left open.
        sealed_data, failed_data, open_data = (payload(2 * CHUNK, label) for label in (b"s", b"f", b"o"))
        sealed, sealed_capability = self.ready(sealed_data, "sealed")
        self.assertEqual(self.upload(sealed, sealed_capability, sealed_data).status, 202)
        failed, failed_capability = self.ready(failed_data, "failed")
        with mock.patch.object(Transfers, "seal_stream", side_effect=PersistenceRefusal("database_unavailable")):
            self.assert_refused(self.upload(failed, failed_capability, failed_data), 503, "policy_unavailable")
        opened, open_capability = self.ready(open_data, "opened")
        with mock.patch.object(UploadGateway, "_abandon"), mock.patch.object(
                Transfers, "seal_stream", side_effect=RuntimeError("crash")):
            self.upload(opened, open_capability, open_data)
        self.assertEqual(self.attempts(failed), [(1, "failed")])
        self.assertEqual(self.attempts(opened), [(1, "open")])
        # The failed stream removed its own object once it had failed its attempt;
        # the crashed one could not, so its object and record wait for the sweeper.
        self.assertEqual(len(self.stored()), 2)
        self.sessions.open_session(ACTOR, T0)
        with recorded_events() as events:
            first = self.sweeper.run(self.clock_now)
        # Only the failed attempt's object is due now; the open stream's lease still lives.
        self.assertEqual((first.streams, first.candidates, first.quarantine, first.lifecycle), (0, 0, 1, 0))
        self.assertEqual(self.record_states(), ["deleted", "sealed", "writing"])
        self.assertEqual(len(self.stored()), 2)
        self.assertEqual({event["kind"] for event in events if event["event"] == "sweep-completed"},
                         {"streams", "candidates", "idempotency", "sessions", "capabilities", "quarantine",
                          "lifecycle"})
        # Past the stream lease the crashed attempt is abandoned and its object goes.
        self.advance(1801)
        second = self.sweeper.run(self.clock_now)
        self.assertEqual((second.streams, second.quarantine), (1, 1))
        self.assertEqual(self.attempts(opened), [(1, "abandoned")])
        self.assertEqual(self.record_states(), ["deleted", "deleted", "sealed"])
        self.assertEqual(self.streams(), 0)
        # Past every candidate's deadline and the session lifetime, everything ends.
        self.advance(CANDIDATE_LIFETIME.total_seconds())
        third = self.sweeper.run(self.clock_now)
        self.assertEqual((third.candidates, third.sessions), (3, 1))
        # A quarantined candidate no validation reached expires too, and its sealed object goes with it.
        self.assertEqual(self.state(sealed), "expired")
        self.assertEqual(self.record_states(), ["deleted", "deleted", "deleted"])
        self.assertEqual(self.stored(), [])
        self.assert_quota_consistent()
        self.advance(IDEMPOTENCY_RETENTION.total_seconds())
        self.assertEqual(self.sweeper.run(self.clock_now).idempotency, 3)
        self.assertEqual(self.scalar("SELECT count(*) FROM upload_capabilities"), 0)

    def test_a_pass_that_cannot_delete_leaves_the_key_for_the_next_and_reports_the_lag(self):
        data = payload(2 * CHUNK)
        candidate, capability = self.ready(data)
        with mock.patch.object(Transfers, "seal_stream", side_effect=PersistenceRefusal("database_unavailable")):
            self.upload(candidate, capability, data)
        # This stream's own cleanup already removed its object; put one back as a stopped process would leave it.
        key = self.scalar("SELECT object_key FROM quarantine_objects")
        (self.root / "quarantine" / key.replace("quarantine/", "").replace("/", ".").replace("-", ".")).write_bytes(
            data)
        self.quarantine.fault = "delete-fails"
        with recorded_events() as events:
            report = self.sweeper.run(self.clock_now)
        self.assertEqual((report.quarantine, report.delete_failures), (0, 1))
        self.assertIn("quarantine-delete-failed", [event["event"] for event in events])
        self.assertEqual(self.record_states(), ["deleting"])
        self.advance(3600)
        self.assertEqual(self.transfers.quarantine_usage(self.clock_now)["cleanup_lag_seconds"], 3600)
        self.quarantine.fault = None
        self.assertEqual(self.sweeper.run(self.clock_now).quarantine, 1)
        self.assertEqual((self.record_states(), self.stored()), (["deleted"], []))
        self.assertEqual(self.transfers.quarantine_usage(self.clock_now)["cleanup_lag_seconds"], 0)

    def test_the_lifecycle_deletes_day_old_objects_only_where_the_record_agrees(self):
        data = payload(CHUNK)
        candidate, capability = self.ready(data)
        self.assertEqual(self.upload(candidate, capability, data).status, 202)
        [sealed_name] = self.stored()
        orphan_name = "0" * 32 + ".01." + "1" * 32
        (self.root / "quarantine" / orphan_name).write_bytes(b"left by a lost record")
        old = (T0 - timedelta(days=2)).timestamp()
        for name in (sealed_name, orphan_name):
            os.utime(self.root / "quarantine" / name, (old, old), follow_symlinks=False)
        # The store says both are old; the service clock says the sealed object is minutes old.
        report = self.sweeper.run(self.clock_now)
        self.assertEqual(report.lifecycle, 1)
        self.assertEqual(self.stored(), [sealed_name])
        self.advance(CANDIDATE_LIFETIME.total_seconds())
        self.sweeper.run(self.clock_now)
        self.assertEqual(self.stored(), [])
        self.assertEqual(self.record_states(), ["deleted"])

    def test_the_sweeper_never_touches_a_live_stream(self):
        data = payload(4 * CHUNK)
        candidate, capability = self.ready(data)
        reports = []
        steps = body_steps(data)
        steps.insert(2, effect(lambda: reports.append(self.sweeper.run(self.clock_now))))
        self.assertEqual(self.put(candidate, capability, steps).status, 202)
        self.assertEqual((reports[0].streams, reports[0].quarantine), (0, 0))
        self.assertEqual(self.record_states(), ["sealed"])


class CrashRetryTests(SweeperCase):
    def test_a_crash_before_the_seal_restarts_by_the_lease_and_never_touches_sealed_bytes(self):
        data = payload(3 * CHUNK)
        candidate, capability = self.ready(data, lifetime=300)
        with mock.patch.object(UploadGateway, "_abandon"), mock.patch.object(
                Transfers, "seal_stream", side_effect=RuntimeError("crash")):
            crashed = self.upload(candidate, capability, data)
        self.assert_refused(crashed, 503, "authority_unavailable")
        self.assertEqual(self.attempts(candidate), [(1, "open")])
        # The stream still owns its lease: neither the capability nor a new one can start another.
        self.assert_refused(self.upload(candidate, capability, data), 409, "upload_in_progress")
        with self.assertRaises(Exception) as caught:
            self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual(caught.exception.code, "upload_in_progress")
        self.advance(1800)
        self.endorse(candidate, data)
        retry = self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual((retry.attempt_number, self.attempts(candidate)), (2, [(1, "abandoned"), (2, "open")]))
        self.assertEqual(self.upload(candidate, retry, data).status, 202)
        sealed_key = self.scalar("SELECT object_key FROM quarantine_objects WHERE state = 'sealed'")
        before = self.stored()
        self.sweeper.run(self.clock_now)
        self.assertEqual(len(self.stored()), len(before) - 1)
        self.assertEqual(self.record_states(), ["deleted", "sealed"])
        self.assertEqual(self.transfers.sealed_object(candidate, 2).object_key, sealed_key)

    def test_a_crash_after_the_seal_replays_the_recorded_result(self):
        data = payload(2 * CHUNK)
        candidate, capability = self.ready(data)
        real = Transfers.seal_stream

        def sealed_then_lost(transfers, *arguments):
            real(transfers, *arguments)
            raise PersistenceRefusal("database_unavailable")

        with mock.patch.object(Transfers, "seal_stream", sealed_then_lost):
            lost = self.upload(candidate, capability, data)
        self.assert_refused(lost, 503, "policy_unavailable")
        # The seal committed before the reply was lost: its bytes and record stay.
        self.assertEqual(self.attempts(candidate), [(1, "sealed")])
        [name] = self.stored()
        replayed = self.upload(candidate, capability, data)
        self.assertEqual((replayed.status, replayed.body["replayed"], replayed.body["sha256"]),
                         (200, True, sha256(data)))
        self.assertEqual((self.root / "quarantine" / name).read_bytes(), data)
        done = self.issuer.complete(ACTOR, candidate, {"attempt": 1, "length": len(data), "sha256": sha256(data)},
                                    self.clock_now)
        self.assertIsInstance(done, Completed)

    def test_a_disconnect_then_a_new_attempt_seals(self):
        data = payload(3 * CHUNK)
        candidate, capability = self.ready(data)
        self.assert_refused(self.put(candidate, capability, body_steps(data)[:1] + [disconnect()]), 422,
                            "upload_integrity")
        retry = self.issuer.issue(ACTOR, candidate, self.clock_now)
        self.assertEqual(self.upload(candidate, retry, data).status, 202)
        self.assertEqual(self.attempts(candidate), [(1, "failed"), (2, "sealed")])
        text = json.dumps(self.query("SELECT event, code FROM audit_events WHERE event = 'upload-failed'"))
        self.assertIn("upload_integrity", text)

    def test_a_restarted_gateway_removes_staged_leftovers(self):
        leftover = self.root / "staging" / ("a" * 32 + ".part")
        leftover.write_bytes(b"x" * 100)
        self.staging.close()
        self.staging = self.make_staging()
        self.assertFalse(leftover.exists())
        self.assertEqual(self.staging.usage()["reserved_bytes"], 0)
