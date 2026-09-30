"""The quarantine store and trusted staging: fresh keys, full read-back, substitution and immutability."""

import errno
import hashlib
import os
from unittest import mock

import psycopg

from fiat_checkpoints.api.app import StartupRefusal
from fiat_checkpoints.domain.coordination import CoordinationRefusal
from fiat_checkpoints.storage.quarantine import DirectoryQuarantine, QuarantineError, read_back
from fiat_checkpoints.upload.staging import StagingArea, StagingRefusal, stage_sealed
from tests.upload_support import CHUNK, UploadCase, body_steps, effect, payload, sha256


KEY = "quarantine/" + "a" * 32 + "/01-" + "b" * 32


class DirectoryStoreTests(UploadCase):
    def source(self, data):
        path = self.root / "source.bin"
        path.write_bytes(data)
        descriptor = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        return descriptor

    def test_a_key_is_created_once_read_in_full_and_never_overwritten(self):
        store = DirectoryQuarantine(self.root / "quarantine")
        self.addCleanup(store.close)
        data = payload(3 * CHUNK)
        store.put_new(KEY, self.source(data), len(data))
        self.assertEqual(b"".join(store.read(KEY)), data)
        self.assertEqual(read_back(store, KEY, len(data)), (len(data), sha256(data)))
        with self.assertRaises(QuarantineError) as caught:
            store.put_new(KEY, self.source(payload(CHUNK, b"other")), CHUNK)
        self.assertEqual(caught.exception.code, "quarantine_conflict")
        self.assertEqual(b"".join(store.read(KEY)), data)
        self.assertEqual(read_back(store, KEY, len(data) - 1)[1], None)
        store.delete(KEY)
        store.delete(KEY)
        with self.assertRaises(QuarantineError) as caught:
            list(store.read(KEY))
        self.assertEqual(caught.exception.code, "quarantine_missing")

    def test_a_crafted_key_or_a_planted_link_cannot_redirect_a_write_or_a_read(self):
        store = DirectoryQuarantine(self.root / "quarantine")
        self.addCleanup(store.close)
        for key in ("quarantine/../escape", "quarantine/" + "a" * 32 + "/1-" + "b" * 32, "/etc/passwd",
                    KEY + "\n", KEY.upper(), None):
            with self.subTest(key=key), self.assertRaises(QuarantineError) as caught:
                store.put_new(key, self.source(b"x"), 1)
            self.assertEqual(caught.exception.code, "quarantine_unavailable")
        outside = self.root / "outside.bin"
        outside.write_bytes(b"outside")
        link = self.root / "quarantine" / ("a" * 32 + ".01." + "b" * 32)
        os.symlink(outside, link)
        with self.assertRaises(QuarantineError) as caught:
            store.put_new(KEY, self.source(b"planted"), 7)
        self.assertEqual(caught.exception.code, "quarantine_conflict")
        with self.assertRaises(QuarantineError) as caught:
            list(store.read(KEY))
        self.assertEqual(caught.exception.code, "quarantine_unavailable")
        self.assertEqual(outside.read_bytes(), b"outside")
        store.delete(KEY)
        self.assertFalse(os.path.lexists(link))
        self.assertEqual(outside.read_bytes(), b"outside")

    def test_a_shared_or_linked_directory_refuses_to_open(self):
        shared = self.root / "shared"
        shared.mkdir(mode=0o700)
        os.chmod(shared, 0o777)
        os.symlink(self.root / "quarantine", self.root / "linked")
        for factory in (DirectoryQuarantine, lambda path: StagingArea(path, capacity_bytes=1)):
            for path in (shared, self.root / "linked", self.root / "absent"):
                with self.subTest(path=path.name), self.assertRaises(StartupRefusal):
                    factory(path)

    def test_the_lifecycle_listing_names_only_old_quarantine_objects(self):
        store = DirectoryQuarantine(self.root / "quarantine")
        self.addCleanup(store.close)
        store.put_new(KEY, self.source(b"old"), 3)
        young = "quarantine/" + "c" * 32 + "/02-" + "d" * 32
        store.put_new(young, self.source(b"new"), 3)
        (self.root / "quarantine" / "unrelated.txt").write_bytes(b"left alone")
        name = self.root / "quarantine" / ("a" * 32 + ".01." + "b" * 32)
        os.utime(name, (1_000_000, 1_000_000), follow_symlinks=False)
        self.assertEqual(store.older_than(2_000_000, 10), [KEY])


class ReadBackTests(UploadCase):
    def run_fault(self, fault, label, **options):
        data = payload(3 * CHUNK, label.encode())
        candidate, capability = self.ready(data, label=label)
        self.quarantine.close()
        self.quarantine = self.make_quarantine(fault=fault, **options)
        self.addCleanup(self.quarantine.close)
        gateway = self.make_gateway(quarantine=self.quarantine)
        return candidate, self.upload(candidate, capability, data, app=gateway), data

    def test_a_store_that_loses_changes_or_swaps_bytes_never_seals_and_keeps_the_evidence(self):
        for fault in ("short-write", "truncate", "substitute"):
            with self.subTest(fault=fault):
                candidate, response, _data = self.run_fault(fault, fault)
                self.assert_refused(response, 503, "authority_unavailable")
                self.assertEqual(self.attempts(candidate), [(1, "failed")])
                self.assert_nothing_held(candidate)
                key = self.scalar("SELECT object_key FROM quarantine_objects WHERE candidate_id = %s", (candidate,))
                self.assertEqual(self.scalar("SELECT state FROM quarantine_objects WHERE object_key = %s", (key,)),
                                 "held")
        # Held objects stay out of every sweep until an operator releases one.
        self.assertEqual(len(self.stored()), 3)
        self.assertEqual(self.transfers.claim_deletions(self.clock_now), [])
        self.assertEqual(self.transfers.quarantine_usage(self.clock_now)["held"], 3)
        key = self.scalar("SELECT object_key FROM quarantine_objects ORDER BY object_key LIMIT 1")
        self.assertTrue(self.transfers.release_held(key, self.clock_now))
        self.assertEqual(self.transfers.claim_deletions(self.clock_now), [key])

    def test_a_full_or_unavailable_store_asks_for_a_retry(self):
        candidate, response, _data = self.run_fault("full", "full")
        self.assert_refused(response, 503, "storage_unavailable")
        self.assertEqual(self.attempts(candidate), [(1, "failed")])
        self.assert_nothing_held(candidate)

    def test_late_visibility_is_waited_for_a_bounded_number_of_reads(self):
        candidate, response, data = self.run_fault(None, "late", late_reads=2)
        self.assertEqual(response.status, 202, response.text)
        self.assertEqual(self.quarantine.reads, 3)
        with mock.patch("fiat_checkpoints.storage.quarantine.time.sleep"):
            candidate, response, _data = self.run_fault(None, "never", late_reads=10)
        self.assert_refused(response, 503, "storage_unavailable")
        self.assertEqual(self.attempts(candidate), [(1, "failed")])

    def test_an_occupied_key_passes_only_with_exactly_the_declared_bytes(self):
        for occupant, status in ((None, 202), (b"z" * (3 * CHUNK), 503)):
            with self.subTest(exact=occupant is None):
                data = payload(3 * CHUNK, b"occupied" + bytes([status % 7]))
                candidate, capability = self.ready(data, label=f"occupied-{status}")
                name = candidate.hex + ".01." + "e" * 32
                (self.root / "quarantine" / name).write_bytes(occupant or data)
                with mock.patch("fiat_checkpoints.api.gateway.secrets.token_hex", return_value="e" * 32):
                    response = self.upload(candidate, capability, data)
                self.assertEqual(response.status, status, response.text)
                if status == 503:
                    # Someone else's bytes under the attempt's key are kept, never replaced.
                    self.assertEqual(response.body["code"], "authority_unavailable")
                    self.assertEqual((self.root / "quarantine" / name).read_bytes(), occupant)


class ImmutabilityTests(UploadCase):
    def sealed(self):
        data = payload(CHUNK)
        candidate, capability = self.ready(data)
        self.assertEqual(self.upload(candidate, capability, data).status, 202)
        return candidate, data

    def refused(self, statement, parameters=()):
        connection = self.database.connect()
        try:
            with self.assertRaises(psycopg.errors.CheckViolation):
                connection.execute(statement, parameters)
        finally:
            connection.close()

    def test_a_sealed_attempt_and_its_quarantine_record_never_change(self):
        candidate, _data = self.sealed()
        self.refused("UPDATE upload_attempts SET sealed_size = 1 WHERE candidate_id = %s", (candidate,))
        self.refused("UPDATE upload_attempts SET state = 'failed' WHERE candidate_id = %s", (candidate,))
        self.refused("DELETE FROM upload_attempts WHERE candidate_id = %s", (candidate,))
        self.refused("UPDATE quarantine_objects SET sealed_sha256 = %s", ("0" * 64,))
        self.refused("UPDATE quarantine_objects SET object_key = %s", ("quarantine/" + "f" * 32 + "/01-" + "f" * 32,))
        self.refused("UPDATE quarantine_objects SET state = 'writing'")
        self.refused("DELETE FROM quarantine_objects")
        self.refused("TRUNCATE quarantine_objects")
        self.refused("UPDATE upload_capabilities SET capability_sha256 = %s, issues = issues + 1", ("1" * 64,))

    def test_an_attempt_a_capability_names_cannot_seal_without_its_read_back_record(self):
        data = payload(CHUNK)
        candidate, _capability = self.ready(data)
        self.refused("UPDATE upload_attempts SET state = 'sealed', sealed_size = %s, sealed_sha256 = %s "
                     "WHERE candidate_id = %s", (len(data), sha256(data), candidate))
        self.assertEqual(self.attempts(candidate), [(1, "open")])

    def test_a_capability_is_never_renewed_after_its_stream_started(self):
        data = payload(4 * CHUNK)
        candidate, capability = self.ready(data)
        steps = body_steps(data)
        steps.insert(1, effect(lambda: self.refused(
            "UPDATE upload_capabilities SET capability_sha256 = %s, issues = issues + 1", ("2" * 64,))))
        self.assertEqual(self.put(candidate, capability, steps).status, 202)


class StagingBrokerTests(UploadCase):
    def sealed_object(self):
        data = payload(3 * CHUNK, b"broker")
        candidate, capability = self.ready(data)
        self.assertEqual(self.upload(candidate, capability, data).status, 202)
        return self.transfers.sealed_object(candidate, 1), data

    def test_the_broker_hands_on_the_checked_bytes_by_descriptor(self):
        sealed, data = self.sealed_object()
        jobs = self.root / "job"
        jobs.mkdir(mode=0o700)
        staged = stage_sealed(self.quarantine, sealed, jobs)
        self.addCleanup(staged.close)
        self.assertEqual((staged.size, staged.sha256), (len(data), sha256(data)))
        [name] = os.listdir(jobs)
        self.assertEqual((jobs / name).stat().st_mode & 0o777, 0o400)
        # Replacing the path afterwards does not change what the descriptor reads.
        os.unlink(jobs / name)
        (jobs / name).write_bytes(b"swapped" * 100)
        self.assertEqual(hashlib.sha256(b"".join(staged.chunks())).hexdigest(), sha256(data))

    def test_a_substituted_or_missing_quarantine_object_is_refused(self):
        sealed, data = self.sealed_object()
        jobs = self.root / "job"
        jobs.mkdir(mode=0o700)
        [name] = self.stored()
        path = self.root / "quarantine" / name
        path.chmod(0o600)
        path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        for replacement in (None, data + b"x", data[:-1]):
            if replacement is not None:
                path.write_bytes(replacement)
            with self.subTest(size=path.stat().st_size), self.assertRaises(StagingRefusal) as caught:
                stage_sealed(self.quarantine, sealed, jobs)
            self.assertEqual(caught.exception.code, "staging_mismatch")
        path.unlink()
        with self.assertRaises(StagingRefusal) as caught:
            stage_sealed(self.quarantine, sealed, jobs)
        self.assertEqual(caught.exception.code, "staging_unavailable")
        self.assertEqual(os.listdir(jobs), [])

    def test_only_a_sealed_attempt_has_a_staging_record(self):
        data = payload(CHUNK)
        candidate, _capability = self.ready(data)
        with self.assertRaises(CoordinationRefusal) as caught:
            self.transfers.sealed_object(candidate, 1)
        self.assertEqual(caught.exception.code, "not_found")


class StagingAreaTests(UploadCase):
    def test_leftovers_go_when_the_area_opens_and_other_files_stay(self):
        leftover = self.root / "staging" / ("f" * 32 + ".part")
        leftover.write_bytes(b"left by a stopped process")
        other = self.root / "staging" / "notes.txt"
        other.write_bytes(b"kept")
        area = self.make_staging()
        self.assertFalse(leftover.exists())
        self.assertTrue(other.exists())
        reservation = area.reserve(10)
        reservation.create()
        self.assertEqual(area.sweep(), 0)
        reservation.close()
        reservation.close()
        self.assertEqual(area.usage()["reserved_bytes"], 0)

    def test_a_link_planted_at_a_staged_name_is_never_followed(self):
        target = self.root / "target.bin"
        target.write_bytes(b"untouched")
        with mock.patch("fiat_checkpoints.upload.staging.secrets.token_hex", return_value="1" * 32):
            reservation = self.staging.reserve(10)
        os.symlink(target, self.root / "staging" / ("1" * 32 + ".part"))
        with self.assertRaises(StagingRefusal) as caught:
            reservation.create()
        self.assertEqual(caught.exception.code, "staging_unavailable")
        reservation.close()
        self.assertEqual(target.read_bytes(), b"untouched")
        # Closing removes only what the reservation created; the next sweep removes the link itself.
        self.assertTrue(os.path.lexists(self.root / "staging" / ("1" * 32 + ".part")))
        self.assertEqual(self.staging.sweep(), 1)
        self.assertFalse(os.path.lexists(self.root / "staging" / ("1" * 32 + ".part")))
        self.assertEqual(target.read_bytes(), b"untouched")

    def test_a_renamed_directory_keeps_receiving_through_its_descriptor(self):
        data = payload(2 * CHUNK)
        candidate, capability = self.ready(data)
        moved = self.root / "moved"

        def swap_directory():
            os.rename(self.root / "staging", moved)
            os.symlink(self.root / "elsewhere", self.root / "staging")

        (self.root / "elsewhere").mkdir(mode=0o700)
        steps = body_steps(data)
        steps.insert(1, effect(swap_directory))
        self.assertEqual(self.put(candidate, capability, steps).status, 202)
        self.assertEqual(os.listdir(self.root / "elsewhere"), [])
        self.assertEqual(os.listdir(moved), [])

    def test_a_write_error_other_than_a_full_disk_is_unavailable(self):
        reservation = self.staging.reserve(10)
        reservation.create()
        with mock.patch("fiat_checkpoints.upload.staging._write_all", side_effect=OSError(errno.EIO, "x")):
            with self.assertRaises(StagingRefusal) as caught:
                reservation.write(b"0123456789")
        self.assertEqual(caught.exception.code, "staging_unavailable")
        with self.assertRaises(StagingRefusal) as caught:
            reservation.write(b"0" * 11)
        self.assertEqual(caught.exception.code, "body_extra")
        reservation.close()
