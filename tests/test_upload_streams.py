"""Slow and expiring streams, disk exhaustion, the proxy-size guard and the measured per-stream bounds."""

import asyncio
from dataclasses import replace
import errno
import gc
import os
import resource
import tempfile
import tracemalloc
from datetime import timedelta
from pathlib import Path
from unittest import mock

from fiat_checkpoints.api.app import StartupRefusal, production_refusals
from fiat_checkpoints.api.gateway import EdgeProfile, GatewayLimits, create_gateway_app, edge_refusals
from fiat_checkpoints.domain.coordination import CANDIDATE_LIFETIME, GIB, CoordinationRefusal
from fiat_checkpoints.storage.quarantine import R2Quarantine
from fiat_checkpoints.upload import staging as staging_module
from fiat_checkpoints.upload.staging import StagingArea, StagingRefusal
from tests.persistence_support import T0, recorded_events
from fiat_checkpoints.persistence.transfer import object_key
from fiat_checkpoints.upload.capability import capability_sha256
from tests.upload_support import (ACTOR, CHUNK, MIB, SETTINGS, UploadCase, body_steps, chunk, effect, exchange,
                                  pause, payload, repeated, run)


# Specification section 17: gateway incremental memory at most 64 MiB per stream.
STREAM_MEMORY_CEILING = 67_108_864


class SlowStreamTests(UploadCase):
    limits = GatewayLimits(idle_seconds=0.3, stream_seconds=1.2)

    def test_an_idle_stream_ends_and_gives_everything_back(self):
        data = payload(4 * CHUNK)
        candidate, capability = self.ready(data)
        steps = body_steps(data)
        steps.insert(2, pause(0.6))
        with recorded_events() as events:
            response = self.put(candidate, capability, steps)
        self.assert_refused(response, 422, "upload_integrity")
        self.assertIn("stream-idle", [event.get("reason") for event in events])
        self.assertEqual(self.attempts(candidate), [(1, "failed")])
        self.assert_nothing_held(candidate)

    def test_a_client_that_stops_sending_is_ended_by_the_idle_limit(self):
        data = payload(4 * CHUNK)
        candidate, capability = self.ready(data)
        response = self.put(candidate, capability, body_steps(data)[:2])
        self.assert_refused(response, 422, "upload_integrity")
        self.assert_nothing_held(candidate)

    def test_a_trickle_is_ended_by_the_absolute_limit(self):
        data = payload(16 * 1024)
        candidate, capability = self.ready(data)
        steps = []
        for item in body_steps(data, 1024):
            steps += [pause(0.15), item]
        with recorded_events() as events:
            response = self.put(candidate, capability, steps)
        self.assert_refused(response, 422, "upload_integrity")
        self.assertIn("stream-deadline", [event.get("reason") for event in events])
        self.assert_nothing_held(candidate)


class ExpiryDuringTransferTests(UploadCase):
    def test_the_candidate_deadline_during_a_stream_refuses_as_expired(self):
        data = payload(4 * CHUNK)
        candidate, capability = self.ready(data)
        steps = body_steps(data)
        steps.insert(2, effect(lambda: self.advance(CANDIDATE_LIFETIME.total_seconds())))
        self.assert_refused(self.put(candidate, capability, steps), 410, "candidate_expired")
        self.assertEqual(self.attempts(candidate), [(1, "failed")])
        self.assert_nothing_held(candidate)
        self.assertEqual(self.transfers.expire_due(self.clock_now), 1)
        self.assertEqual(self.state(candidate), "expired")

    def test_the_sweeper_expiring_a_candidate_mid_stream_wins(self):
        data = payload(4 * CHUNK)
        candidate, capability = self.ready(data)

        def sweep():
            self.advance(CANDIDATE_LIFETIME.total_seconds() + 1)
            self.assertEqual(self.transfers.expire_due(self.clock_now), 1)

        steps = body_steps(data)
        steps.insert(2, effect(sweep))
        self.assert_refused(self.put(candidate, capability, steps), 410, "candidate_expired")
        self.assertEqual((self.state(candidate), self.attempts(candidate)), ("expired", [(1, "abandoned")]))
        self.assert_nothing_held(candidate)
        self.assertEqual(self.stored(), [])

    def test_the_stream_lease_ending_mid_stream_refuses(self):
        data = payload(4 * CHUNK)
        candidate, capability = self.ready(data)
        steps = body_steps(data)
        steps.insert(2, effect(lambda: self.advance(1800)))
        with recorded_events() as events:
            self.assert_refused(self.put(candidate, capability, steps), 422, "upload_integrity")
        self.assertIn("stream-deadline", [event.get("reason") for event in events])
        self.assert_nothing_held(candidate)

    def test_a_seal_after_the_deadline_refuses_as_expired(self):
        data = payload(CHUNK)
        candidate, capability = self.ready(data)
        stream = self.transfers.start(capability_sha256(capability.value), object_key(candidate, 1, "c" * 32),
                                      SETTINGS.environment_id, self.clock_now)
        self.assertEqual(stream.lease.expires_at, T0 + timedelta(seconds=1800))
        late = T0 + CANDIDATE_LIFETIME
        with self.assertRaises(CoordinationRefusal) as caught:
            self.transfers.seal_stream(stream.lease, len(data), capability.archive_sha256, stream.object_key, 1,
                                       self.scalar("SELECT endorsement_sha256 FROM upload_capabilities"), late)
        self.assertEqual(caught.exception.code, "candidate_expired")
        self.assertEqual(self.attempts(candidate), [(1, "open")])


class DiskTests(UploadCase):
    capacity_bytes = 3 * CHUNK

    def test_staging_capacity_is_reserved_before_any_byte_is_read(self):
        first_data, second_data = payload(2 * CHUNK, b"first"), payload(2 * CHUNK, b"second")
        first, first_capability = self.ready(first_data, "first")
        second, second_capability = self.ready(second_data, "second")
        steps = body_steps(first_data)
        steps.insert(1, pause(0.5))

        async def overlapping():
            running = asyncio.create_task(exchange(
                self.gateway, "PUT", f"/v1/candidates/{first}/content",
                self.headers(first_capability, len(first_data)), steps))
            await asyncio.sleep(0.2)
            refused = await exchange(self.gateway, "PUT", f"/v1/candidates/{second}/content",
                                     self.headers(second_capability, len(second_data)), body_steps(second_data))
            return await running, refused

        sealed, refused = run(overlapping())
        self.assertEqual(sealed.status, 202, sealed.text)
        self.assert_refused(refused, 429, "quota_exceeded")
        # The refused stream never started: its capability still seals once there is room.
        self.assertEqual(self.attempts(second), [(1, "open")])
        self.assertEqual(self.upload(second, second_capability, second_data).status, 202)

    def test_a_declared_size_over_the_free_floor_is_refused(self):
        data = payload(2 * CHUNK)
        candidate, capability = self.ready(data)
        self.staging.close()
        self.staging = self.make_staging(floor_bytes=10 * CHUNK, free_bytes=lambda: 11 * CHUNK)
        gateway = self.make_gateway(staging=self.staging)
        self.assert_refused(self.upload(candidate, capability, data, app=gateway), 429, "quota_exceeded")
        self.assertEqual(self.attempts(candidate), [(1, "open")])

    def test_the_free_floor_holds_once_every_admitted_stream_has_written(self):
        directory = self.root / "floor"
        directory.mkdir(mode=0o700)

        def free():
            # Ten chunks of filesystem whose only other content is the staged files.
            return 10 * CHUNK - sum(entry.stat(follow_symlinks=False).st_size for entry in os.scandir(directory))

        area = StagingArea(directory, capacity_bytes=64 * CHUNK, floor_bytes=6 * CHUNK, free_bytes=free)
        self.addCleanup(area.close)
        first, second = area.reserve(2 * CHUNK), area.reserve(2 * CHUNK)
        # Nothing is written yet, but the two streams will write four chunks.
        with self.assertRaises(StagingRefusal) as caught:
            area.reserve(2 * CHUNK)
        self.assertEqual(caught.exception.code, "staging_full")
        for reservation in (first, second):
            reservation.create()
            reservation.write(payload(2 * CHUNK))
            reservation.finish()
        self.assertEqual(free(), area.floor_bytes)
        # Written bytes count once: removing one file leaves room for exactly one more.
        first.close()
        third = area.reserve(2 * CHUNK)
        for reservation in (second, third):
            reservation.close()
        self.assertEqual(area.usage()["reserved_bytes"], 0)

    def test_the_free_floor_counts_bytes_a_live_stream_has_yet_to_write(self):
        directory = self.root / "staging"

        def free():
            # Seven chunks of filesystem whose only other content is the staged files.
            return 7 * CHUNK - sum(entry.stat(follow_symlinks=False).st_size for entry in os.scandir(directory))

        self.staging.close()
        self.staging = self.make_staging(capacity_bytes=64 * CHUNK, floor_bytes=2 * CHUNK, free_bytes=free)
        gateway = self.make_gateway(staging=self.staging)
        first_data, second_data = payload(3 * CHUNK, b"first"), payload(3 * CHUNK, b"second")
        first, first_capability = self.ready(first_data, "first")
        second, second_capability = self.ready(second_data, "second")
        steps = body_steps(first_data)
        steps.insert(1, pause(0.5))

        async def overlapping():
            running = asyncio.create_task(exchange(
                gateway, "PUT", f"/v1/candidates/{first}/content",
                self.headers(first_capability, len(first_data)), steps))
            await asyncio.sleep(0.2)
            refused = await exchange(gateway, "PUT", f"/v1/candidates/{second}/content",
                                     self.headers(second_capability, len(second_data)), body_steps(second_data))
            return await running, refused

        sealed, refused = run(overlapping())
        self.assertEqual(sealed.status, 202, sealed.text)
        # One chunk of the first stream was on disk and two were still to come.
        self.assertEqual(refused.status, 429, refused.text)
        self.assert_refused(refused, 429, "quota_exceeded")
        self.assertEqual(self.attempts(second), [(1, "open")])
        self.assertEqual(self.upload(second, second_capability, second_data, app=gateway).status, 202)

    def test_a_full_disk_during_the_stream_refuses_as_unavailable_and_cleans_up(self):
        data = payload(3 * CHUNK)
        candidate, capability = self.ready(data)
        real = staging_module._write_all
        written = []

        def filling(descriptor, chunk_bytes):
            if sum(written) + len(chunk_bytes) > CHUNK:
                raise OSError(errno.ENOSPC, "synthetic-full")
            written.append(len(chunk_bytes))
            return real(descriptor, chunk_bytes)

        with mock.patch.object(staging_module, "_write_all", filling):
            response = self.upload(candidate, capability, data)
        self.assert_refused(response, 503, "storage_unavailable")
        self.assertEqual(self.attempts(candidate), [(1, "failed")])
        self.assert_nothing_held(candidate)
        self.assertEqual(self.stored(), [])

    def test_a_staged_name_already_taken_refuses_as_unavailable(self):
        data = payload(2 * CHUNK)
        candidate, capability = self.ready(data)
        taken = self.root / "staging" / ("2" * 32 + ".part")
        taken.write_bytes(b"planted")
        with mock.patch("fiat_checkpoints.upload.staging.secrets.token_hex", return_value="2" * 32):
            response = self.upload(candidate, capability, data)
        self.assert_refused(response, 503, "storage_unavailable")
        self.assertEqual(taken.read_bytes(), b"planted")
        self.assertEqual(self.attempts(candidate), [(1, "failed")])
        self.assertEqual(self.streams(), 0)

    def test_a_staged_file_never_passes_its_declared_size(self):
        data = payload(3 * CHUNK)
        candidate, capability = self.ready(data)
        sizes = []
        steps = []
        for item in body_steps(data):
            steps += [item, effect(lambda: sizes.append(self.staged_bytes()))]
        self.assertEqual(self.put(candidate, capability, steps).status, 202)
        # Sampled after every chunk the gateway read; the request ends before the last sample.
        self.assertEqual(sizes, [CHUNK, 2 * CHUNK])
        self.assertLessEqual(max(sizes), len(data))
        self.assertEqual((self.staged(), self.staged_bytes()), ([], 0))


class ProxyGuardTests(UploadCase):
    def test_a_proxy_below_the_ceiling_or_one_that_buffers_refuses_to_start(self):
        cases = (
            (EdgeProfile("proxy", 100_000_000, True), ("proxy-body-limit",)),
            (EdgeProfile("proxy", GIB - 1, True), ("proxy-body-limit",)),
            (EdgeProfile("proxy", GIB, False), ("proxy-buffering",)),
            (EdgeProfile("proxy", None, False), ("proxy-body-limit", "proxy-buffering")),
            (EdgeProfile("direct", GIB, True), ("configuration-value",)),
            (EdgeProfile("cdn", GIB, True), ("configuration-value",)),
        )
        for edge, codes in cases:
            with self.subTest(edge=edge), self.assertRaises(StartupRefusal) as caught:
                self.make_gateway(edge=edge)
            self.assertEqual(caught.exception.codes, codes)
        self.make_gateway(edge=EdgeProfile("proxy", GIB, True))
        self.make_gateway(edge=EdgeProfile())
        # A lower configured ceiling lowers what the proxy must carry.
        self.assertEqual(edge_refusals(EdgeProfile("proxy", 200_000_000, True), 150_000_000), ())

    def test_a_proxy_that_cuts_a_body_short_seals_nothing(self):
        data = payload(8 * CHUNK)
        candidate, capability = self.ready(data)
        cut = body_steps(data)[:4] + [chunk(b"", False)]
        self.assert_refused(self.put(candidate, capability, cut), 422, "upload_integrity")
        self.assert_nothing_held(candidate)

    def test_limits_and_wiring_refuse_with_fixed_startup_codes(self):
        with self.assertRaises(StartupRefusal) as caught:
            GatewayLimits(idle_seconds=61)
        self.assertEqual(caught.exception.codes, ("configuration-value",))
        for bad in ({"stream_seconds": 1801}, {"carrier_max_bytes": GIB + 1}, {"idle_seconds": 0}):
            with self.subTest(limits=bad), self.assertRaises(StartupRefusal):
                GatewayLimits(**bad)
        low = replace(SETTINGS, carrier_max_bytes=1000)
        with self.assertRaises(StartupRefusal) as caught:
            create_gateway_app(low, self.services())
        self.assertEqual(caught.exception.codes, ("configuration-value",))
        for services in (object(), self.services(quarantine=object()), self.services(transfers=self.coordinator)):
            with self.subTest(services=type(services).__name__), self.assertRaises(StartupRefusal) as caught:
                create_gateway_app(SETTINGS, services)
            self.assertEqual(caught.exception.codes, ("scaffold-only",))
        production_projections = type("Production", (), {"environment": "production"})()
        with self.assertRaises(StartupRefusal) as caught:
            create_gateway_app(SETTINGS, self.services(projections=production_projections))
        self.assertEqual(caught.exception.codes, ("configuration-local-identity",))

    def test_production_and_the_live_quarantine_adapter_refuse_to_start(self):
        production = replace(SETTINGS, profile="production")
        with tempfile.TemporaryDirectory() as temporary:
            expected = production_refusals(production, Path(temporary))
            with self.assertRaises(StartupRefusal) as caught:
                create_gateway_app(production, self.services(), Path(temporary))
            self.assertEqual(caught.exception.codes, expected)
            with self.assertRaises(StartupRefusal) as caught:
                R2Quarantine(production, Path(temporary))
            self.assertEqual(caught.exception.codes, expected)
        self.assertIn("scaffold-only", expected)
        with self.assertRaises(StartupRefusal) as caught:
            R2Quarantine(SETTINGS)
        self.assertEqual(caught.exception.codes, ("scaffold-only",))
        with self.assertRaises(StartupRefusal) as caught:
            R2Quarantine(object())
        self.assertEqual(caught.exception.codes, ("configuration-fields",))


def measure(case, block, count, label=None):
    """Stream `count` copies of `block` through the gateway; return the response and measured bounds.

    Memory is the peak of Python allocations above the level before the
    request, traced across every thread, and the change in the process's peak
    resident set. Disk is the largest staged total seen between chunks and the
    staged and quarantine totals after the request.
    """
    body, steps = repeated(block, count)
    candidate = case.announce(body, label or f"measure-{count}")
    case.endorse(candidate, body)
    capability = case.issuer.issue(ACTOR, candidate, case.clock_now)
    staged = []
    sampled = []
    for index, step in enumerate(steps):
        sampled.append(step)
        if index % 16 == 0:
            sampled.append(effect(lambda: staged.append(case.staged_bytes())))
    gc.collect()
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    tracemalloc.start()
    try:
        base = tracemalloc.get_traced_memory()[0]
        response = case.put(candidate, capability, sampled)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    stored = sum((case.root / "quarantine" / name).stat().st_size for name in case.stored())
    return response, {"declared_bytes": body.size, "incremental_python_bytes": peak - base,
                      "peak_rss_growth_kib": rss_after - rss_before, "staged_peak_bytes": max(staged),
                      "staged_after_bytes": case.staged_bytes(), "quarantine_bytes": stored}


class MeasuredBoundTests(UploadCase):
    """Metron: the stream is measured, not predicted, and its peak does not grow with the carrier."""

    capacity_bytes = 128 * MIB

    def test_gateway_memory_per_stream_stays_bounded_and_does_not_grow_with_size(self):
        block = payload(256 * 1024, b"measure")
        small_response, small = measure(self, block, 16)
        large_response, large = measure(self, block, 384)
        self.assertEqual((small_response.status, large_response.status), (202, 202), large_response.text)
        self.assertEqual((small["declared_bytes"], large["declared_bytes"]), (4 * MIB, 96 * MIB))
        for bounds in (small, large):
            self.assertLessEqual(bounds["incremental_python_bytes"], STREAM_MEMORY_CEILING)
            self.assertLessEqual(bounds["staged_peak_bytes"], bounds["declared_bytes"])
            self.assertEqual(bounds["staged_after_bytes"], 0)
        # 96 MiB streamed without holding it: the peak stays far below the carrier
        # and within a few buffers of the 4 MiB stream's.
        self.assertLess(large["incremental_python_bytes"], 16 * MIB)
        self.assertLess(large["incremental_python_bytes"] - small["incremental_python_bytes"], 4 * MIB)
        self.assertEqual(large["quarantine_bytes"], 100 * MIB)
