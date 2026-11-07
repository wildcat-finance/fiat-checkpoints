"""Measured bounds of the intake path: metadata latency, validation wall time and gateway memory.

Metron: every check here measures on this host and holds the specification's
section 17 ceiling; none is a production capacity claim. The metadata p95
gate is not here: `scripts/latency.py` holds it on the native aarch64 latency
profile, because this x86_64 profile is emulated. Validation wall time is the
released valid fixture through the sandboxed native sequence, as
`scripts/benchmark.sh` measures it. Gateway
memory is the Step 5 per-stream measurement in `fiat_checkpoints.demo.streams`,
which the `gateway-stream-memory` design criterion also calls.
"""

import unittest

from fiat_checkpoints.demo.streams import measure_stream_memory
from fiat_checkpoints.records.trees import REPOSITORY
from fiat_checkpoints.validation.benchmark import measure as measure_validation
from fiat_checkpoints.validation.sandbox import Sandbox
from fiat_checkpoints.validation.service import service_binds
from tests import authority_fixtures as fixtures
from tests.test_demo_scenario import METADATA_ROUTES, latency, p95
from tests.test_upload_streams import STREAM_MEMORY_CEILING
from tests.upload_support import MIB


# Specification section 17 and the design record's integration gates.
VALIDATION_BUDGET_MS = 900_000


class PercentileTests(unittest.TestCase):
    def test_p95_is_nearest_rank(self):
        self.assertEqual(p95([5]), 5)
        self.assertEqual(p95([3, 1, 2]), 3)
        self.assertEqual(p95(list(range(1, 21))), 19)
        self.assertEqual(p95(list(range(1, 101))), 95)

    def test_latency_counts_metadata_routes_only(self):
        timings = [("announce", 10.0), ("endorsement", 30.0), ("status", 20.0), ("login", 9000.0),
                   ("upload", 8000.0)]
        record = latency(timings)
        self.assertEqual(set(record["routes"]), {"announce", "endorsement", "status"})
        self.assertEqual((record["count"], record["p95_ms"]), (3, 30.0))
        self.assertNotIn("login", METADATA_ROUTES)
        self.assertNotIn("upload", METADATA_ROUTES)


class GatewayStreamMemoryTests(unittest.TestCase):
    """Starts no process: the gateway, staging and store run in this process against PostgreSQL."""

    def test_incremental_memory_per_stream_stays_under_64_mib(self):
        rows = measure_stream_memory()
        self.assertEqual([row["declared_bytes"] for row in rows], [4 * MIB, 96 * MIB])
        for row in rows:
            self.assertEqual(row["status"], 202, row)
            self.assertLessEqual(row["incremental_python_bytes"], STREAM_MEMORY_CEILING)
            self.assertEqual(row["staged_after_bytes"], 0)
        self.assertLess(rows[1]["incremental_python_bytes"] - rows[0]["incremental_python_bytes"], 4 * MIB)


class ValidationWallTimeTests(unittest.TestCase):
    """The released valid fixture through a fresh gVisor sandbox; needs `scripts/sandbox-env.sh run`."""

    spawns_child_process = True

    def test_current_valid_fixture_validates_within_900000_ms(self):
        sandbox = Sandbox()
        sandbox.check()
        report = measure_validation(sandbox, fixtures.release(), 1, binds=service_binds(REPOSITORY))
        [sample] = report["samples"]
        self.assertTrue(sample["completed"], sample["refusal"])
        self.assertLessEqual(sample["wall_ms"], VALIDATION_BUDGET_MS)
        self.assertTrue(report["passed"])


if __name__ == "__main__":
    unittest.main()
