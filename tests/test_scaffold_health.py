"""Exercise the actual ASGI app and the local process entry point."""

from contextlib import contextmanager
import io
import json
import logging
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from fastapi.testclient import TestClient
import httpx

from fiat_checkpoints.api.app import create_app
from fiat_checkpoints.config import load_config
from fiat_checkpoints.telemetry.logging import EventFormatter


ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def recorded_events():
    logger = logging.getLogger("fiat_checkpoints")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(EventFormatter())
    previous = (logger.handlers[:], logger.level, logger.propagate)
    logger.handlers[:] = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        yield stream
    finally:
        logger.handlers[:], logger.level, logger.propagate = previous


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(create_app(load_config(ROOT / "config/local.json"), ROOT))
        self.addCleanup(self.client.close)

    def test_liveness_and_readiness_are_distinct(self):
        live = self.client.get("/health/live")
        ready = self.client.get("/health/ready")
        self.assertEqual((live.status_code, live.json()), (200, {"status": "live"}))
        self.assertEqual((ready.status_code, ready.json()),
                         (503, {"status": "unavailable", "code": "intake-closed"}))
        self.assertEqual(ready.headers["cache-control"], "no-store")

    def test_only_health_routes_exist(self):
        for route in ("/", "/openapi.json", "/docs", "/redoc", "/login", "/announce", "/upload", "/download", "/status"):
            with self.subTest(route=route):
                self.assertEqual(self.client.get(route).status_code, 404)
                self.assertEqual(self.client.post(route, content=b"untrusted-body").status_code, 404)
        self.assertEqual(self.client.post("/health/live", content=b"untrusted-body").status_code, 405)

    def test_logs_have_bounded_fields_and_generated_correlation(self):
        marker = "private-request-marker"
        with recorded_events() as events:
            response = self.client.get("/unknown/" + marker + "?value=" + marker,
                                       headers={"authorization": marker, "x-request-id": marker})
        self.assertNotIn(marker, events.getvalue())
        event = json.loads(events.getvalue())
        self.assertEqual(set(event), {"event", "request_id", "route", "status", "duration_us"})
        self.assertEqual((event["event"], event["route"], event["status"]), ("health-request", "other", 404))
        self.assertRegex(event["request_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(response.headers["x-request-id"], event["request_id"])
        self.assertIs(type(event["duration_us"]), int)
        self.assertGreaterEqual(event["duration_us"], 0)

    def test_startup_refusal_is_structured_and_value_free(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "local.json"
            data = json.loads((ROOT / "config/local.json").read_bytes())
            data["profile"] = "production"
            config.write_text(json.dumps(data))
            run = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/serve.py"), "--config", str(config)],
                                 capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(run.stdout, "")
        event = json.loads(run.stderr)
        self.assertEqual(event["event"], "startup-refused")
        self.assertIn("test-trust-forbidden", event["codes"])
        self.assertNotIn(temporary, run.stderr)

    def test_actual_local_process_reports_closed_readiness(self):
        with tempfile.TemporaryDirectory() as temporary:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            data = json.loads((ROOT / "config/local.json").read_bytes())
            data["port"] = port
            config = Path(temporary) / "local.json"
            config.write_text(json.dumps(data))
            output = Path(temporary) / "events.jsonl"
            with output.open("w+") as stream:
                process = subprocess.Popen([sys.executable, "-I", str(ROOT / "scripts/serve.py"), "--config", str(config)],
                                           stdout=stream, stderr=stream)
                try:
                    with httpx.Client(trust_env=False, timeout=0.5) as client:
                        deadline = time.monotonic() + 10
                        while True:
                            try:
                                live = client.get(f"http://127.0.0.1:{port}/health/live")
                                break
                            except httpx.TransportError:
                                if process.poll() is not None or time.monotonic() >= deadline:
                                    self.fail("local process did not expose health")
                                time.sleep(0.025)
                        ready = client.get(f"http://127.0.0.1:{port}/health/ready")
                        self.assertEqual(live.status_code, 200)
                        self.assertEqual(ready.status_code, 503)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                stream.seek(0)
                events = [json.loads(line) for line in stream if line.strip()]
                self.assertEqual(events[0]["event"], "local-health-starting")
                self.assertEqual([event["status"] for event in events if event["event"] == "health-request"], [200, 503])
