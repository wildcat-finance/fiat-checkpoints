"""Hostile configuration inputs and production admission refusals."""

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest

from fiat_checkpoints.api.app import create_app, production_refusals, StartupRefusal
from fiat_checkpoints.config import ConfigError, load_config, parse_config


ROOT = Path(__file__).resolve().parents[1]


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "config/local.json").read_bytes())

    def parse(self, data):
        return parse_config(json.dumps(data).encode())

    def test_local_examples_parse(self):
        self.assertEqual(load_config(ROOT / "config/local.json").profile, "local")
        self.assertEqual(load_config(ROOT / "config/container.json").host, "0.0.0.0")

    def test_every_required_field_is_required(self):
        for key in self.data:
            with self.subTest(key=key), self.assertRaisesRegex(ConfigError, "configuration-fields"):
                self.parse({k: v for k, v in self.data.items() if k != key})

    def test_unknown_keys_and_top_level_types_refuse(self):
        for data in ([self.data], None, 1, "configuration", dict(self.data, extra=True)):
            with self.subTest(kind=type(data).__name__), self.assertRaises(ConfigError):
                self.parse(data)

    def test_duplicate_keys_refuse_even_if_values_agree(self):
        raw = json.dumps(self.data).removesuffix("}") + ',"profile":"local"}'
        with self.assertRaisesRegex(ConfigError, "configuration-duplicate-key"):
            parse_config(raw.encode())

    def test_malformed_utf8_json_constants_and_depth_refuse(self):
        for raw in (b"\xff", b"{", b"{} {}", b"NaN", b"Infinity", b"[" * 2000 + b"]" * 2000):
            with self.subTest(raw_length=len(raw)), self.assertRaises(ConfigError):
                parse_config(raw)

    def test_integer_fields_reject_coercion_and_bounds(self):
        for key, maximum in (("port", 65535), ("schema_version", 1),
                             ("request_max_bytes", 65536), ("carrier_max_bytes", 1073741824),
                             ("validation_concurrency", 4)):
            for value in (True, False, "1", 1.0, None, [], {}, 0, -1, maximum + 1):
                with self.subTest(key=key, value=value), self.assertRaises(ConfigError):
                    self.parse(dict(self.data, **{key: value}))

    def test_text_fields_do_not_coerce(self):
        for key in ("profile", "service_id", "environment_id", "host", "trust_profile", "sandbox_profile"):
            for value in (None, 1, True, [], {}, "", "bad\nvalue"):
                with self.subTest(key=key, value=value), self.assertRaises(ConfigError):
                    self.parse(dict(self.data, **{key: value}))

    def test_protocol_path_cannot_select_a_private_file(self):
        for value in ("../private.json", "/etc/passwd", "https://example.org/lock", [], True):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                self.parse(dict(self.data, protocol_lock=value))

    def test_local_identity_cannot_appear_production(self):
        for field, value in (("trust_profile", "production"), ("environment_id", "live")):
            with self.subTest(field=field), self.assertRaises(ConfigError):
                self.parse(dict(self.data, **{field: value}))

    def test_size_and_file_kind_are_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = root / "missing.json"
            with self.assertRaisesRegex(ConfigError, "configuration-unavailable"):
                load_config(missing)
            large = root / "large.json"
            large.write_bytes(b" " * 16385)
            with self.assertRaises(ConfigError):
                load_config(large)
            link = root / "link.json"
            link.symlink_to(ROOT / "config/local.json")
            with self.assertRaises(ConfigError):
                load_config(link)
            fifo = root / "pipe"
            os.mkfifo(fifo)
            with self.assertRaises(ConfigError):
                load_config(fifo)
            with self.assertRaises(ConfigError):
                load_config(root)

    def test_production_test_trust_missing_pin_and_isolation_refuse(self):
        settings = replace(self.parse(self.data), profile="production")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(production_refusals(settings, root), (
                "test-trust-forbidden", "protocol-pin-missing", "isolation-unavailable", "scaffold-only"
            ))
            with self.assertRaises(StartupRefusal):
                create_app(settings, root)

    def test_declarations_and_an_existing_file_cannot_open_production(self):
        settings = replace(self.parse(self.data), profile="production", environment_id="production",
                           trust_profile="production", protocol_lock="protocol.lock.json", sandbox_profile="gvisor")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "protocol.lock.json").write_bytes(b"untrusted opaque bytes")
            with self.assertRaises(StartupRefusal) as caught:
                create_app(settings, root)
            self.assertEqual(caught.exception.codes, ("isolation-unavailable", "scaffold-only"))

    def test_error_does_not_repeat_supplied_value(self):
        marker = "configuration-private-marker"
        with self.assertRaises(ConfigError) as caught:
            self.parse(dict(self.data, host=marker))
        self.assertNotIn(marker, str(caught.exception))
