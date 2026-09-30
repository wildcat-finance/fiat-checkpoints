"""Secret references: configuration names a credential; only the runtime mount holds its value."""

import io
import logging
import os
from pathlib import Path
import pickle
import tempfile
import unittest

from fiat_checkpoints.auth.secrets import Secret, SecretReference, SecretUnavailable
from fiat_checkpoints.auth.sessions import SessionStore
from fiat_checkpoints.auth.tokens import pkce_challenge, pkce_verifier
from tests.auth_support import SETTINGS, FakeProvider, T0, user_document
from tests.persistence_support import DatabaseCase


VALUE = b"synthetic-client-secret-" + b"7" * 16


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.mount = Path(self.directory.name)

    def write(self, name, value):
        path = self.mount / name
        path.write_bytes(value)
        return path

    def code(self, call):
        with self.assertRaises(SecretUnavailable) as caught:
            call()
        self.assertIsNone(caught.exception.__cause__)
        return caught.exception.code

    def test_a_reference_names_a_secret_and_never_carries_one(self):
        self.assertEqual(SecretReference.parse("secret:login-client").name, "login-client")
        for value in ("synthetic-client-secret", "secret:", "secret:../login", "secret:/run/secrets/x",
                      "secret:Login", "secret:login client", "https://secrets.invalid/x", "SECRET:login",
                      " secret:login", "secret:" + "a" * 64, 7, None, b"secret:login"):
            with self.subTest(value=repr(value)[:24]):
                self.assertEqual(self.code(lambda: SecretReference.parse(value)), "secret-reference-invalid")

    def test_the_value_comes_only_from_one_bounded_regular_file(self):
        self.write("login-client", VALUE + b"\n")
        secret = SecretReference.parse("secret:login-client").resolve(self.mount)
        self.assertEqual(secret.reveal(), VALUE)
        self.assertNotIn(VALUE.decode(), repr(secret) + str(secret) + repr([secret]))
        with self.assertRaises(TypeError):
            pickle.dumps(secret)

    def test_links_special_files_and_bad_sizes_refuse_without_the_value(self):
        target = self.write("real", VALUE)
        cases = {
            "linked": lambda: os.symlink(target, self.mount / "linked"),
            "hard": lambda: os.link(target, self.mount / "hard"),
            "folder": lambda: (self.mount / "folder").mkdir(),
            "pipe": lambda: os.mkfifo(self.mount / "pipe"),
            "empty": lambda: self.write("empty", b""),
            "newline": lambda: self.write("newline", b"\n"),
            "large": lambda: self.write("large", b"x" * 4097),
            "lines": lambda: self.write("lines", b"one\ntwo\n"),
            "nul": lambda: self.write("nul", b"one\x00two"),
        }
        for name, make in cases.items():
            with self.subTest(case=name):
                make()
                code = self.code(lambda: SecretReference(name).resolve(self.mount))
                self.assertEqual(code, "secret-unavailable")
        self.assertEqual(self.code(lambda: SecretReference("missing").resolve(self.mount)), "secret-unavailable")
        self.assertEqual(self.code(lambda: SecretReference("real").resolve("relative/mount")), "secret-mount-invalid")
        linked_mount = Path(self.directory.name + "-link")
        os.symlink(self.mount, linked_mount)
        self.addCleanup(os.unlink, linked_mount)
        self.assertEqual(self.code(lambda: SecretReference("real").resolve(linked_mount)), "secret-unavailable")
        self.assertEqual(self.code(lambda: SecretReference("../real").resolve(self.mount)),
                         "secret-reference-invalid")

    def test_a_secret_value_is_not_the_repr_of_its_holder(self):
        self.assertEqual(repr(Secret(VALUE)), "Secret(<redacted>)")


class ProviderSecretTests(DatabaseCase):
    """A provider adapter resolves its client secret at exchange time; it reaches no row, response or event."""

    def test_the_client_secret_is_read_at_exchange_and_kept_nowhere(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "login-client").write_bytes(VALUE)
            reference = SecretReference.parse("secret:login-client")
            sessions = SessionStore(self.database, audience=SETTINGS.service_id, environment=SETTINGS.environment_id)
            stream = io.StringIO()
            logger = logging.getLogger("fiat_checkpoints")
            handler = logging.StreamHandler(stream)
            logger.addHandler(handler)
            self.addCleanup(logger.removeHandler, handler)
            for expected, outcome in ((VALUE, "opened"), (b"another-value", "refused")):
                with self.subTest(outcome=outcome):
                    provider = FakeProvider(secret=(reference, Path(directory), expected))
                    begun = sessions.begin_login(T0)
                    url = provider.authorization_url(begun.state, pkce_challenge(pkce_verifier(begun.state,
                                                                                               begun.binding)))
                    state, code = provider.authorize(url, user_document(41, "a"))
                    try:
                        result = sessions.complete_login(state, begun.binding, code, provider, T0).actor.actor_id
                    except Exception as error:
                        result = getattr(error, "code", None)
                        self.assertNotIn(VALUE.decode(), repr(error))
                    self.assertEqual(result, 41 if outcome == "opened" else "auth_required")
        rows = self.query("SELECT * FROM sessions") + self.query("SELECT * FROM login_states")
        self.assertNotIn(VALUE.decode(), repr(rows) + stream.getvalue())
