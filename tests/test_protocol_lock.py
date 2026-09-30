"""The shipped lock, the read-only trees and production startup without them."""

from dataclasses import replace
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest import mock

from fiat_checkpoints.api.app import StartupRefusal, create_app, production_refusals
from fiat_checkpoints.conformance import PROTOCOL_CODES, production_settings
from fiat_checkpoints.records.refusals import PROTOCOL, SERVICE, RecordRefusal
from fiat_checkpoints.records.trees import DEFAULT_TREES, load_release
from tests import authority_fixtures as fixtures


ROOT = fixtures.ROOT
# Study section 3, reproduced by the released `release` check at the authority commit.
PINS = {
    "source_commit": "685158cdc5407ca5559bf9ef4a021d664e764ece",
    "release_manifest_sha256": "fb24ac3d2e9875a11c37c2ebcdb6ef76fd3dc6a440f27bfe2c8070341dc7069c",
    "artifact_sha256": "3b67ca2c0e474f3d2cc67240a712cd806d57f1f03354726400743d770d964615",
    "schema_set_sha256": "b94bae8b24bd56c233cb10bc6b295d07985c8ad6245f26cff9b8abbc7612fe7d",
    "verifier_sha256": "de7774287ce7cb459608ddc56a68d5cb7f94ad0d5f17fc127946e2498324c149",
    "fixture_corpus_sha256": "1a259027b38040f3472cf00599aa0eb35b0c02721f47c41782223819bb175a62",
}
NATIVE = {"source_commit": "1d4e4eebcba1825d0eb3192bf08a6c509bdc0d74", "profile": "native-1d4e4eeb-openpgp-v1",
          "executable_sha256": "326817a508a2d0be382e8e44071ec1d5957411a9cb6091764d7a33e9e032ff30"}
COSIGN_LINUX_AMD64 = "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"


def lock_value():
    return json.loads((ROOT / "protocol.lock.json").read_bytes())


class ShippedLockTests(unittest.TestCase):
    def test_lock_carries_the_study_pins(self):
        lock = lock_value()
        self.assertEqual(lock["authority"], PINS)
        self.assertEqual(lock["native"], NATIVE)
        self.assertEqual(lock["tools"]["python"], "3.14.6")
        self.assertEqual(lock["tools"]["cosign"]["version"], "3.1.3")
        self.assertEqual(lock["tools"]["cosign"]["assets"]["linux-amd64"]["sha256"], COSIGN_LINUX_AMD64)

    def test_shipped_lock_passes_the_released_lock_check(self):
        release = fixtures.release()
        self.assertEqual(release.lock_check["code"], "lock-agrees")
        self.assertTrue(release.lock_check["source_commit_asserted"])
        self.assertEqual(release.lock_check["source_commit"], PINS["source_commit"])
        self.assertEqual(release.lock_check["release_manifest_sha256"], PINS["release_manifest_sha256"])
        self.assertEqual(release.lock_check["pins"], {key: PINS[key] for key in (
            "artifact_sha256", "schema_set_sha256", "verifier_sha256", "fixture_corpus_sha256")})
        self.assertEqual(release.authority_root, DEFAULT_TREES / "authority")

    def lock_refusal(self, mutate):
        lib = fixtures.library()
        lock = lock_value()
        mutate(lock)
        with self.assertRaises(lib.canonical.Refusal) as caught:
            lib.release.lock_check(json.dumps(lock).encode(), fixtures.release().authority_root,
                                   source_commit=PINS["source_commit"])
        return caught.exception.code

    def test_released_lock_check_refuses_each_substitution(self):
        cases = (
            ("mutable-source-reference", lambda lock: lock["authority"].update(source_commit="main")),
            ("source-commit-mismatch", lambda lock: lock["authority"].update(source_commit="b" * 40)),
            ("release-manifest-mismatch", lambda lock: lock["authority"].update(release_manifest_sha256="c" * 64)),
            ("mixed-components", lambda lock: lock["authority"].update(schema_set_sha256="d" * 64)),
            ("mixed-components", lambda lock: lock["authority"].update(verifier_sha256="e" * 64)),
            ("unsupported-native-pin", lambda lock: lock["native"].update(executable_sha256="f" * 64)),
            ("unsupported-python-pin", lambda lock: lock["tools"].update(python="3.12.13")),
            ("unsupported-tool-pin", lambda lock: lock["tools"]["cosign"].update(version="3.1.2")),
            ("lock-fields", lambda lock: lock.update(extra=True)),
            ("lock-fields", lambda lock: lock.update(protocol="checkpoint-authority/v2")),
        )
        for code, mutate in cases:
            with self.subTest(code=code):
                self.assertEqual(self.lock_refusal(mutate), code)


class LoaderRefusalTests(unittest.TestCase):
    """Manifest and lock refusals that happen before any tree code is imported."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        shutil.copyfile(ROOT / "protocol.lock.json", self.root / "protocol.lock.json")
        shutil.copyfile(ROOT / "protocol.trees.json", self.root / "protocol.trees.json")

    def refusal(self, trees=DEFAULT_TREES):
        with self.assertRaises(RecordRefusal) as caught:
            load_release(self.root, trees)
        self.assertEqual(caught.exception.producer, SERVICE)
        return caught.exception.code

    def test_missing_lock_and_manifest_refuse(self):
        (self.root / "protocol.trees.json").unlink()
        self.assertEqual(self.refusal(), "protocol-trees-missing")
        (self.root / "protocol.lock.json").unlink()
        self.assertEqual(self.refusal(), "protocol-pin-missing")

    def test_linked_or_special_lock_refuses(self):
        (self.root / "protocol.lock.json").unlink()
        (self.root / "protocol.lock.json").symlink_to(ROOT / "protocol.lock.json")
        self.assertEqual(self.refusal(), "protocol-file-unsafe")
        (self.root / "protocol.lock.json").unlink()
        os.link(self.root / "protocol.trees.json", self.root / "protocol.lock.json")
        self.assertEqual(self.refusal(), "protocol-file-unsafe")

    def test_malformed_lock_refuses(self):
        for raw in (b"not json", b'{"authority": {}}', b'{"a": 1, "a": 2}', b"[]", b"\xff"):
            with self.subTest(raw=raw):
                (self.root / "protocol.lock.json").write_bytes(raw)
                self.assertEqual(self.refusal(), "protocol-lock-malformed")

    def test_malformed_tree_manifest_refuses(self):
        original = json.loads((ROOT / "protocol.trees.json").read_bytes())
        rows = original["authority"]["files"]
        mutations = (
            lambda value: value.update(extra=1),
            lambda value: value.update(schema="fiat-checkpoints-protocol-trees/v2"),
            lambda value: value["authority"].update(source_commit="main"),
            lambda value: value["native"].update(files=0),
            lambda value: value["native"].update(profile_sha256="A" * 64),
            lambda value: value["authority"].update(files=[{"path": "../escape", "sha256": "0" * 64}, *rows]),
            lambda value: value["authority"].update(files=[{"path": "/absolute", "sha256": "0" * 64}, *rows]),
            lambda value: value["authority"].update(files=list(reversed(rows))),
            lambda value: value["authority"].update(files=[rows[0], *rows]),
            lambda value: value["authority"]["files"][0].update(size=1),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                value = json.loads(json.dumps(original))
                mutate(value)
                (self.root / "protocol.trees.json").write_text(json.dumps(value))
                self.assertEqual(self.refusal(), "protocol-trees-malformed")
        (self.root / "protocol.trees.json").write_bytes(b'{"schema": 1.5}')
        self.assertEqual(self.refusal(), "protocol-trees-malformed")

    def test_manifest_and_lock_must_name_the_same_commits(self):
        for section in ("authority", "native"):
            with self.subTest(section=section):
                value = json.loads((ROOT / "protocol.trees.json").read_bytes())
                value[section]["source_commit"] = "9" * 40
                (self.root / "protocol.trees.json").write_text(json.dumps(value))
                self.assertEqual(self.refusal(), "protocol-tree-commit")

    def test_absent_or_relative_trees_refuse(self):
        self.assertEqual(self.refusal(self.root / "absent"), "protocol-tree-missing")
        self.assertEqual(self.refusal(Path("relative/trees")), "protocol-tree-relocated")


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.settings = production_settings()

    def test_shipped_lock_leaves_only_the_non_protocol_blockers(self):
        codes = production_refusals(self.settings, ROOT, DEFAULT_TREES)
        self.assertEqual(codes, ("isolation-unavailable", "scaffold-only"))
        with self.assertRaises(StartupRefusal):
            create_app(self.settings, ROOT, DEFAULT_TREES)

    def test_startup_refuses_without_the_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            codes = production_refusals(self.settings, Path(temporary), DEFAULT_TREES)
        self.assertEqual(codes, ("protocol-pin-missing", "isolation-unavailable", "scaffold-only"))
        undeclared = replace(self.settings, protocol_lock=None)
        self.assertIn("protocol-pin-missing", production_refusals(undeclared, ROOT, DEFAULT_TREES))

    def test_startup_refuses_a_substituted_lock_by_the_released_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copyfile(ROOT / "protocol.trees.json", root / "protocol.trees.json")
            lock = lock_value()
            lock["authority"]["verifier_sha256"] = "e" * 64
            (root / "protocol.lock.json").write_text(json.dumps(lock))
            with self.assertRaises(RecordRefusal) as caught:
                load_release(root, DEFAULT_TREES)
            codes = production_refusals(self.settings, root, DEFAULT_TREES)
        self.assertEqual((caught.exception.code, caught.exception.producer, caught.exception.protocol_code,
                          caught.exception.stage),
                         ("protocol-lock-refused", PROTOCOL, "mixed-components", "release"))
        self.assertEqual(codes[0], "protocol-lock-refused")

    def test_interpreter_other_than_the_lock_refuses(self):
        with mock.patch("fiat_checkpoints.records.trees.platform.python_version", return_value="3.14.5"):
            with self.assertRaises(RecordRefusal) as caught:
                load_release(ROOT, DEFAULT_TREES)
        self.assertEqual(caught.exception.code, "protocol-python-mismatch")

    def test_every_startup_code_is_a_declared_protocol_code(self):
        self.assertIn("protocol-pin-missing", PROTOCOL_CODES)
        source = (ROOT / "src/fiat_checkpoints/records/trees.py").read_text()
        emitted = set(re.findall(r'"(protocol-[a-z-]+)"', source))
        self.assertEqual(emitted, set(PROTOCOL_CODES))


class TreeCustodyTests(unittest.TestCase):
    """Each substitution in a copied tree refuses before the service trusts it."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.trees = fixtures.writable_copy(self.base / "trees")
        self.addCleanup(fixtures.make_writable, self.trees)
        self.authority = self.trees / "authority"
        self.native = self.trees / "native"

    def refusal(self, trees=None):
        fixtures.make_read_only(self.trees)
        with self.assertRaises(RecordRefusal) as caught:
            load_release(ROOT, trees or self.trees)
        return caught.exception

    def test_read_only_copy_loads(self):
        fixtures.make_read_only(self.trees)
        release = load_release(ROOT, self.trees)
        self.assertEqual(release.lock_check["code"], "lock-agrees")

    def test_writable_tree_refuses(self):
        with self.assertRaises(RecordRefusal) as caught:
            load_release(ROOT, self.trees)
        self.assertEqual(caught.exception.code, "protocol-tree-writable")

    def test_relocated_tree_refuses(self):
        link = self.base / "linked"
        link.symlink_to(self.trees, target_is_directory=True)
        self.assertEqual(self.refusal(link).code, "protocol-tree-relocated")

    def test_planted_module_refuses_before_import(self):
        planted = self.authority / fixtures.RELEASED.replace("checkpoint-authority/", "scripts/checkpoint_authority/")
        (planted / "planted.py").write_text("raise SystemExit(9)\n")
        self.assertEqual(self.refusal().code, "protocol-tree-extra")

    def test_changed_authority_file_refuses(self):
        path = self.authority / "plugins/hexaemeron/skills/fiat/scripts/checkpoint_authority/trust.py"
        path.write_bytes(path.read_bytes() + b"\n")
        self.assertEqual(self.refusal().code, "protocol-tree-drift")

    def test_missing_authority_file_refuses(self):
        (self.authority / ".python-version").unlink()
        self.assertEqual(self.refusal().code, "protocol-tree-missing")

    def test_symlink_or_hard_link_inside_a_tree_refuses(self):
        path = self.authority / "plugins/hexaemeron/skills/fiat/scripts/checkpoint_authority/wire.py"
        saved = self.base / "wire.py"
        path.rename(saved)
        path.symlink_to(saved)
        self.assertEqual(self.refusal().code, "protocol-tree-unsafe")
        fixtures.make_writable(self.trees)
        path.unlink()
        os.link(saved, path)
        self.assertEqual(self.refusal().code, "protocol-file-unsafe")

    def test_changed_or_extra_native_file_refuses_after_the_lock_check(self):
        profile = json.loads((DEFAULT_TREES / "authority" / fixtures.RELEASED / "native-profile.json").read_bytes())
        path = self.native / profile["files"][0]["path"]
        path.write_bytes(path.read_bytes() + b"#")
        self.assertEqual(self.refusal().code, "protocol-tree-drift")
        fixtures.make_writable(self.trees)
        path.write_bytes((DEFAULT_TREES / "native" / profile["files"][0]["path"]).read_bytes())
        (self.native / "sitecustomize.py").write_text("")
        self.assertEqual(self.refusal().code, "protocol-tree-extra")


class ImageTreeTests(unittest.TestCase):
    def test_image_build_copies_and_checks_the_trees(self):
        text = (ROOT / "containers/test.Dockerfile").read_text()
        for line in ("COPY .protocol-trees/authority /opt/fiat-checkpoints/protocol/authority",
                     "COPY .protocol-trees/native /opt/fiat-checkpoints/protocol/native",
                     "RUN chmod -R a-w /opt/fiat-checkpoints/protocol",
                     "load_release('/build/check', '/opt/fiat-checkpoints/protocol')"):
            self.assertIn(line, text)
        self.assertLess(text.index("USER 65532:65532"), text.index("load_release("))

    def test_image_trees_are_read_only_to_the_service_user(self):
        for directory, names, files in os.walk(DEFAULT_TREES):
            self.assertFalse(os.access(directory, os.W_OK))
            for name in files:
                self.assertFalse(os.access(Path(directory) / name, os.W_OK))

    def test_image_trees_hold_exactly_the_manifest_and_profile_files(self):
        manifest = json.loads((ROOT / "protocol.trees.json").read_bytes())
        authority = {str(path.relative_to(DEFAULT_TREES / "authority"))
                     for path in (DEFAULT_TREES / "authority").rglob("*") if path.is_file()}
        self.assertEqual(authority, {row["path"] for row in manifest["authority"]["files"]})
        native = [path for path in (DEFAULT_TREES / "native").rglob("*") if path.is_file()]
        self.assertEqual(len(native), manifest["native"]["files"])


if __name__ == "__main__":
    unittest.main()
