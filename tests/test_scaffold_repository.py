"""Check declared pins, immutable source bytes and the public source surface."""

import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPECIFICATION_SHA256 = "8ee755c1f9e5c29703af30bd08caffb6fad80c8a0990ee0acecebef09b02f541"
SUBSTRATE_SHA256 = "99a4ee46e3c58a4528ad6ef4433a39f55f8d3c8ccaefe8e5d86371ae95ee8bc0"
IMAGE = "python:3.12.13-slim-bookworm@sha256:6e13e65c55e33adf203d77ee371cf8bf5d81bd4902ef07565721f46bf44917af"


def public_path(path):
    parts = Path(path).parts
    return not any(part in {".hexaemeron", ".elenchus", ".venv", "private", "secrets", "observations"} for part in parts) and not (
        path.endswith((".zip", ".tar", ".tar.gz", ".bundle", ".pem", ".key", ".p12", ".pfx"))
        or Path(path).name == ".env" or Path(path).name.startswith(".env.")
    )


def normalized_export(raw):
    return "\n".join(line for line in raw.splitlines() if line.strip() and not line.lstrip().startswith("#"))


class PinsTests(unittest.TestCase):
    def run_uv(self, arguments, root=ROOT):
        return subprocess.run(["uv", *arguments, "--project", str(root), "--offline"],
                              cwd=root, capture_output=True, text=True, timeout=30, check=False)

    def test_runtime_and_installed_dependencies_match_the_lock(self):
        self.assertEqual(sys.version_info[:3], (3, 12, 13))
        self.assertEqual((ROOT / ".python-version").read_text().strip(), "3.12.13")
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        self.assertEqual(project["project"]["requires-python"], "==3.12.13")
        self.assertEqual(project["tool"]["uv"]["required-version"], "==0.12.13")
        lock = tomllib.loads((ROOT / "uv.lock").read_text())
        expected = {package["name"]: package["version"] for package in lock["package"]
                    if package["name"] not in {"fiat-checkpoints", "tzdata"}}
        installed = {re.sub(r"[-_.]+", "-", dist.metadata["Name"].lower()): dist.version
                     for dist in importlib.metadata.distributions()}
        self.assertEqual(installed, expected)

    def test_each_registry_artifact_has_a_sha256_and_public_origin(self):
        lock = tomllib.loads((ROOT / "uv.lock").read_text())
        for package in lock["package"]:
            if package["name"] == "fiat-checkpoints":
                continue
            self.assertEqual(package["source"], {"registry": "https://pypi.org/simple"})
            artifacts = package.get("wheels", []) + ([package["sdist"]] if "sdist" in package else [])
            self.assertTrue(artifacts, package["name"])
            for artifact in artifacts:
                self.assertRegex(artifact["hash"], r"^sha256:[0-9a-f]{64}$")
                self.assertTrue(artifact["url"].startswith("https://files.pythonhosted.org/"))

    def test_lock_is_current_and_rejects_direct_dependency_drift(self):
        valid = self.run_uv(["lock", "--check"])
        self.assertEqual(valid.returncode, 0, valid.stderr)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("pyproject.toml", "uv.lock", ".python-version"):
                shutil.copyfile(ROOT / name, root / name)
            project = root / "pyproject.toml"
            project.write_text(project.read_text().replace("fastapi==0.141.1", "fastapi==0.141.0"))
            drift = self.run_uv(["lock", "--check"], root)
            self.assertNotEqual(drift.returncode, 0)

    def test_both_hashed_exports_match_the_current_lock(self):
        for name, extra in (("requirements.lock", ["--no-dev"]), ("requirements-dev.lock", [])):
            with self.subTest(lock=name):
                run = self.run_uv(["export", "--locked", "--no-emit-project", "--no-header", *extra])
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(normalized_export(run.stdout), normalized_export((ROOT / name).read_text()))

    def test_container_is_exact_pinned_nonroot_and_installs_hashed_wheels(self):
        dockerfile = (ROOT / "containers/api.Dockerfile").read_text()
        self.assertIn("FROM --platform=linux/amd64 " + IMAGE + "\n", dockerfile)
        self.assertIn("--require-hashes --only-binary=:all:", dockerfile)
        self.assertIn("USER 65532:65532", dockerfile)
        self.assertNotIn("apt-get", dockerfile)
        self.assertNotIn(".hexaemeron", dockerfile)

    def test_ci_has_read_only_permissions_pinned_actions_and_no_release_credentials(self):
        workflow = (ROOT / ".github/workflows/check.yml").read_text()
        self.assertIn("pull_request:", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("secrets.", workflow)
        for action in re.findall(r"uses: (\S+)", workflow):
            self.assertRegex(action, r"^[a-z0-9/-]+@[0-9a-f]{40}$")
        self.assertIn("./scripts/check.sh --group scaffold", workflow)


class ProvenanceTests(unittest.TestCase):
    def test_specification_and_historical_substrate_are_unchanged(self):
        self.assertEqual(hashlib.sha256((ROOT / "docs/specification.md").read_bytes()).hexdigest(), SPECIFICATION_SHA256)
        substrate = (ROOT / "docs/deployment-substrate.md").read_bytes()
        self.assertEqual(hashlib.sha256(substrate[:3515]).hexdigest(), SUBSTRATE_SHA256)
        self.assertIn(b"2026-09-18", substrate[3515:])

    def test_public_source_manifest_binds_shipped_files(self):
        manifest = json.loads((ROOT / "docs/sources.json").read_bytes())
        self.assertEqual(manifest["schema"], "fiat-checkpoints-source-manifest/v1")
        for item in manifest["shipped"]:
            raw = (ROOT / item["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), item["sha256"])
        for item in manifest["sources"]:
            self.assertTrue(item["url"].startswith("https://github.com/"))
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
        raw = (ROOT / "docs/sources.json").read_text()
        self.assertNotIn("/home/", raw)
        self.assertNotIn(".hexaemeron", raw)

    def test_licence_and_empty_protocol_locations(self):
        licence = (ROOT / "LICENSE").read_text()
        self.assertIn("Apache License", licence)
        self.assertIn("Version 2.0, January 2004", licence)
        self.assertFalse((ROOT / "protocol.lock.json").exists())
        self.assertEqual([p.name for p in (ROOT / "schemas").iterdir()], [".gitkeep"])
        self.assertEqual([p.name for p in (ROOT / "migrations").iterdir()], [".gitkeep"])

    def test_public_path_rule_catches_archives_observations_and_secret_files(self):
        for path in ("archive.zip", "tmp/result.bundle", "observations/run.json", ".env", "config/private/live.json", "secrets/key.json", ".hexaemeron/state.json"):
            self.assertFalse(public_path(path), path)
        self.assertTrue(public_path("docs/specification.md"))

    def test_git_candidates_contain_no_private_paths_or_secret_material(self):
        result = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                                cwd=ROOT, capture_output=True, timeout=10, check=True)
        paths = {name.decode() for name in result.stdout.split(b"\0") if name}
        self.assertTrue(paths)
        secret_patterns = [re.compile(rb"-----BEGIN " + rb"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
                           re.compile(rb"gh[pousr]_" + rb"[A-Za-z0-9]{36,}"),
                           re.compile(rb"github_pat_" + rb"[A-Za-z0-9_]{30,}")]
        for name in sorted(paths):
            self.assertTrue(public_path(name), name)
            path = ROOT / name
            self.assertFalse(path.is_symlink(), name)
            raw = path.read_bytes()
            self.assertFalse(raw.startswith(b"PK\x03\x04"), name)
            self.assertFalse(any(pattern.search(raw) for pattern in secret_patterns), name)
