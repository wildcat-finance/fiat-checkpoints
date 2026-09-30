"""Check declared pins, immutable source bytes and the public source surface."""

import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
PYTHON = (3, 14, 6)
UV = "0.12.13"
SPECIFICATION_SHA256 = "8ee755c1f9e5c29703af30bd08caffb6fad80c8a0990ee0acecebef09b02f541"
SUBSTRATE_BYTES = 3515
SUBSTRATE_SHA256 = "99a4ee46e3c58a4528ad6ef4433a39f55f8d3c8ccaefe8e5d86371ae95ee8bc0"
IMAGE = ("python:3.14.6-slim-trixie@sha256:"
         "b921fe7e7522f828d45197a47656ec465a9b15689b27fa8e1fba2864fca5b967")
PRIVATE_PARTS = {".hexaemeron", ".elenchus", ".reports", ".venv", "private", "secrets", "observations"}
PRIVATE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".bundle", ".pem", ".key", ".p12", ".pfx")
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN " + rb"(?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
    re.compile(rb"gh[pousr]_" + rb"[A-Za-z0-9]{36,}"),
    re.compile(rb"github_pat_" + rb"[A-Za-z0-9_]{30,}"),
    re.compile(rb"AKIA" + rb"[0-9A-Z]{16}"),
)
PRIVATE_PATH_PATTERN = re.compile(rb"/(?:Users|home)/[A-Za-z0-9._-]+/")


def public_path(path):
    parts = Path(path).parts
    name = Path(path).name
    return not (any(part in PRIVATE_PARTS for part in parts)
                or path.endswith(PRIVATE_SUFFIXES)
                or name == ".env" or name.startswith(".env."))


def git_index_path(root):
    marker = root / ".git"
    if marker.is_dir():
        return marker / "index"
    text = marker.read_text()
    if not text.startswith("gitdir: "):
        raise ValueError("unsupported .git file")
    return Path(text[len("gitdir: "):].strip()) / "index"


def tracked_entries(root):
    """Read path and mode for each Git index entry without starting Git."""
    raw = git_index_path(root).read_bytes()
    signature, version, count = struct.unpack(">4sLL", raw[:12])
    if signature != b"DIRC" or version not in (2, 3):
        raise ValueError("unsupported index")
    offset, entries = 12, []
    for _ in range(count):
        start = offset
        mode = struct.unpack(">L", raw[offset + 24:offset + 28])[0]
        flags = struct.unpack(">H", raw[offset + 60:offset + 62])[0]
        offset += 62
        if flags & 0x4000:
            offset += 2
        end = raw.index(b"\0", offset)
        entries.append((raw[offset:end].decode("utf-8"), mode))
        offset = start + ((end - start) // 8 + 1) * 8
    return entries


def normalized_export(raw):
    return "\n".join(line for line in raw.splitlines()
                     if line.strip() and not line.lstrip().startswith("#"))


def normalized_name(name):
    return re.sub(r"[-_.]+", "-", name.lower())


class PinsTests(unittest.TestCase):
    def test_runtime_and_declared_versions_are_pinned(self):
        self.assertEqual(sys.version_info[:3], PYTHON)
        self.assertEqual((ROOT / ".python-version").read_text(), "3.14.6\n")
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        self.assertEqual(project["project"]["requires-python"], "==3.14.6")
        self.assertEqual(project["tool"]["uv"]["required-version"], "==" + UV)
        self.assertEqual(project["project"]["dependencies"],
                         ["fastapi==0.141.1", "psycopg[binary]==3.3.6", "uvicorn==0.53.0"])

    def test_installed_distributions_match_the_lock(self):
        lock = tomllib.loads((ROOT / "uv.lock").read_text())
        # tzdata is locked for Windows only and is absent from the Linux environment.
        expected = {package["name"]: package["version"] for package in lock["package"]
                    if package["name"] not in {"fiat-checkpoints", "tzdata"}}
        installed = {normalized_name(dist.metadata["Name"]): dist.version
                     for dist in importlib.metadata.distributions()}
        self.assertEqual(installed, expected)

    def test_each_registry_artifact_has_a_sha256_and_public_origin(self):
        lock = tomllib.loads((ROOT / "uv.lock").read_text())
        self.assertEqual(lock["requires-python"], "==3.14.6")
        for package in lock["package"]:
            if package["name"] == "fiat-checkpoints":
                continue
            with self.subTest(package=package["name"]):
                self.assertEqual(package["source"], {"registry": "https://pypi.org/simple"})
                artifacts = package.get("wheels", []) + ([package["sdist"]] if "sdist" in package else [])
                self.assertTrue(artifacts)
                for artifact in artifacts:
                    self.assertRegex(artifact["hash"], r"^sha256:[0-9a-f]{64}$")
                    self.assertTrue(artifact["url"].startswith("https://files.pythonhosted.org/"))

    def test_hashed_requirement_files_pin_every_requirement(self):
        for name in ("requirements.lock", "requirements-dev.lock", "requirements-tools.lock"):
            blocks = [block for block in re.split(r"\n(?=\S)", (ROOT / name).read_text().strip())
                      if not block.startswith("#")]
            with self.subTest(lock=name):
                self.assertTrue(blocks)
                for block in blocks:
                    self.assertRegex(block, r"^[a-z0-9-]+(?:\[[a-z]+\])?==\S+")
                    self.assertRegex(block, r"--hash=sha256:[0-9a-f]{64}")
        tools = (ROOT / "requirements-tools.lock").read_text()
        self.assertTrue(tools.startswith("uv==" + UV + " \\\n"))

    def test_containers_are_exact_pinned_and_install_hashed_wheels(self):
        api = (ROOT / "containers/api.Dockerfile").read_text()
        test = (ROOT / "containers/test.Dockerfile").read_text()
        for name, text in (("api", api), ("test", test)):
            with self.subTest(image=name):
                self.assertEqual(re.findall(r"^FROM .*$", text, re.M),
                                 ["FROM --platform=linux/amd64 " + IMAGE])
                self.assertIn("--require-hashes --", text.replace("\\\n    ", ""))
                self.assertIn("--only-binary=:all:", text)
                self.assertIn("USER 65532:65532", text)
                self.assertNotIn("apt-get", text)
                self.assertNotIn(".hexaemeron", text)
        self.assertIn("uv sync --project /build/project --locked", test)
        self.assertIn("UV_PYTHON_DOWNLOADS=never", test)

    def test_ci_has_read_only_permissions_pinned_actions_and_no_credentials(self):
        raw = (ROOT / ".github/workflows/check.yml").read_text()
        self.assertNotIn("pull_request_target", raw)
        self.assertNotIn("secrets.", raw)
        workflow = yaml.safe_load(raw)
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertIn("pull_request", workflow[True])
        job = workflow["jobs"]["scaffold"]
        self.assertEqual(job["runs-on"], "ubuntu-24.04")
        steps = job["steps"]
        uses = [step["uses"] for step in steps if "uses" in step]
        self.assertTrue(uses)
        for action in uses:
            self.assertRegex(action, r"^[a-z0-9/-]+@[0-9a-f]{40}$")
        for checkout in [step for step in steps if "uses" in step]:
            self.assertEqual(checkout["with"]["persist-credentials"], False)
        skills = [step["with"] for step in steps if step.get("with", {}).get("repository") == "wildcat-finance/skills"]
        self.assertEqual(len(skills), 1)
        self.assertRegex(skills[0]["ref"], r"^[0-9a-f]{40}$")
        commands = " ".join(step["run"] for step in steps if "run" in step)
        self.assertIn("-f containers/test.Dockerfile", commands)
        self.assertIn("--network none", commands)
        self.assertIn("scripts/protocol_trees.py export", commands)
        self.assertIn("python3 scripts/check.py --group scaffold", commands)
        self.assertIn("python3 scripts/check.py --group protocol,domain", commands)
        self.assertIn("python3 scripts/check.py --group persistence,concurrency", commands)
        self.assertIn("scripts/test-postgres.sh start", commands)
        self.assertIn("--volume fiat-checkpoints-postgres-socket:/run/fiat-postgres", commands)
        self.assertIn("--env FIAT_TEST_POSTGRES=/run/fiat-postgres", commands)

    def test_postgresql_test_server_is_pinned_by_digest_and_has_no_network(self):
        script = (ROOT / "scripts/test-postgres.sh").read_text()
        self.assertEqual(re.findall(r"^IMAGE=.*$", script, re.M), [
            "IMAGE=postgres:16.15-trixie@sha256:"
            "1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54"])
        self.assertIn("--network none", script)
        self.assertIn("listen_addresses= ", script)
        self.assertIn("--auth-host=reject", script)
        environment = (ROOT / "scripts/linux-env.sh").read_text()
        self.assertIn('"$ROOT/scripts/test-postgres.sh"', environment)
        self.assertIn("--env FIAT_TEST_POSTGRES=/run/fiat-postgres", environment)


class LockToolTests(unittest.TestCase):
    spawns_child_process = True

    def run_uv(self, arguments, root=ROOT):
        return subprocess.run(["uv", *arguments, "--project", str(root), "--offline", "--no-config"],
                              cwd=root, capture_output=True, text=True, timeout=300, check=False)

    def test_uv_is_the_pinned_version(self):
        run = subprocess.run(["uv", "--version"], capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(run.returncode, 0)
        self.assertTrue(run.stdout.startswith("uv " + UV + " "), run.stdout)

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

    def test_hashed_exports_match_the_current_lock(self):
        for name, extra in (("requirements.lock", ["--no-dev"]), ("requirements-dev.lock", [])):
            with self.subTest(lock=name):
                run = self.run_uv(["export", "--locked", "--no-emit-project", "--no-header", *extra])
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(normalized_export(run.stdout), normalized_export((ROOT / name).read_text()))


class ProvenanceTests(unittest.TestCase):
    def test_specification_is_the_adopted_bytes(self):
        raw = (ROOT / "docs/specification.md").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), SPECIFICATION_SHA256)
        self.assertEqual(len(raw), 103107)

    def test_substrate_record_keeps_its_original_prefix_and_appends_a_correction(self):
        raw = (ROOT / "docs/deployment-substrate.md").read_bytes()
        self.assertEqual(hashlib.sha256(raw[:SUBSTRATE_BYTES]).hexdigest(), SUBSTRATE_SHA256)
        appended = raw[SUBSTRATE_BYTES:]
        self.assertRegex(appended, rb"\n## Correction -- 2026-09-\d\d\n")
        self.assertIn(b"specification sections 4.2, 6 and 9", appended)

    def test_source_manifest_binds_shipped_copies(self):
        manifest = json.loads((ROOT / "docs/sources.json").read_bytes())
        self.assertEqual(set(manifest), {"schema", "baseline_commit", "sources", "shipped"})
        self.assertEqual(manifest["schema"], "fiat-checkpoints-source-manifest/v1")
        self.assertRegex(manifest["baseline_commit"], r"^[0-9a-f]{40}$")
        ids = set()
        for item in manifest["sources"]:
            with self.subTest(source=item["id"]):
                self.assertNotIn(item["id"], ids)
                ids.add(item["id"])
                self.assertTrue(item["url"].startswith("https://github.com/"))
                bindings = {"sha256", "git_commit"} & set(item)
                self.assertEqual(len(bindings), 1)
                if "sha256" in item:
                    self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
                else:
                    self.assertRegex(item["git_commit"], r"^[0-9a-f]{40}$")
        specification = [item for item in manifest["sources"] if item["id"] == "adopted-specification"]
        self.assertEqual(specification[0]["sha256"], SPECIFICATION_SHA256)
        paths = [item["path"] for item in manifest["shipped"]]
        self.assertEqual(paths, ["docs/specification.md", "docs/study.md", "docs/runbook.md"])
        for item in manifest["shipped"]:
            with self.subTest(path=item["path"]):
                self.assertIn(item["source"], ids)
                raw = (ROOT / item["path"]).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), item["sha256"])

    def test_licence_and_reserved_locations_carry_no_protocol_data(self):
        licence = (ROOT / "LICENSE").read_text()
        self.assertIn("Apache License", licence)
        self.assertIn("Version 2.0, January 2004", licence)
        # Step 2 ships the released lock and tree manifest; no protocol schema is copied in.
        self.assertFalse((ROOT / "schemas").exists())
        # Step 3 ships numbered SQL migrations and nothing else there.
        for path in (ROOT / "migrations").iterdir():
            self.assertRegex(path.name, r"^\d{4}_[a-z0-9_]+\.sql$")
        package = ROOT / "src/fiat_checkpoints"
        for name in ("auth", "grants", "validation"):
            with self.subTest(module=name):
                self.assertEqual([p.name for p in (package / name).iterdir() if p.name != "__pycache__"],
                                 ["__init__.py"])
                self.assertEqual((package / name / "__init__.py").read_bytes(), b"")

    def test_readme_names_the_start_and_check_commands(self):
        readme = (ROOT / "README.md").read_text()
        for command in ("python3 scripts/serve.py --config config/local.json",
                        "scripts/linux-env.sh run python3 scripts/check.py --group scaffold",
                        "./scripts/check.sh --group scaffold"):
            self.assertIn(command, readme)


class HygieneTests(unittest.TestCase):
    def test_public_path_rule_catches_archives_observations_and_secret_files(self):
        for path in ("archive.zip", "tmp/result.bundle", "observations/run.json", ".env",
                     ".env.production", "config/private/live.json", "secrets/key.json",
                     ".hexaemeron/state.json", "keys/signer.pem", "export.tar.gz"):
            with self.subTest(path=path):
                self.assertFalse(public_path(path))
        self.assertTrue(public_path("docs/specification.md"))

    def test_index_reader_matches_a_known_path(self):
        paths = {path for path, _ in tracked_entries(ROOT)}
        self.assertIn("docs/deployment-substrate.md", paths)
        self.assertIn("scripts/check.py", paths)

    def test_tracked_files_hold_no_private_path_archive_or_credential(self):
        entries = tracked_entries(ROOT)
        self.assertTrue(entries)
        for name, mode in entries:
            with self.subTest(path=name):
                self.assertTrue(public_path(name))
                self.assertIn(mode, (0o100644, 0o100755))
                raw = (ROOT / name).read_bytes()
                self.assertFalse(raw.startswith(b"PK\x03\x04"))
                self.assertFalse(any(pattern.search(raw) for pattern in SECRET_PATTERNS))
                self.assertIsNone(PRIVATE_PATH_PATTERN.search(raw))

    def test_secret_patterns_detect_synthetic_material(self):
        samples = (b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----", b"ghp_" + b"a" * 36,
                   b"github_pat_" + b"b" * 30, b"AKIA" + b"C" * 16)
        for sample in samples:
            with self.subTest(length=len(sample)):
                self.assertTrue(any(pattern.search(sample) for pattern in SECRET_PATTERNS))
        self.assertIsNotNone(PRIVATE_PATH_PATTERN.search(b"/home/" + b"someone/checkout"))
