"""Synthetic authority records signed with keys generated for each test run.

Keys live only in ignored temporary directories and are signed with the image's
pinned OpenSSL. The released public fixtures are read from the verified
authority tree and named by the digests the release manifest binds.
"""

import base64
import functools
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

from fiat_checkpoints.records.authority import OPENSSL_PATH, AuthorityRecords, ServiceScope, tool_pins
from fiat_checkpoints.records.trees import DEFAULT_TREES, REPOSITORY, load_release


ROOT = REPOSITORY
RELEASED = "plugins/hexaemeron/skills/fiat/checkpoint-authority/"
SCOPE = ServiceScope("test", "fiat-checkpoints-test", 7, "fiat-" + "a" * 64)
IDENTITIES = {"snapshot_id": "1" * 64, "controller_manifest_sha256": "2" * 64, "outer_sha256": "3" * 64}


@functools.cache
def release():
    """The shipped lock over the image's read-only trees, verified once per process."""
    return load_release(ROOT, DEFAULT_TREES)


def library():
    return release().library


def released_bytes(name):
    """A released fixture by its path in the verified tree, checked against the release digest."""
    path = RELEASED + name
    data = (release().authority_root / path).read_bytes()
    manifest = json.loads((release().authority_root / RELEASED / "release-manifest.json").read_bytes())
    expected = {row["path"]: row["sha256"] for row in manifest["transitive_files"]}
    if hashlib.sha256(data).hexdigest() != expected[path]:
        raise AssertionError("released fixture digest")
    return data


def time(offset):
    return "2026-09-30T00:%02d:%02dZ" % divmod(offset, 60)


class Signer:
    """One P-256 key pair in a private temporary directory."""

    def __init__(self):
        self.directory = tempfile.TemporaryDirectory(prefix="fiat-checkpoints-key-")
        self.path = Path(self.directory.name)
        self._openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "key.pem")
        self.spki = self._openssl("pkey", "-in", "key.pem", "-pubout", "-outform", "DER")
        public = base64.b64encode(self.spki).decode()
        self.key = {"format": "spki-p256", "algorithm": "ecdsa-p256-sha256", "public": public,
                    "fingerprint": hashlib.sha256(self.spki).hexdigest()}

    def _openssl(self, *arguments, message=None):
        run = subprocess.run([OPENSSL_PATH, *arguments], cwd=self.path, input=message,
                             capture_output=True, timeout=60, check=True,
                             env={"PATH": "/usr/bin:/bin", "OPENSSL_CONF": "/dev/null"})
        return run.stdout

    def sign(self, message):
        return self._openssl("dgst", "-sha256", "-sign", "key.pem", message=message)

    def close(self):
        self.directory.cleanup()


def common(kind, sequence, previous, issued, issuer, scope=SCOPE):
    return {"protocol": "checkpoint-authority/v1", "environment": scope.environment,
            "service": scope.service, "scope": {"repository_id": scope.repository_id, "run_id": scope.run_id},
            "type": kind, "sequence": sequence, "previous": previous, "issued_at": time(issued),
            "issuer": issuer}


def statement(record):
    """The in-toto statement the protocol signs, built without validating the record.

    For a valid record these are the bytes `signatures.statement_bytes` returns;
    an invalid one still gets a correctly signed carrier, so the library's own
    record check is what refuses it.
    """
    lib = library()
    return {"_type": lib.schema.STATEMENT, "subject": lib.signatures.subjects(record),
            "predicateType": lib.schema.PREDICATE, "predicate": record}


def envelope(record, signer, *, statement=None):
    """Sign the exact statement bytes; `statement` substitutes a whole statement."""
    lib = library()
    payload = lib.canonical.canonical(globals()["statement"](record) if statement is None else statement)
    return lib.signatures.envelope_bytes(payload, signer.sign(lib.signatures.pae(payload)))


def ref(kind, data):
    return {"type": kind, "sha256": hashlib.sha256(data).hexdigest()}


def root_bytes(signer, environment="test"):
    return library().canonical.canonical({"environment": environment, "key": signer.key})


class Chain:
    """A policy, enrollment challenge, key enrollment and run grant, in journal order."""

    def __init__(self, operator, contributor, *, scope=SCOPE, actor=41):
        self.operator, self.contributor, self.scope, self.actor = operator, contributor, scope, actor
        self.records, self.envelopes = [], []
        lib = library()
        lock = release().lock_check
        policy = common("authority-policy", 1, None, 0, operator.key["fingerprint"], scope) | {
            "authorities": [{"key": operator.key, "roles": ["policy", "operator"],
                             "not_before": time(0), "not_after": "2027-01-01T00:00:00Z"}],
            "allowed_protocols": ["checkpoint-authority/v1"], "signature_profile": "dsse-p256-sha256-der/v1",
            "native": {key: lock["native"][key] for key in ("source_commit", "executable_sha256", "profile")},
            "release": {"source_commit": lock["source_commit"], **{key: lock["pins"][key] for key in (
                "artifact_sha256", "schema_set_sha256", "verifier_sha256", "fixture_corpus_sha256")}},
            "storage_policy_sha256": "4" * 64,
            "locations": [{"role": "primary", "location_id": "primary-eu", "account_id": "account-a", "jurisdiction": "EU"},
                          {"role": "recovery", "location_id": "recovery-eu", "account_id": "account-b", "jurisdiction": "EU"}],
            "max_head_age_seconds": 60}
        self.add(policy, operator)
        self.policy = ref("authority-policy", self.envelopes[0])
        challenge = self.next("enrollment-challenge", 10) | {
            "policy": self.policy, "actor_id": actor, "key": contributor.key, "nonce": "nonce-1",
            "expires_at": time(200)}
        self.add(challenge, operator)
        proof = contributor.sign(lib.trust.proof_message(challenge))
        enrollment = self.next("key-enrollment", 20) | {
            "policy": self.policy, "actor_id": actor, "key": contributor.key,
            "proof": {"challenge": ref("enrollment-challenge", self.envelopes[1]),
                      "signature": base64.b64encode(proof).decode()},
            "not_before": time(20), "not_after": "2026-12-31T00:00:00Z"}
        self.add(enrollment, operator)
        self.enrollment = ref("key-enrollment", self.envelopes[2])
        grant = self.next("run-grant", 30) | {
            "policy": self.policy, "actor_id": actor, "enrollment": self.enrollment,
            "permissions": ["announce", "upload"], "not_before": time(30), "not_after": "2026-12-31T00:00:00Z"}
        self.add(grant, operator)
        self.grant = ref("run-grant", self.envelopes[3])

    def next(self, kind, issued):
        previous = {"type": self.records[-1]["type"], "sha256": hashlib.sha256(self.envelopes[-1]).hexdigest()}
        return common(kind, len(self.records) + 1, previous, issued, self.operator.key["fingerprint"], self.scope)

    def add(self, record, signer):
        self.records.append(record)
        self.envelopes.append(envelope(record, signer))

    def endorsement(self, **changes):
        record = common("upload-endorsement", 1, None, 40, self.contributor.key["fingerprint"], self.scope) | {
            "policy": self.policy, "actor_id": self.actor, "enrollment": self.enrollment,
            "grant": self.grant, "candidate_id": "candidate-1", "nonce": "endorse-1",
            "expires_at": time(100), "identities": dict(IDENTITIES), "carrier_length": 4096,
            "parent": {"type": "parent-link", "sha256": "5" * 64}}
        return record | changes


def records(roots, scope=SCOPE):
    return AuthorityRecords(release(), scope, tuple(roots), tool_pins(release()))


def writable_copy(target):
    """Copy the image trees into `target` with write bits, ready for one substitution."""
    shutil.copytree(DEFAULT_TREES, target, symlinks=True)
    make_writable(target)
    return target


def make_writable(root):
    for directory, names, files in os.walk(root):
        os.chmod(directory, 0o755)
        for name in files:
            path = Path(directory) / name
            if not path.is_symlink():
                os.chmod(path, 0o644)


def make_read_only(root):
    for directory, names, files in os.walk(root, topdown=False):
        for name in files:
            path = Path(directory) / name
            if not path.is_symlink():
                os.chmod(path, stat.S_IMODE(path.stat().st_mode) & ~0o222)
        os.chmod(directory, 0o555)
