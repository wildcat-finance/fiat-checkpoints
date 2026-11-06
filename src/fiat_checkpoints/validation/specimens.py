"""The 35 released hostile fixture ids, rebuilt from the released valid archive.

The release lists each id with its asserted refusal class and the native stage
that produces it (`native-capabilities.json`). The released corpus ships the
valid two-step archive itself, not the hostile specimens, so each one is
rebuilt here by mutating exactly the bytes its id names, as the native tests
at the pinned source commit do, with a ZIP writer independent of `hexctl.py`.
Two ids are not archive bytes at all: `wrong-outer-digest` is a wrong digest
operand and `tampered-sidecar` is a sidecar file beside the archive, so a
specimen also carries the digest and sidecar its inspect call uses.
"""

from dataclasses import dataclass
import hashlib
import json
import struct
import zipfile
import io
import zlib


FIXTURE = "plugins/hexaemeron/skills/fiat/checkpoint-authority/native-fixture/"
CAPABILITIES = "plugins/hexaemeron/skills/fiat/checkpoint-authority/native-capabilities.json"
README = "README.txt"
MANIFEST = "checkpoint.json"
BUNDLE = "git/repository.bundle"


@dataclass(frozen=True)
class Specimen:
    fixture_id: str
    archive: bytes
    inspect_sha256: str
    sidecar: str | None
    asserted_refusal: str
    native_stage: str

    @property
    def archive_sha256(self):
        return hashlib.sha256(self.archive).hexdigest()

    def __repr__(self):
        return "Specimen(%s)" % self.fixture_id


def canonical_line(value):
    """`hexctl.py`'s canonical JSON plus one LF, written independently."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def _local(name, data, method=0, flags=0, extra=b""):
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, flags, method, 0, 33, crc, len(data), len(data),
                       len(name), len(extra)) + name + extra + data


def _central(name, data, offset, method=0, flags=0, extra=b"", mode=0o100644, declared_size=None):
    size = len(data) if declared_size is None else declared_size
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", (3 << 8) | 20, 20, flags, method, 0, 33, crc,
                       size, size, len(name), len(extra), 0, 0, 0, mode << 16, offset) + name + extra


def write_zip(entries):
    """Stored entries in the given order, no comment, no ZIP64 record."""
    body, offsets = bytearray(), []
    for entry in entries:
        offsets.append(len(body))
        body += _local(entry["name"], entry["data"], entry.get("method", 0), entry.get("flags", 0),
                       entry.get("extra", b""))
    start = len(body)
    for entry, offset in zip(entries, offsets):
        body += _central(entry["name"], entry["data"], offset, entry.get("method", 0), entry.get("flags", 0),
                         entry.get("extra", b""), entry.get("mode", 0o100644), entry.get("declared_size"))
    body += struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, len(entries), len(entries), len(body) - start,
                        start, 0)
    return bytes(body)


def _pack(members, overrides=None):
    overrides = overrides or {}
    entries = []
    for name in sorted(members, key=lambda item: item.encode("utf-8")):
        entry = {"name": name.encode("utf-8"), "data": members[name]}
        entry.update(overrides.get(name, {}))
        entries.append(entry)
    return write_zip(entries)


def _flip(value):
    return ("0" if value[0] != "0" else "1") + value[1:]


def _retarget(members, manifest, path, data):
    members[path] = data
    for entry in manifest["archive"]["entries"]:
        if entry["path"] == path:
            entry["bytes"], entry["sha256"] = len(data), hashlib.sha256(data).hexdigest()
            if path == BUNDLE:
                manifest["bundle"]["bytes"], manifest["bundle"]["sha256"] = entry["bytes"], entry["sha256"]
            return
    raise KeyError(path)


class Corpus:
    """Builders over one released valid archive; each call returns fresh bytes."""

    def __init__(self, archive, capabilities):
        self.archive = archive
        self.capabilities = capabilities
        with zipfile.ZipFile(io.BytesIO(archive)) as container:
            self._members = {info.filename: container.read(info.filename) for info in container.infolist()}

    @classmethod
    def released(cls, release):
        """Read the archive and the fixture table from the verified authority tree."""
        library = release.library
        root = release.authority_root
        archive = library.native_io.read(root / FIXTURE / "checkpoint.zip", 1_073_741_824)
        fixture = json.loads(library.native_io.read(root / FIXTURE / "fixture.json"))
        if hashlib.sha256(archive).hexdigest() != fixture["outer_sha256"]:
            raise ValueError("released-fixture-drift")
        capabilities = library.canonical.decode(library.native_io.read(root / CAPABILITIES, 1_048_576))
        return cls(archive, capabilities)

    def members(self):
        return dict(self._members)

    def manifest(self, members):
        return json.loads(members[MANIFEST])

    def declared(self):
        """The released table: id -> (asserted refusal, native stage)."""
        return {row["id"]: (row["asserted_refusal"], row["native_stage"]) for row in self.capabilities["fixtures"]}

    def ids(self):
        return sorted(self.declared())

    def build(self, fixture_id):
        declared = self.declared()
        if fixture_id not in declared or fixture_id not in BUILDERS:
            raise KeyError(fixture_id)
        built = BUILDERS[fixture_id](self)
        archive, sha256, sidecar = built if type(built) is tuple else (built, None, None)
        sha256 = hashlib.sha256(archive).hexdigest() if sha256 is None else sha256
        refusal, stage = declared[fixture_id]
        return Specimen(fixture_id, archive, sha256, sidecar, refusal, stage)


def _rename(new_name):
    def build(corpus):
        members = corpus.members()
        members[new_name] = members.pop(README)
        return _pack(members)
    return build


def _override(name, **values):
    def build(corpus):
        return _pack(corpus.members(), {name: values})
    return build


def _duplicate(corpus):
    members = corpus.members()
    entries = []
    for name in sorted(members, key=lambda item: item.encode("utf-8")):
        entries.append({"name": name.encode("utf-8"), "data": members[name]})
        if name == README:
            entries.append({"name": name.encode("utf-8"), "data": members[name]})
    return write_zip(entries)


def _case_fold(corpus):
    members = corpus.members()
    members["readme.TXT"] = members[README]
    return _pack(members)


def _non_utf8(corpus):
    members = corpus.members()
    entries = [{"name": name.encode("utf-8"), "data": members[name]}
               for name in sorted(members, key=lambda item: item.encode("utf-8"))]
    entries.append({"name": b"\xff\xfe-evil.txt", "data": b"hostile"})
    entries.sort(key=lambda entry: entry["name"])
    return write_zip(entries)


def _entry_count(corpus):
    data = bytearray(_pack(corpus.members()))
    end = len(data) - 22
    struct.pack_into("<H", data, end + 8, 4201)
    struct.pack_into("<H", data, end + 10, 4201)
    return bytes(data)


def _trailing(corpus):
    return _pack(corpus.members()) + b"\x00" * 8


def _grow_readme(corpus):
    members = corpus.members()
    members[README] = members[README] + b"hostile appended bytes\n"
    return _pack(members)


def _flip_byte(path):
    def build(corpus):
        members = corpus.members()
        data = bytearray(members[path])
        data[-2] ^= 0xFF
        members[path] = bytes(data)
        return _pack(members)
    return build


def _unmanifested(corpus):
    members = corpus.members()
    members["controller-capsule/controller/hostile-extra.txt"] = b"extra\n"
    return _pack(members)


def _missing_member(corpus):
    members = corpus.members()
    del members[README]
    return _pack(members)


def _wrong_digest(corpus):
    return corpus.archive, _flip(hashlib.sha256(corpus.archive).hexdigest()), None


def _sidecar(corpus):
    real = hashlib.sha256(corpus.archive).hexdigest()
    return corpus.archive, real, "%s  specimen.zip\n" % _flip(real)


def _missing_object(corpus):
    members = corpus.members()
    manifest = corpus.manifest(members)
    bundle = members[BUNDLE]
    end = bundle.index(b"\n\n") + 2
    _retarget(members, manifest, BUNDLE, bundle[:end + 64])
    members[MANIFEST] = canonical_line(manifest)
    return _pack(members)


def _ref_map(corpus):
    members = corpus.members()
    manifest = corpus.manifest(members)
    refs = dict(manifest["refs"])
    first = sorted(refs)[0]
    refs[first] = _flip(refs[first])
    manifest["refs"] = refs
    members[MANIFEST] = canonical_line(manifest)
    return _pack(members)


def _signature_proof(corpus):
    members = corpus.members()
    manifest = corpus.manifest(members)
    proof = json.loads(members["proof/signatures.json"])
    bogus = _flip(proof["signer"]["fingerprints"][0])
    proof["signer"]["fingerprints"] = [bogus]
    data = canonical_line(proof)
    _retarget(members, manifest, "proof/signatures.json", data)
    manifest["proof"]["sha256"] = hashlib.sha256(data).hexdigest()
    manifest["signer"]["fingerprints"] = [bogus]
    members[MANIFEST] = canonical_line(manifest)
    return _pack(members)


def _identity(corpus):
    members = corpus.members()
    manifest = corpus.manifest(members)
    target = "identity/checkpoint-identity.json"
    payload = json.loads(members[target])
    payload["snapshot_id"] = _flip(payload["snapshot_id"])
    _retarget(members, manifest, target, canonical_line(payload))
    members[MANIFEST] = canonical_line(manifest)
    return _pack(members)


def _schema(corpus):
    members = corpus.members()
    manifest = corpus.manifest(members)
    manifest["schema"] = "fiat-checkpoint-archive/v0"
    members[MANIFEST] = canonical_line(manifest)
    return _pack(members)


def _absolute_source(corpus):
    members = corpus.members()
    manifest = corpus.manifest(members)
    entries = manifest["archive"]["entries"]
    entries[0]["path"] = "/etc/passwd"
    entries.sort(key=lambda item: item["path"].encode("utf-8"))
    members[MANIFEST] = canonical_line(manifest)
    return _pack(members)


def _acceptance(corpus):
    members = corpus.members()
    manifest = corpus.manifest(members)
    payload = b"{}\n"
    members["acceptance/current"] = payload
    manifest["archive"]["entries"].append({"path": "acceptance/current", "bytes": len(payload),
                                           "sha256": hashlib.sha256(payload).hexdigest()})
    manifest["archive"]["entries"].sort(key=lambda item: item["path"].encode("utf-8"))
    members[MANIFEST] = canonical_line(manifest)
    return _pack(members)


def _secret(corpus):
    members = corpus.members()
    manifest = corpus.manifest(members)
    # A synthetic token shape; it is not, and never was, a credential.
    _retarget(members, manifest, README, members[README] + b"\nghp_" + b"A" * 36 + b"\n")
    members[MANIFEST] = canonical_line(manifest)
    return _pack(members)


BUILDERS = {
    "traversal-dotdot": _rename("controller-capsule/../evil.txt"),
    "absolute-path": _rename("/evil.txt"),
    "backslash-separator": _rename("controller-capsule\\evil.txt"),
    "drive-letter": _rename("C:/evil.txt"),
    "duplicate-name": _duplicate,
    "case-fold-collision": _case_fold,
    "non-utf8-name": _non_utf8,
    "control-character-name": _rename("evil\x01name.txt"),
    "nfc-mismatch-name": _rename("e\u0301vil.txt"),
    "directory-entry": _override(README, mode=0o040755),
    "symlink-entry": _override(README, mode=0o120777),
    "special-mode-entry": _override(README, mode=0o020666),
    "setuid-or-executable-mode": _override(README, mode=0o104755),
    "compressed-entry": _override(README, method=8),
    "encrypted-entry": _override(README, flags=0x1),
    "zip64-record": _override(README, extra=struct.pack("<HH", 0x0001, 0)),
    "entry-count-over-limit": _entry_count,
    "expanded-size-over-limit": _override(README, declared_size=65 * 1024 * 1024),
    "bundle-over-limit": _override(BUNDLE, declared_size=1025 * 1024 * 1024),
    "trailing-data": _trailing,
    "size-mismatch": _grow_readme,
    "tampered-manifest": _flip_byte("controller-capsule/MANIFEST.json"),
    "unmanifested-member": _unmanifested,
    "missing-member": _missing_member,
    "wrong-receipt": _flip_byte("controller-capsule/controller/ledger.jsonl"),
    "wrong-outer-digest": _wrong_digest,
    "tampered-sidecar": _sidecar,
    "missing-object": _missing_object,
    "ref-map-mismatch": _ref_map,
    "signature-proof-mismatch": _signature_proof,
    "identity-mismatch": _identity,
    "unknown-schema-version": _schema,
    "absolute-source-path-in-manifest": _absolute_source,
    "self-referential-acceptance": _acceptance,
    "secret-shaped-member": _secret,
}
