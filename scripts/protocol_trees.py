#!/usr/bin/env python3
"""Build the two read-only protocol trees from a local Skills clone, bound by digest.

    python3 scripts/protocol_trees.py manifest --skills-repo DIR
    python3 scripts/protocol_trees.py export --skills-repo DIR --out DIR

`manifest` writes `protocol.trees.json` from the commits `protocol.lock.json`
pins. `export` writes `<out>/authority` and `<out>/native` with `git archive`
at those commits and refuses unless every file matches the recorded digests.
Both run on a build host before an image build; the service never runs Git,
fetches a tree or reads a mutable reference.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile


ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "protocol.lock.json"
MANIFEST = ROOT / "protocol.trees.json"
SCHEMA = "fiat-checkpoints-protocol-trees/v1"
RELEASE_MANIFEST = "plugins/hexaemeron/skills/fiat/checkpoint-authority/release-manifest.json"
NATIVE_PROFILE = "plugins/hexaemeron/skills/fiat/checkpoint-authority/native-profile.json"
# The released `release` check reads the interpreter pin beside the tree root.
AUTHORITY_EXTRA = (".python-version", RELEASE_MANIFEST)
COMMIT = re.compile(r"[0-9a-f]{40}")
ARCHIVE_MAX = 256 * 1024 * 1024


class TreeRefusal(Exception):
    """A fixed code; Git diagnostics and paths stay out of the message."""


def git_archive(repo, commit, paths):
    if COMMIT.fullmatch(commit) is None:
        raise TreeRefusal("mutable-source-reference")
    run = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", commit, "--", *paths],
                         capture_output=True, timeout=300, check=False)
    if run.returncode != 0 or len(run.stdout) > ARCHIVE_MAX:
        raise TreeRefusal("git-archive-failed")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(run.stdout)) as tar:
        for member in tar.getmembers():
            if member.isdir() or member.name == "pax_global_header":
                continue
            if not member.isfile():
                raise TreeRefusal("tree-member-kind")
            files[member.name] = tar.extractfile(member).read()
    if sorted(files) != sorted(paths):
        raise TreeRefusal("tree-member-set")
    return files


def authority_paths(repo, commit):
    listing = git_archive(repo, commit, [RELEASE_MANIFEST])[RELEASE_MANIFEST]
    manifest = json.loads(listing)
    paths = {row["path"] for component in manifest["components"].values() for row in component["files"]}
    paths |= {row["path"] for row in manifest["transitive_files"]}
    return sorted(paths | set(AUTHORITY_EXTRA))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def lock():
    value = json.loads(LOCK.read_bytes())
    return value["authority"]["source_commit"], value["native"]["source_commit"]


def build_manifest(repo):
    authority_commit, native_commit = lock()
    files = git_archive(repo, authority_commit, authority_paths(repo, authority_commit))
    profile = json.loads(files[NATIVE_PROFILE])
    if profile["source_commit"] != native_commit:
        raise TreeRefusal("native-source-pin")
    return {
        "schema": SCHEMA,
        "authority": {"source_commit": authority_commit,
                      "files": [{"path": path, "sha256": digest(files[path])} for path in sorted(files)]},
        "native": {"source_commit": native_commit, "profile_sha256": digest(files[NATIVE_PROFILE]),
                   "files": len(profile["files"])},
    }


def write_tree(directory, files):
    for path, data in sorted(files.items()):
        target = directory / path
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)


def export(repo, out):
    recorded = json.loads(MANIFEST.read_bytes())
    if recorded != build_manifest(repo):
        raise TreeRefusal("tree-manifest-stale")
    if out.exists():
        raise TreeRefusal("output-exists")
    authority = git_archive(repo, recorded["authority"]["source_commit"],
                            [row["path"] for row in recorded["authority"]["files"]])
    for row in recorded["authority"]["files"]:
        if digest(authority[row["path"]]) != row["sha256"]:
            raise TreeRefusal("authority-digest")
    profile = json.loads(authority[NATIVE_PROFILE])
    native = git_archive(repo, recorded["native"]["source_commit"], [row["path"] for row in profile["files"]])
    for row in profile["files"]:
        if digest(native[row["path"]]) != row["sha256"]:
            raise TreeRefusal("native-digest")
    write_tree(out / "authority", authority)
    write_tree(out / "native", native)
    return {"authority_files": len(authority), "native_files": len(native)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument("operation", choices=["manifest", "export"])
    parser.add_argument("--skills-repo", required=True)
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    repo = Path(args.skills_repo).resolve(strict=True)
    try:
        if args.operation == "manifest":
            raw = json.dumps(build_manifest(repo), indent=2, sort_keys=True) + "\n"
            MANIFEST.write_text(raw)
            print(json.dumps({"manifest": MANIFEST.name, "sha256": digest(raw.encode())}))
        else:
            if args.out is None:
                raise TreeRefusal("output-missing")
            print(json.dumps(export(repo, Path(args.out).absolute())))
    except TreeRefusal as error:
        print("protocol-trees-refused: " + str(error), file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError):
        print("protocol-trees-refused: tree-input-unavailable", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
