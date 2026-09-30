# Decision: Pin the released authority protocol as two read-only image trees

## Status

Accepted, 2026-09-30. Covers the protocol pin, how its code reaches each image,
identity handling, DSSE byte preservation and the candidate transition table.
Authentication, persistence, upload and validation belong to their own steps.

## Context

The service consumes `checkpoint-authority/v1` from Skills commit
`685158cdc5407ca5559bf9ef4a021d664e764ece` and the native commands from
Skills commit `1d4e4eebcba1825d0eb3192bf08a6c509bdc0d74`. The released library
already defines records, signatures, trust, parent joins and the lock check.
The service must call it, must not fetch it at runtime and must not trust a
tree it has not checked.

## Decision

`protocol.lock.json` is the released example lock with `authority.source_commit`
set to the authority commit. Its release manifest digest is
`fb24ac3d2e9875a11c37c2ebcdb6ef76fd3dc6a440f27bfe2c8070341dc7069c`.

`protocol.trees.json` lists the 126 authority files by SHA-256: every file the
release manifest names, the manifest itself and `.python-version`. It names the
native tree by the release's profile digest,
`dca86cde305bd5b1bce7daf6bfac7b86c71a855504d8733baaa768dd07e1389e`, which
lists 238 files.

The trees reach an image at build time, never at runtime.
`scripts/protocol_trees.py export` runs `git archive` at the two locked commits
from a local Skills clone and refuses unless every byte matches the manifest
and profile. The Dockerfile copies the result to
`/opt/fiat-checkpoints/protocol/{authority,native}` as root, removes every write
bit, then runs the service loader as the unprivileged user. A tree that fails
the check fails the build. The image digest then binds the trees. The test image
does this now. The validator image in Step 6 and any image whose role imports
the protocol use the same export and the same build-time check.

At startup `load_release` reads the lock and manifest, and requires each tree
root at its own real path, unwritable by the process. It enumerates and hashes
the authority tree before importing any of it, so an extra module refuses
before it can run. It then imports the package under a private name without
bytecode, runs the released `lock` check with the manifest's commit, compares
the lock's Python pin with the running interpreter, and hashes the native tree
against the released profile. Each failure has one fixed `protocol-*` code, and
production startup reports it. A lock the release refuses keeps the library's
code as `protocol_code`, for example `mixed-components`.

Signature verification uses `/usr/bin/openssl` pinned by SHA-256
`38633817061f9d161c8b14c1ff72c9f223e8208d977a4c15d843010611a5dded`, from the
digest-pinned base image. No record selects a tool.

## Identity handling

The three identities keep their names: `snapshot_id`,
`controller_manifest_sha256` and `archive_sha256`, which the protocol calls
`outer_sha256`. They are compared by role, never by position, and the service
never recomputes them. A swapped pair refuses as `identity_mismatch`.

## DSSE byte preservation

The service keeps the envelope bytes exactly as received, including an
accepted URL-safe or unpadded base64 form, and identifies them by the SHA-256
of those bytes. The signed payload is the library's exact decoded statement,
not a reserialization. Two valid signatures over one payload keep two envelope
identities and one payload.

## Refusal producers

A refusal names its producer. `protocol_refused` carries the library's code and
stage and nothing else. Service-side bounds refuse as `request_invalid` before
the library sees the bytes.

## Transition table

`domain/transitions.py` holds 28 rows: the 25 of the specification section 11
table (ten forward phases, `accepted` to `revoked`, and `rejected` or `expired`
from each of the seven states before signer authorization) and three rows the
section's diagram and expiry paragraph require (specification lines 344 and
350). Work the signer has durably authorized ends in complete publication or a
signed denial, so `publishing_receipt`, `finalizing` and
`publishing_finalization` each move to the terminal state `denied` on a signed
denial, and none of them can be rejected or expire. A denial of accepted work
stays `accepted` to `revoked`. A transition needs exactly its row's evidence.

## Alternatives

- Fetch or clone Skills at startup. Rejected: the service would depend on a
  network and on a reference it cannot pin at runtime.
- Copy the trees into this repository. Rejected: 364 files of another
  repository's source would need a second review path here, and a digest
  already binds them.
- Mount a host checkout into the container at runtime. Rejected: the tree
  would not be bound to an image digest, and a writable host path could change
  between the check and the import.

## Consequences

Building an image needs a local Skills clone with both commits
(`SKILLS_REPO=<clone> scripts/linux-env.sh build`), and CI checks out Skills at
the authority commit. A new protocol release changes the lock, the manifest and
the image together.

The hashes establish the bytes present at startup. They do not establish that
the process's dynamic libraries or the image's OpenSSL are trustworthy; the
base image digest carries that trust. A root-owned read-only tree is hashed
once at startup, just before the import, and nothing rechecks it afterwards.
Native executable pins for Python, Git and GnuPG come with the validator image
in Step 6; until then the native tree is checked by file hash only.
