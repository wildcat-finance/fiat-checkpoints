# fiat-checkpoints

The replaceable service behind Fiat's distributed checkpoint layer: contributor
authentication and run authorisation, bounded quarantine upload grants,
isolated validation against a pinned protocol release, immutable publication
and replication with signed statements, derived indexes, and the infrastructure
around them.

The portable protocol lives in [`wildcat-finance/skills`](https://github.com/wildcat-finance/skills)
and is pinned here by release or exact commit digest. This repository never
widens a schema locally to accept a failing upload.

Nothing is deployed. The current checkpoint transport remains the local store
under `<origin>/.hexaemeron/checkpoints/`, and no checkpoint operation uploads,
posts, commits or pushes.

## This repository is public

No archive, observation, credential, environment value or deployment secret
enters this tree. Ever.

## Current state

The scaffold, the pinned protocol and PostgreSQL coordination exist, and
admission is closed. The service answers `GET /health/live` with 200 and
`GET /health/ready` with 503 and the code `intake-closed`. Every production
start refuses: a test trust root, a missing or refused protocol pin and
unavailable isolation each have a fixed startup code, and the scaffold adds
`scaffold-only`. The [configuration contract](config/README.md) lists the
fields and codes.

[`protocol.lock.json`](protocol.lock.json) pins the released authority
protocol, and [`protocol.trees.json`](protocol.trees.json) lists the bytes of
the two read-only Skills trees each image carries. The
[protocol decision](docs/decisions/drafts/pin-authority-protocol.md) explains
how they are built and checked.

[`migrations/`](migrations) and `src/fiat_checkpoints/persistence/` coordinate
candidates, quota reservations, fenced leases, immutable publication intents
and the outbox in PostgreSQL 16. Nothing there can mark a checkpoint accepted.
The [coordination decision](docs/decisions/drafts/coordinate-intake-with-fenced-leases.md)
records the table layout, idempotency scope and lease rules.

`src/fiat_checkpoints/auth/` and `src/fiat_checkpoints/grants/` authenticate a
contributor by numeric identity, session and CSRF token, verify each run's
operator-signed trust records through the released library, and bind one
signed upload endorsement to each announced candidate. No identity provider is
deployed, and the intake app refuses production like the health app. The
[authentication decision](docs/decisions/drafts/bind-uploads-to-enrolled-keys.md)
records session, key and endorsement custody.

A recorded endorsement returns an upload capability. The upload gateway,
`src/fiat_checkpoints/api/gateway.py`, takes it on one fixed route, counts and
hashes the exact bytes into bounded staging, writes them to a fresh
quarantine key, reads them back in full and only then seals the attempt.
`src/fiat_checkpoints/upload/` holds the capability, staging, issuer and
sweeper code; `src/fiat_checkpoints/storage/` holds the local quarantine store,
and the live R2 adapter refuses to start. The
[transfer decision](docs/decisions/drafts/seal-uploads-in-bounded-quarantine.md)
records capability and staging lifetimes and the measured per-stream bounds,
and [`docs/runbooks/`](docs/runbooks) holds the staging and cleanup records.

## Start locally

Python 3.14.6 with the locked dependencies installed:

```sh
python3 scripts/serve.py --config config/local.json
```

It binds `127.0.0.1:8000` and logs one JSON event per health request.

## Check

Tests run on x86_64 Linux inside the pinned test image. On a Mac, the colima
profile `fiat-s862a` provides that kernel; `scripts/linux-env.sh` creates it,
builds the image and runs a command in it with the checkout mounted and no
network:

```sh
scripts/linux-env.sh start
SKILLS_REPO=<skills clone> scripts/linux-env.sh build
scripts/linux-env.sh run python3 scripts/check.py --group scaffold
scripts/linux-env.sh run python3 scripts/check.py --group protocol,domain
scripts/linux-env.sh db-start
scripts/linux-env.sh run python3 scripts/check.py --group persistence,concurrency
scripts/linux-env.sh run python3 scripts/check.py --group auth,endorsement
scripts/linux-env.sh run python3 scripts/check.py --group upload,quarantine
scripts/linux-env.sh facts
```

`db-start` runs the digest-pinned PostgreSQL 16 test server with no network.
The test container reaches it only through a Unix socket volume, and each test
creates and drops its own database; the persistence, concurrency, auth,
endorsement, upload and quarantine groups need it. `db-stop` removes the
server.

The build exports both protocol trees from a local clone of
`wildcat-finance/skills` holding the two locked commits, and refuses unless
every file matches its recorded digest.

On a Linux host with uv 0.12.13, the wrapper runs the same check from the
locked environment:

```sh
./scripts/check.sh --group scaffold
```

`scripts/check.py` runs every module named `tests/test_<group>.py` or
`tests/test_<group>_*.py` for each named group, or every test with
`--group all`. It prints one JSON line with the case ids, counters, source
digests and the kernel, architecture and interpreter it ran on. An absent
group, a group with no tests, a skip, an expected failure, an error or a
failure cannot pass. `--report <path>` also writes an `elenchus.unittest.v1`
counter report and runs only tests that start no child process.
`check.py design` writes a design conformance report for a criterion whose
resolver is registered in `src/fiat_checkpoints/conformance.py`, and refuses
any other.

## Records

The [adopted specification](docs/specification.md) is kept byte for byte, and
[source bindings](docs/sources.json) name its digest and the other sources.
The [study](docs/study.md) and [runbook](docs/runbook.md) are this delivery's
receipted plan. [The runtime decision](docs/decisions/drafts/isolate-checkpoint-intake.md)
records the selected construction, and the
[substrate record](docs/deployment-substrate.md) carries a dated correction.

Publication belongs to [issue #2](https://github.com/wildcat-finance/fiat-checkpoints/issues/2),
retrieval to [issue #3](https://github.com/wildcat-finance/fiat-checkpoints/issues/3),
and live deployment proof to [Skills #863](https://github.com/wildcat-finance/skills/issues/863).
The code is licensed under [Apache-2.0](LICENSE).
