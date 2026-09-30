# Checkpoint intake and validation delivery

This runbook derives from the receipted study for service issue #1. The run
starts from `61b8dc4be1587d1c6ef46f2f228833214965e7f1`. It consumes the
released authority protocol at Skills commit
`685158cdc5407ca5559bf9ef4a021d664e764ece` and runs every service role on
CPython 3.14.6; the operator confirmed that interpreter on 2026-09-29.

Publication, finalization and retrieval belong to service issues #2 and #3.
This run authorizes no infrastructure, paid resource or deployment. Every
commit has author and committer `Dr Laurence E. Day <laurence@wildcat.finance>`
and a valid signature, with no Shoggoth identity, bot login or provenance
trailer.

```design-lock
schema | protasis-design-evidence/v1
sha256 | 429ff07ff19cf157a60d437c37928b4f32026a562adb0c27078bf65a56c846bc
candidate | isolated-pinned-runtime
```

Step 1 creates the public runner `scripts/check.py`. It is registered here
before it exists, and Step 1's push binds its bytes:

```command-interfaces
schema | protasis-command-interfaces/v1
scripts/check.py | build_parser | step:1
```

The runner's builder is `parser = argparse.ArgumentParser(...)`, literal
`add_argument` calls, then `return parser`. It accepts `--group`, `--report`,
`--candidate`, `--criterion` and `--out`, plus an optional `design` mode, so
the design record's resolvers
(`python3 scripts/check.py design --candidate <id> --criterion <id> --out <path>`)
fit it. It starts no child process when it produces an Elenchus report, refuses
an absent group and refuses zero tests.

**Where commands run.** The operator chose a local colima VM for Linux work on
2026-09-29. Exit and Elenchus commands run in the run's Linux environment:
colima profile `fiat-s862a`, x86_64, with the run worktree mounted at the same
path, inside the pinned test image Step 1 defines. The macOS host runs only the
prose lints and Git. A check that cannot run in that environment refuses its
exit; nothing falls back to the host. Hosted CI repeats the same groups as a
second observation, and its result does not replace the local exit.

The named groups require actual tests for their declared behavior. A missing
group, skipped test, failure or error refuses the exit. No count is predicted.
Reports keep observed counts, case identifiers, source and tool digests and
artefact hashes, without production payloads.

## Step 1: Scaffold the isolated service

**Goal.** Establish a reproducible local service skeleton, its Linux test environment and exact specification provenance while keeping admission closed.

**Entry.** Clean managed worktree at the starting commit, receipted study and selected design, verified signing identity and same-repository issue #1; no product code exists and `scripts/check.py` is absent.

**Exit.** Admission stays closed: liveness only, readiness unavailable, and production startup refuses missing protocol pins, test trust roots or unavailable isolation. Run in the Linux environment:

```sh
python3 scripts/check.py --group scaffold
```

It verifies the 3.14.6 runtime, hashed dependency and image pins, strict configuration, the public check entry point and wrapper, CI, licence, the immutable specification digest, the preserved substrate prefix and repository hygiene.

**Files.** `AGENTS.md`, `.gitignore`, `.dockerignore`, `.python-version`, `pyproject.toml`, hashed dependency locks, `.github/workflows/check.yml`, `containers/api.Dockerfile`, `containers/test.Dockerfile`, `scripts/linux-env.sh`, `config/`, `src/fiat_checkpoints/`, `scripts/check.py`, `scripts/check.sh`, `scripts/serve.py`, `tests/test_scaffold*.py`, `LICENSE`, `README.md`, `docs/specification.md`, `docs/study.md`, `docs/runbook.md`, `docs/sources.json`, `docs/decisions/drafts/isolate-checkpoint-intake.md`, and a dated correction appended to `docs/deployment-substrate.md`. The inherited scaffold at `f81f119b1984c9379b6a4405b1492ab4a5e007fa` may be reused after review; every pin moves to 3.14.6 and every commit is re-authored under this run's identity. Empty module and migration locations carry no protocol schema and no invented protocol lock.

**Tests.** Locked-dependency drift; missing, duplicate, unknown and malformed configuration; type and bound checks; production refusals for a test root, a missing pin and unavailable isolation; liveness versus unavailable readiness; wrapper behavior; absent group and zero-test refusal; the `design` mode refusing an unknown candidate or criterion; the specification digest; the preserved substrate prefix; no tracked archive, observation or credential; the Starlette HTTPX test adapter lead at the new pins. Record the Linux environment's kernel, architecture and image digest. Elenchus command: `python3 scripts/check.py --group scaffold --report {report}`; format: `unittest-json-v1`; report file: `.hexaemeron/elenchus-step-1.json`

**Disciplines.** phylax: dependency, configuration, filesystem and test-process boundaries. ephoros: bounded liveness and readiness and fixed startup refusal codes. metron: record the reference host; no performance claim. elenchus: reproduce and guard any observed scaffold failure. hypomnema: the design record for `isolated-pinned-runtime`, the substrate correction and the README start and check commands.

## Step 2: Pin released protocol and domain rules

**Goal.** Consume the released authority protocol and CP-3 interfaces without inventing a service wire format.

**Entry.** Step 1 green; the released lock, schema set, verifier, fixture corpus and native pins in study section 3 reproduce at the authority commit.

**Exit.** The protocol and domain rules hold, and the design record's protocol-lock-shipped report exists at its recorded path before Step 3 opens. Run in the Linux environment:

```sh
python3 scripts/check.py --group protocol,domain
python3 scripts/check.py design --candidate isolated-pinned-runtime --criterion protocol-lock-shipped --out .hexaemeron/design/reports/isolated-pinned-runtime-protocol-lock-shipped.json
```

**Files.** `protocol.lock.json`, the read-only authority and native tree loader and its source manifest, `src/fiat_checkpoints/domain/`, `src/fiat_checkpoints/records/`, `tests/test_protocol*.py`, `tests/test_domain*.py`, synthetic fixture bindings, and `docs/decisions/drafts/pin-authority-protocol.md`.

**Tests.** Digest, environment, predicate, schema, signature and identity substitutions; the shipped lock passing the released `lock` check and startup refusing without it; unsupported custody and relocation; untrusted keys; missing parent evidence; malformed DSSE vectors; exact signature-byte preservation; exhaustive legal and illegal domain transitions. Elenchus command: `python3 scripts/check.py --group protocol,domain --report {report}`; format: `unittest-json-v1`; report file: `.hexaemeron/elenchus-step-2.json`

**Disciplines.** phylax: bounded hostile record parsing and trust inputs. ephoros: fixed producer-specific refusal codes. metron: enforce parser limits without a speed claim. elenchus: release-bound negative fixtures. hypomnema: record the protocol pin, identity handling and DSSE byte preservation.

## Step 3: Persist candidates and fenced work

**Goal.** Coordinate retryable candidates, reservations, attempts and immutable intent without making SQL authoritative.

**Entry.** Step 2 green and its `protocol-lock-shipped` report passing; PostgreSQL 16 runs in the Linux environment.

**Exit.** Migrations, scoped idempotency, quotas, leases, transactions and outbox scheduling hold, crash recovery refuses stale workers, and the restart-recovery report exists before Step 4 opens. Run in the Linux environment:

```sh
python3 scripts/check.py --group persistence,concurrency
python3 scripts/check.py design --candidate isolated-pinned-runtime --criterion restart-recovery --out .hexaemeron/design/reports/isolated-pinned-runtime-restart-recovery.json
```

**Files.** `migrations/`, `src/fiat_checkpoints/persistence/`, reservation, lease and outbox domain types, `tests/test_persistence*.py`, `tests/test_concurrency*.py`, and `docs/decisions/drafts/coordinate-intake-with-fenced-leases.md`.

**Tests.** Concurrent announce; a changed request under one idempotency key; cross-run existence hiding; quota reservation races; stale completion; migration restart; unique-intent contention. Elenchus command: `python3 scripts/check.py --group persistence,concurrency --report {report}`; format: `unittest-json-v1`; report file: `.hexaemeron/elenchus-step-3.json`

**Disciplines.** phylax: SQL, transactions and resource accounting. ephoros: state, lease, retry and quota events. metron: record contention measurements before any optimization. elenchus: crash and race guards. hypomnema: record table layout, idempotency scope and fenced leases.

## Step 4: Authenticate contributors and exact uploads

**Goal.** Join authenticated numeric identity, approved run and key history and one signed upload endorsement.

**Entry.** Step 3 green and its `restart-recovery` report passing; signed local authority fixtures exist and production configuration stays unavailable.

**Exit.** Login and session expiry, CSRF, operator-approved enrollment and grants, proof of possession and the exact-upload binding hold. Run in the Linux environment:

```sh
python3 scripts/check.py --group auth,endorsement
```

**Files.** `src/fiat_checkpoints/auth/`, `src/fiat_checkpoints/grants/`, API authentication and endorsement adapters, `tests/test_auth*.py`, `tests/test_endorsement*.py`, and `docs/decisions/drafts/bind-uploads-to-enrolled-keys.md`.

**Tests.** Numeric identity despite a rename; provider-token substitution; login and endorsement replay and expiry; altered digests; unauthorized historical signers; revoked grants; cross-run leakage; a carried key refused for self-enrollment. Elenchus command: `python3 scripts/check.py --group auth,endorsement --report {report}`; format: `unittest-json-v1`; report file: `.hexaemeron/elenchus-step-4.json`

**Disciplines.** phylax: external identity, sessions, key proof and secret references. ephoros: fixed authentication and authorization outcomes without credentials. metron: measure request bounds without predicting latency. elenchus: hostile identity guards. hypomnema: record session, key and endorsement custody.

## Step 5: Seal bounded quarantine uploads

**Goal.** Stream one authorized submission into exact sealed bytes without granting provider access.

**Entry.** Step 4 green: current authorization, endorsement, quota reservation and lease behavior pass.

**Exit.** Actor-bound short-lived capabilities, strict framing, actual byte counting and SHA-256, bounded staging, quarantine read-back, immutable attempts, expiry and cleanup hold. Run in the Linux environment:

```sh
python3 scripts/check.py --group upload,quarantine
```

**Files.** Upload routes, trusted staging, the quarantine R2 adapter with a local test double, the sweeper, `tests/test_upload*.py`, `tests/test_quarantine*.py`, and staging and cleanup operator records under `docs/runbooks/`.

**Tests.** Missing, extra and truncated bytes; a changed digest; replayed and concurrent grants; slow streams; disk exhaustion; expiry during transfer; the proxy-size guard; path and object substitution; crash retry. Gateway incremental memory stays at or below 67,108,864 bytes per stream. Elenchus command: `python3 scripts/check.py --group upload,quarantine --report {report}`; format: `unittest-json-v1`; report file: `.hexaemeron/elenchus-step-5.json`

**Disciplines.** phylax: hostile streams, capabilities and files. ephoros: transfer, expiry and cleanup state. metron: measure incremental memory and disk bounds. elenchus: transfer and restart guards. hypomnema: record capability and staging lifetimes.

## Step 6: Validate exact bytes in isolation

**Goal.** Produce trusted validation evidence and an immutable publication intent through the complete pinned command sequence.

**Entry.** Step 5 green; gVisor `runsc` release and digest are pinned after running in the Linux environment; the validator image holds the read-only authority and native trees.

**Exit.** Inspect, fresh restore, controller verification with observations, identity, complete commit-signature coverage, run and key scope, parent and prior evidence and signed policy freshness hold on one exact input, and the rejection runner covers every declared fixture at its real producer phase. Run in the Linux environment:

```sh
python3 scripts/check.py --group validation,sandbox
```

**Files.** `src/fiat_checkpoints/validation/`, the sandbox launcher, typed outputs, trust injection, resource policy, `scripts/reject-case.sh`, `scripts/benchmark.sh`, `tests/test_validation*.py`, `tests/test_sandbox*.py`, released fixture bindings, `docs/decisions/drafts/isolate-validator-trust.md` and validation operator records under `docs/runbooks/`.

**Tests.** All 35 upstream fixture ids at their declared phases; network, credential, hook and config, other-job, path-swap, concurrency and resource-ceiling cases; a failed restore followed by a successful verify; stale output; a false carried identity; malformed native output mapping to fixed `validation_failed` (`native-local-errors`); whole-job limits the protocol lacks; diagnostics, destination and concurrency containment for Skills #1647, #1648 and #1649; a missing sandbox refusing rather than falling back to a plain subprocess. Elenchus command: `python3 scripts/check.py --group validation,sandbox --report {report}`; format: `unittest-json-v1`; report file: `.hexaemeron/elenchus-step-6.json`

**Disciplines.** phylax: archive, Git, child-process and sandbox boundaries. ephoros: bounded current-attempt outcomes and resource measurements. metron: measure the released corpus at its actual size and enforce the ceilings. elenchus: guard every observed failure and keep an `inconclusive` verdict from Skills #1541 as observed. hypomnema: record sandbox profile, trust injection and coverage exclusions.

## Step 7: Demonstrate intake and hand off intent

**Goal.** Demonstrate the complete issue #1 intake-to-validation path and give issue #2 its exact intent contract.

**Entry.** Steps 1 to 6 green with pinned artefacts and no unresolved acceptance-impacting failure.

**Exit.** The local intake-validation demo, the rejection corpus, restart and lease tests and measured resource suites pass, and the four integration reports exist at their recorded paths before integration. Run in the Linux environment:

```sh
python3 scripts/check.py --group all
python3 scripts/check.py design --candidate isolated-pinned-runtime --criterion native-sequence-linux --out .hexaemeron/design/reports/isolated-pinned-runtime-native-sequence-linux.json
python3 scripts/check.py design --candidate isolated-pinned-runtime --criterion intake-hostile-suites --out .hexaemeron/design/reports/isolated-pinned-runtime-intake-hostile-suites.json
python3 scripts/check.py design --candidate isolated-pinned-runtime --criterion validation-wall-time --out .hexaemeron/design/reports/isolated-pinned-runtime-validation-wall-time.json
python3 scripts/check.py design --candidate isolated-pinned-runtime --criterion gateway-stream-memory --out .hexaemeron/design/reports/isolated-pinned-runtime-gateway-stream-memory.json
```

**Files.** `scripts/demo.sh`, `tests/test_demo*.py`, `tests/test_performance*.py`, the issue #2 handoff document with its evidence contract, one example intent and every stable refusal, and README demo commands.

**Tests.** The real HTTP and PostgreSQL path into the pinned isolated validator; one successful exact intent; wrong actor, changed bytes, forged identity, revoked scope and unavailable isolation each producing no intent; no authority object or signature; the current valid fixture validated within 900,000 ms; metadata p95 at most 500 ms excluding identity-provider calls; negative production startup and protocol mismatch. Elenchus command: `python3 scripts/check.py --group all --report {report}`; format: `unittest-json-v1`; report file: `.hexaemeron/elenchus-step-7.json`

**Disciplines.** phylax: complete intake trust joins. ephoros: correlated demonstration and restart outcomes. metron: retain exact samples and thresholds without a production capacity claim. elenchus: keep every final refusal and fix guard. hypomnema: publish the bounded intent handoff and name the production proof Skills #863 still owns.
