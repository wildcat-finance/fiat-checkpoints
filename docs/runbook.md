# Checkpoint intake and validation delivery

This runbook derives from the receipted study for service issue #1. The
starting commit is `61b8dc4be1587d1c6ef46f2f228833214965e7f1`. Only Step 1
has its external prerequisites today. Step 2 requires released Skills #1676
evidence and the study's complete source-review and inventory-admission
conditions before any dependent edit. If they remain absent, preserve Step
1's checked checkpoint and halt with issue #1 open.

Publication, finalization and retrieval belong to service issues #2 and #3.
This run authorizes no infrastructure, paid resource or deployment. A future
inventory cannot be inserted into controller state or fabricated by amendment;
unsupported admission requires a supported fresh governed run, retaining the
scaffold as source evidence.

```design-lock
schema | protasis-design-evidence/v1
sha256 | fed947c292ba99a7f049a336a568d873608bfbb1a68098f65707ad2c94095054
candidate | mediated-isolated
```

The following reviewed research reporter is controller-local. Its interface
was checked without executing a declared service test. Six synthetic
observations cover success, assertion failure, skip, an empty suite, import
error and partial design-report binding. It refuses missing test groups and
zero tests. It is not evidence that the service works.

```command-interfaces
schema | protasis-command-interfaces/v1
.hexaemeron/check.py | build_parser | 5f7409e29dbd723a663de590104c59f2ad32fafec7116ced320cc0de8dac2ee7
```

Commands below run with the pinned service interpreter and locked environment.
Step 1 supplies the public `scripts/check.py` runner and `scripts/check.sh`
wrapper. Before its implementation receipt, review the shipped runner and
append a checked runbook amendment replacing the complete Exit and Tests
fields and the registration set for all seven steps. Keep this original
declaration unchanged. No controller-local path is a shipped test dependency.

The named groups require actual tests for their declared behavior. A missing
group, skipped test, failure or error refuses its exit. No count is predicted.
The final reports preserve observed counts, case identifiers, source/tool
digests and artifact hashes without production payloads. The runbook declares
Elenchus counters separately from those richer product reports.

## Step 1: Scaffold the isolated service

**Goal.** Establish a reproducible local service skeleton and exact specification provenance while keeping admission closed.

**Entry.** Clean managed worktree from the starting commit, receipted study and selected design, verified author/signing identity and same-repository issue #1; no product implementation exists.

**Exit.** `python3 .hexaemeron/check.py --group scaffold` verifies exact runtime/dependency/image pins, strict configuration, the public check entry point, CI, licence, source provenance and repository hygiene. A local process exposes only liveness and unavailable readiness. Production startup refuses missing protocol, test trust or unavailable isolation; no accepted, upload, authentication or download behavior ships.

**Files.** `AGENTS.md`, `.gitignore`, `.dockerignore`, `.python-version`, `pyproject.toml`, hashed dependency locks, `.github/workflows/`, `containers/`, `config/`, `src/fiat_checkpoints/`, `scripts/check.py`, `scripts/check.sh`, `tests/test_scaffold*.py`, `LICENSE`, `README.md`, `docs/specification.md`, `docs/study.md`, `docs/runbook.md`, public source manifest, `docs/decisions/drafts/isolate-checkpoint-intake.md`, and an appended correction to `docs/deployment-substrate.md`. Preserve the exact supplied specification bytes and baseline substrate prefix. Empty module/migration locations carry no protocol schemas or invented protocol lock.

**Tests.** Locked-dependency drift, missing/duplicate/unknown/malformed configuration, type and bound checks, production test-root/missing-pin/unavailable-isolation refusals, liveness versus unavailable readiness, public wrapper behavior, absent groups and zero-test refusal, immutable specification digest, preserved historical record, and no tracked real archives, observations or credentials. Exercise a local container when supported and record its observed result separately. Elenchus command: `python3 .hexaemeron/check.py --group scaffold --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-1.json`.

**Disciplines.** phylax: dependency, configuration, filesystem and test-process boundaries. ephoros: bounded liveness/readiness and fixed startup refusal codes. metron: record the reference host, with no performance claim. elenchus: reproduce and guard any observed scaffold failure. hypomnema: preserve the source and chosen construction in the stated documents.

## Step 2: Pin released protocol and domain rules

**Goal.** Consume released authority and CP-3 interfaces without inventing a service wire format.

**Entry.** Step 1 green; Skills #1676 provides exact released schema, verifier, fixture and amendment evidence; complete release-bound audit/source reading and supported known-failure inventory admission are established. Missing evidence or an unsupported inventory retrofit halts before product edits.

**Exit.** `python3 .hexaemeron/check.py --group protocol,domain` verifies exact protocol pins, golden and hostile records, all three identities, parent/prior verification and legal/illegal domain transitions. Produce the selected candidate's released-protocol report at its design-record path before Step 3 can open.

**Files.** `protocol.lock.json`, released artifact loader and source manifest, `src/fiat_checkpoints/domain/`, `src/fiat_checkpoints/records/`, `tests/test_protocol*.py`, `tests/test_domain*.py`, synthetic fixture bindings, and the protocol decision record.

**Tests.** Digest, environment, predicate, schema, signature and identity substitutions; unsupported custody/relocation; untrusted keys; missing parent evidence; malformed DSSE vectors; exact signature-byte preservation; transition exhaustiveness. Elenchus command: `python3 .hexaemeron/check.py --group protocol,domain --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-2.json`.

**Disciplines.** phylax: bounded hostile record parsing and trust inputs. ephoros: fixed producer-specific refusal codes. metron: enforce parser limits without a speed claim. elenchus: release-bound negative fixtures and required inoculation. hypomnema: record version, identity and signature decisions.

## Step 3: Persist candidates and fenced work

**Goal.** Coordinate retryable candidates, reservations, attempts and immutable intent without making SQL authoritative.

**Entry.** Step 2 and the released-protocol gate pass; an isolated local PostgreSQL 16 profile and migration path are available.

**Exit.** `python3 .hexaemeron/check.py --group persistence,concurrency` verifies migrations, scoped idempotency, quotas, leases, transactions and outbox scheduling, including crash recovery with stale workers refused.

**Files.** `migrations/`, `src/fiat_checkpoints/persistence/`, reservation/lease/outbox domain types, `tests/test_persistence*.py`, `tests/test_concurrency*.py`, and the persistence decision record.

**Tests.** Concurrent announce, changed request under one key, cross-run existence hiding, quota reservation races, stale completion, migration restart and unique-intent contention. Elenchus command: `python3 .hexaemeron/check.py --group persistence,concurrency --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-3.json`.

**Disciplines.** phylax: SQL, transactions and resource accounting. ephoros: state, lease, retry and quota events. metron: record contention measurements before optimization. elenchus: crash and race guards. hypomnema: document persistence and restart behavior.

## Step 4: Authenticate contributors and exact uploads

**Goal.** Join authenticated numeric identity, approved run/key history and one signed upload endorsement.

**Entry.** Released identity/endorsement contracts and persistent reservations pass; signed local authority fixtures are available, with production configuration still unavailable.

**Exit.** `python3 .hexaemeron/check.py --group auth,endorsement` verifies login/session expiry, CSRF, operator-approved enrollment and grants, proof of possession and the exact-upload binding.

**Files.** `src/fiat_checkpoints/auth/`, `src/fiat_checkpoints/grants/`, API authentication/endorsement adapters, `tests/test_auth*.py`, `tests/test_endorsement*.py`, and credential-custody documentation.

**Tests.** Numeric identity despite rename, provider-token substitution, login/endorsement replay and expiry, altered digests, unauthorized historical signers, revoked grants and cross-run leakage. Elenchus command: `python3 .hexaemeron/check.py --group auth,endorsement --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-4.json`.

**Disciplines.** phylax: external identity, sessions, key proof and secret references. ephoros: fixed authentication and authorization outcomes without credentials. metron: measure request bounds without predicting latency. elenchus: hostile identity guards. hypomnema: record session and key custody.

## Step 5: Seal bounded quarantine uploads

**Goal.** Stream one authorized submission into exact sealed bytes without granting provider access.

**Entry.** Current authorization, endorsement, quota reservation and lease behavior pass.

**Exit.** `python3 .hexaemeron/check.py --group upload,quarantine` verifies actor-bound short-lived capabilities, strict framing, actual byte counting and SHA-256, bounded staging, R2 read-back, immutable attempts, expiry and cleanup.

**Files.** Upload routes, trusted staging, quarantine R2 adapter, sweeper, `tests/test_upload*.py`, `tests/test_quarantine*.py`, and staging/cleanup operator records.

**Tests.** Missing/extra/truncated bytes, changed digest, replay/concurrent grants, slow streams, disk exhaustion, expiry during transfer, proxy-size guard, path/object substitution and crash retry. Elenchus command: `python3 .hexaemeron/check.py --group upload,quarantine --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-5.json`.

**Disciplines.** phylax: hostile streams, capabilities and files. ephoros: transfer, expiry and cleanup state. metron: measure incremental memory and disk bounds. elenchus: transfer and restart guards. hypomnema: document capability and staging lifetimes.

## Step 6: Validate exact bytes in isolation

**Goal.** Produce trusted validation evidence and immutable publication intent through the complete pinned command sequence.

**Entry.** Sealed input, approved authority inputs, complete released protocol and pinned isolated runtime pass; required upstream containment guards have earned their supported admission.

**Exit.** `python3 .hexaemeron/check.py --group validation,sandbox` verifies inspect, fresh restore, controller verification with observations, identity, complete commit-signature coverage, run/key scope, parent/prior evidence and signed policy freshness on one exact input. The suite executes the public rejection runner over every declared fixture at its real producer phase.

**Files.** `src/fiat_checkpoints/validation/`, sandbox launcher, typed outputs, trust injection, resource policy, `scripts/reject-case.sh`, `tests/test_validation*.py`, `tests/test_sandbox*.py`, released fixture bindings and validation decision/operator records.

**Tests.** All 35 upstream fixture IDs at their declared phases; network, credentials, hooks/config, other jobs, path swap, concurrency and resource ceilings; failed restore followed by successful verify; stale output; false carried identity; diagnostics containment for Skills #1647 through #1649. Elenchus command: `python3 .hexaemeron/check.py --group validation,sandbox --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-6.json`.

**Disciplines.** phylax: archive, Git, child-process and sandbox boundaries. ephoros: bounded current-attempt outcomes and resource measurements. metron: measure the actual pinned corpus and enforce ceilings. elenchus: guard every supported source-bound failure and preserve upstream limits. hypomnema: document validator coverage and exclusions.

## Step 7: Demonstrate intake and hand off intent

**Goal.** Demonstrate the complete issue #1 intake-to-validation path and supply issue #2 with its exact intent contract.

**Entry.** Steps 1 through 6 pass with pinned artifacts and no unresolved acceptance-impacting failure.

**Exit.** `python3 .hexaemeron/check.py --group all` runs the local intake-validation demo, rejection corpus, restart/lease tests and measured resource suites. Resolve every selected pending integration report from its named real checks. Preserve source, fixture, runtime, protocol and report hashes, a successful intent and every stable refusal; keep production closed and issue #2/#3 ownership explicit.

**Files.** `scripts/demo.sh`, `scripts/benchmark.sh`, `tests/test_demo*.py`, `tests/test_performance*.py`, final local handoff documentation, and exact evidence references for the integration record.

**Tests.** Real HTTP and PostgreSQL path into the pinned isolated validator; successful exact intent; wrong actor, changed bytes, forged identity, revoked scope and unavailable isolation; no authority object/signature; measured time, memory, disk and job limits; negative production startup and protocol mismatch. Elenchus command: `python3 .hexaemeron/check.py --group all --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-7.json`.

**Disciplines.** phylax: complete intake trust joins. ephoros: correlated demonstration and restart outcomes. metron: retain exact samples and thresholds without a production capacity claim. elenchus: preserve every final refusal and fix guard. hypomnema: publish the bounded intent handoff and production proof still owned by Skills #863.

### Amendment -- 2026-09-18

**What changed.** Complete replacement Exit: `python3 scripts/check.py --group scaffold` verifies exact runtime/dependency/image pins, strict configuration, the public check entry point, CI, licence, source provenance and repository hygiene. A local process exposes only liveness and unavailable readiness. Production startup refuses missing protocol, test trust or unavailable isolation; no accepted, upload, authentication or download behavior ships.

Complete replacement Tests: Locked-dependency drift, missing/duplicate/unknown/malformed configuration, type and bound checks, production test-root/missing-pin/unavailable-isolation refusals, liveness versus unavailable readiness, public wrapper behavior, absent groups and zero-test refusal, immutable specification digest, preserved historical record, and no tracked real archives, observations or credentials. Exercise a local container when supported and record its observed result separately. Elenchus command: `python3 scripts/check.py --group scaffold --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-1.json`.

**Why.** Step 1 now names the reviewed public test runner. Its complete source fixes the declared interface and report contracts; this amendment records interface review only. The test obligations and the Step 2 released-protocol prerequisite still apply.

```command-interfaces
schema | protasis-command-interfaces/v1
.hexaemeron/check.py | build_parser | 5f7409e29dbd723a663de590104c59f2ad32fafec7116ced320cc0de8dac2ee7
scripts/check.py | build_parser | 5a65a9da664dea1c07567d2abc83718866c57920019b7288936d1df900590a20
```

**Steps touched.** Step 1.

**Still holding.** Step 1: entry holds; exit holds. Step 2: entry holds; exit holds. Step 3: entry holds; exit holds. Step 4: entry holds; exit holds. Step 5: entry holds; exit holds. Step 6: entry holds; exit holds. Step 7: entry holds; exit holds.

### Amendment -- 2026-09-18

**What changed.** Complete replacement Exit: `python3 scripts/check.py --group protocol,domain` verifies exact protocol pins, golden and hostile records, all three identities, parent/prior verification and legal/illegal domain transitions. Produce the selected candidate's released-protocol report at its design-record path before Step 3 can open.

Complete replacement Tests: Digest, environment, predicate, schema, signature and identity substitutions; unsupported custody/relocation; untrusted keys; missing parent evidence; malformed DSSE vectors; exact signature-byte preservation; transition exhaustiveness. Elenchus command: `python3 scripts/check.py --group protocol,domain --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-2.json`.

**Why.** Step 2 now names the reviewed public test runner. Its complete source fixes the declared interface and report contracts; this amendment records interface review only. The test obligations and the Step 2 released-protocol prerequisite still apply.

**Steps touched.** Step 2.

**Still holding.** Step 1: entry holds; exit holds. Step 2: entry holds; exit holds. Step 3: entry holds; exit holds. Step 4: entry holds; exit holds. Step 5: entry holds; exit holds. Step 6: entry holds; exit holds. Step 7: entry holds; exit holds.

### Amendment -- 2026-09-18

**What changed.** Complete replacement Exit: `python3 scripts/check.py --group persistence,concurrency` verifies migrations, scoped idempotency, quotas, leases, transactions and outbox scheduling, including crash recovery with stale workers refused.

Complete replacement Tests: Concurrent announce, changed request under one key, cross-run existence hiding, quota reservation races, stale completion, migration restart and unique-intent contention. Elenchus command: `python3 scripts/check.py --group persistence,concurrency --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-3.json`.

**Why.** Step 3 now names the reviewed public test runner. Its complete source fixes the declared interface and report contracts; this amendment records interface review only. The test obligations and the Step 2 released-protocol prerequisite still apply.

**Steps touched.** Step 3.

**Still holding.** Step 1: entry holds; exit holds. Step 2: entry holds; exit holds. Step 3: entry holds; exit holds. Step 4: entry holds; exit holds. Step 5: entry holds; exit holds. Step 6: entry holds; exit holds. Step 7: entry holds; exit holds.

### Amendment -- 2026-09-18

**What changed.** Complete replacement Exit: `python3 scripts/check.py --group auth,endorsement` verifies login/session expiry, CSRF, operator-approved enrollment and grants, proof of possession and the exact-upload binding.

Complete replacement Tests: Numeric identity despite rename, provider-token substitution, login/endorsement replay and expiry, altered digests, unauthorized historical signers, revoked grants and cross-run leakage. Elenchus command: `python3 scripts/check.py --group auth,endorsement --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-4.json`.

**Why.** Step 4 now names the reviewed public test runner. Its complete source fixes the declared interface and report contracts; this amendment records interface review only. The test obligations and the Step 2 released-protocol prerequisite still apply.

**Steps touched.** Step 4.

**Still holding.** Step 1: entry holds; exit holds. Step 2: entry holds; exit holds. Step 3: entry holds; exit holds. Step 4: entry holds; exit holds. Step 5: entry holds; exit holds. Step 6: entry holds; exit holds. Step 7: entry holds; exit holds.

### Amendment -- 2026-09-18

**What changed.** Complete replacement Exit: `python3 scripts/check.py --group upload,quarantine` verifies actor-bound short-lived capabilities, strict framing, actual byte counting and SHA-256, bounded staging, R2 read-back, immutable attempts, expiry and cleanup.

Complete replacement Tests: Missing/extra/truncated bytes, changed digest, replay/concurrent grants, slow streams, disk exhaustion, expiry during transfer, proxy-size guard, path/object substitution and crash retry. Elenchus command: `python3 scripts/check.py --group upload,quarantine --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-5.json`.

**Why.** Step 5 now names the reviewed public test runner. Its complete source fixes the declared interface and report contracts; this amendment records interface review only. The test obligations and the Step 2 released-protocol prerequisite still apply.

**Steps touched.** Step 5.

**Still holding.** Step 1: entry holds; exit holds. Step 2: entry holds; exit holds. Step 3: entry holds; exit holds. Step 4: entry holds; exit holds. Step 5: entry holds; exit holds. Step 6: entry holds; exit holds. Step 7: entry holds; exit holds.

### Amendment -- 2026-09-18

**What changed.** Complete replacement Exit: `python3 scripts/check.py --group validation,sandbox` verifies inspect, fresh restore, controller verification with observations, identity, complete commit-signature coverage, run/key scope, parent/prior evidence and signed policy freshness on one exact input. The suite executes the public rejection runner over every declared fixture at its real producer phase.

Complete replacement Tests: All 35 upstream fixture IDs at their declared phases; network, credentials, hooks/config, other jobs, path swap, concurrency and resource ceilings; failed restore followed by successful verify; stale output; false carried identity; diagnostics containment for Skills #1647 through #1649. Elenchus command: `python3 scripts/check.py --group validation,sandbox --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-6.json`.

**Why.** Step 6 now names the reviewed public test runner. Its complete source fixes the declared interface and report contracts; this amendment records interface review only. The test obligations and the Step 2 released-protocol prerequisite still apply.

**Steps touched.** Step 6.

**Still holding.** Step 1: entry holds; exit holds. Step 2: entry holds; exit holds. Step 3: entry holds; exit holds. Step 4: entry holds; exit holds. Step 5: entry holds; exit holds. Step 6: entry holds; exit holds. Step 7: entry holds; exit holds.

### Amendment -- 2026-09-18

**What changed.** Complete replacement Exit: `python3 scripts/check.py --group all` runs the local intake-validation demo, rejection corpus, restart/lease tests and measured resource suites. Resolve every selected pending integration report from its named real checks. Preserve source, fixture, runtime, protocol and report hashes, a successful intent and every stable refusal; keep production closed and issue #2/#3 ownership explicit.

Complete replacement Tests: Real HTTP and PostgreSQL path into the pinned isolated validator; successful exact intent; wrong actor, changed bytes, forged identity, revoked scope and unavailable isolation; no authority object/signature; measured time, memory, disk and job limits; negative production startup and protocol mismatch. Elenchus command: `python3 scripts/check.py --group all --report {report}`; format: `unittest-json-v1`; report file: `.elenchus/step-7.json`.

**Why.** Step 7 now names the reviewed public test runner. Its complete source fixes the declared interface and report contracts; this amendment records interface review only. The test obligations and the Step 2 released-protocol prerequisite still apply.

```command-interfaces
schema | protasis-command-interfaces/v1
scripts/check.py | build_parser | 5a65a9da664dea1c07567d2abc83718866c57920019b7288936d1df900590a20
```

**Steps touched.** Step 7.

**Still holding.** Step 1: entry holds; exit holds. Step 2: entry holds; exit holds. Step 3: entry holds; exit holds. Step 4: entry holds; exit holds. Step 5: entry holds; exit holds. Step 6: entry holds; exit holds. Step 7: entry holds; exit holds.
