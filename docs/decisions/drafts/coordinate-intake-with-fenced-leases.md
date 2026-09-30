# Decision: Coordinate intake in PostgreSQL with scoped keys, reserved quota and fenced leases

## Status

Accepted, 2026-09-30. Covers the Step 3 table layout, idempotency scope, quota
reservation, fenced leases, the transactional outbox and the PostgreSQL test
server. Authentication, upload transfer, validation and publication belong to
their own steps and issues.

## Context

Specification section 11 makes PostgreSQL a transactional index and work
coordinator, never the source of accepted truth. Losing session or upload
state may expire a candidate but must never manufacture acceptance. Workers
claim work with expiring leases and increasing fencing numbers, and an
expired worker must not advance a candidate. Section 9 sets the quotas, and
they must be reserved before any upload capability is granted.

## Decision

`migrations/0001_coordination.sql` creates the coordination tables, and
`src/fiat_checkpoints/persistence/` is the only code that writes them.

### Table layout

| Table | Holds |
| --- | --- |
| `actors`, `run_registrations` | The numeric actor id and the `(service_id, repository_id, run_id)` scope. Neither records authorization. |
| `candidates` | State, version, fence, carrier digest, declared size, sealed attempt, fixed retry and terminal codes, deadline. |
| `candidate_transitions` | The 28 rows of `domain/transitions.py`. A trigger refuses any state change not listed, any insert other than `announced`, and any change to a candidate's binding fields. |
| `idempotency_keys` | `(actor_id, operation, idempotency_key)` to a request fingerprint and candidate. |
| `quota_usage`, `reservations` | One counter row per global, run and actor scope, and one row per candidate or stream reservation. |
| `upload_attempts`, `validation_attempts` | `(candidate_id, attempt_number)` with the fence and lease expiry that granted it. |
| `publication_intents` | One per candidate: the three identities, the validating fence and the exact evidence bytes with their SHA-256. |
| `outbox_jobs` | `validate-candidate` and `publish-intent` jobs, written in the transaction that makes them due. |
| `audit_events` | One row per candidate transition or retry, with fixed codes only. |

Triggers make `publication_intents` and `audit_events` refuse update, delete
and truncate. `archive_sha256` has no uniqueness constraint, so two runs that
submit the same bytes never learn of each other.

Sessions and grants arrive with Step 4. Object copies, authority records,
accepted representations, denial projections and rebuild checkpoints belong
to issues #2 and #3. Each later table arrives in a new numbered migration; the
runner refuses a changed or unknown applied migration.

### Idempotency scope

A key is 16 to 128 printable ASCII characters and is scoped to one actor and
operation. Its fingerprint is the SHA-256 of canonical JSON binding the
operation, actor, run scope and every announce body field. A matching replay
returns the existing candidate; any other fingerprint is `idempotency_conflict`
and names nothing about other actors. A mapping lives for the 24-hour
candidate lifetime plus seven days, then stops answering.

### Quota reservation

Announce reserves one candidate and the declared bytes before the candidate
exists. Each scope is one conditional `UPDATE ... WHERE usage + n <= limit`,
taken in the fixed order global, run, actor. A refusal rolls back the key, the
candidate and every counter. An upload lease reserves one stream against the
actor and global counters before it is granted. Reservations are released
exactly once: sealing releases the stream, rejection and expiry release
everything. A lease that expires unsealed gives its stream back before the
next stream is admitted. A validation pass keeps the candidate reservation,
because an intent is not acceptance. Configuration may lower any ceiling,
never raise it.

### Fenced leases

Every lease grant increments the candidate's fence. Every completion locks
the candidate row, then requires the same fence on the candidate, attempt and
job, and an unexpired lease. A worker whose lease expired is refused as
`lease_stale` even when nobody has replaced it. A replacement claim is
possible only after expiry, and it gets a higher fence and the same sealed
input. Repeating a completed seal or pass with the same lease returns the
same result.

### Outbox and retries

A claim locks the job's candidate with `FOR UPDATE SKIP LOCKED`, then the job,
so it never holds a job while it waits for the candidate. A dependency outage
keeps the candidate in its phase with a fixed `retry_reason` and reschedules
the job with exponential backoff: half of a window of 2^(n-1) seconds, plus
jitter over the other half, with the window capped at 300 seconds. A
`validation_failed` tool failure holds the job for an operator after a
configured number of attempts, at most 32.

### Local expiry

The sweeper expires only `announced`, `uploading`, `quarantined` and
`validating` candidates. Before an intent exists nothing can have reached a
signer, so the service's own cancellation is the only cancellation. Once an
intent exists the candidate waits for its publication owner, whose journal
decides between cancellation and signer authorization (issue #2). Until
issue #2 consumes intents, each one keeps its candidate and byte reservation,
so 5 per actor, 20 per run or 100 overall stop new announces; issue #2 carries
the release path.

### Transactions and failures

Each call is one READ COMMITTED transaction on its own connection. The
candidate row is always locked before anything belonging to it, and quota
rows are locked global, run, actor, so no two calls wait on each other in a
cycle. A serialization failure or deadlock reruns the call up to eight times,
and only the attempt that commits logs its events.
Every other library failure becomes `database_unavailable` or
`persistence_failed`, raised with no chained cause. Statements and lock waits
time out after 10 seconds.

### Test server

Checks use `postgres:16.15-trixie`, pinned by index digest
`sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`.
`scripts/test-postgres.sh` runs it with no network, data in tmpfs and a Unix
socket in a named volume. The test container mounts that volume and keeps
`--network none`; local socket connections are trusted. Every test creates and
drops its own database. `scripts/linux-env.sh db-start` and CI use the same
script.

## Signals

| Question | Signal |
| --- | --- |
| Why has this candidate stopped? | `candidate-*`, `upload-*`, `validation-started` and `intent-recorded` events with state pair, fence and `age_ms`; `retry-scheduled` and `job-held` with the fixed reason, count and delay |
| Did a stale worker try to finish? | `lease-expired` and `lease-stale-refused` with kind and fence |
| Can the host take another job? | `Coordinator.usage()` global counts; `quota-refused` with the scope that refused; `quota-released` |

Events carry random candidate ids, never actor ids, digests, keys or evidence
bytes. Events are logged after their transaction commits; a rolled-back call
logs only its refusal.

## Contention baseline

Measured on 2026-09-30 in the colima `fiat-s862a` x86_64 VM (4 vCPUs, qemu
emulation on an arm64 Mac) against the pinned server. No optimization was
made. Each repetition used a fresh migrated database and distinct keys, actors
and four runs, so no call was refused. Times include opening a connection per
call. The script was a throwaway and is not shipped.

| Concurrent announces | Repetitions | Wall median | Per-call p50 | p95 | p99 | Max |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 7 | 108.7 ms | 107.2 ms | 119.9 ms | 119.9 ms | 119.9 ms |
| 16 | 7 | 835.7 ms | 513.6 ms | 763.8 ms | 813.5 ms | 823.6 ms |

Sixteen racing announces take about 7.7 times one announce, which is what one
global counter row serializing them predicts. These numbers come from an
emulated VM and say nothing about production latency.

## Alternatives

- SERIALIZABLE transactions with retry instead of explicit row locks.
  Rejected: every announce touches the global counter, so contention retries
  would grow with load and could exhaust the retry budget.
- Counting outstanding candidates with `SELECT count(*)` at admission.
  Rejected: two transactions can both read the count below the limit and both
  commit.
- A global unique constraint on `archive_sha256`. Rejected by specification
  section 11: it leaks cross-run existence through deduplication.
- Lease validity by holder identity alone. Rejected: a worker that paused past
  its expiry would still match, so the fence and expiry are both checked.
- PostgreSQL inside the test image. Rejected: the image installs hashed wheels
  only and no system packages, and a server started by a test would be a child
  process that the Elenchus report run refuses.

## Consequences

The service can restart at any point: a transaction either commits whole or
leaves nothing, migrations rerun as a no-op, and stale leases refuse. A
database outage stops new work but cannot fabricate progress. Every
completion serializes on one candidate row, and every announce serializes on
the global counter row; the baseline above is the reference for any later
change. Changing this layout after it ships is an ask-first change under the
study.

The checks do not restart the PostgreSQL server itself; they terminate
backends mid-transaction and rebuild every client object. Server-side crash
durability is PostgreSQL's own guarantee and is not retested here.
