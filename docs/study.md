# Authenticated checkpoint intake and isolated validation

Assuming, unless corrected: the user authorizes local scaffolding now; the
adopted specification remains fixed at SHA-256
`8ee755c1f9e5c29703af30bd08caffb6fad80c8a0990ee0acecebef09b02f541`; service issue
#1 owns intake through validation intent; its publication and retrieval
siblings retain their own work. This study treats Python 3.12.13 as the exact
service interpreter available for the specification's Python 3.12 profile.
No assumption supplies a missing protocol release or deployment authority.

The study supports scaffold planning. Protocol-consuming work remains blocked
on Skills #1676 and its release-bound source review. The service does not yet
exist, and none of the future service checks below has run.

## 1. Problem statement and completion

An authorized contributor needs to submit one exact checkpoint to a service
that checks its bytes, provenance, controller state and current run authority
before handing a sealed validation result to publication. The implementation
boundary is [service issue #1](https://github.com/wildcat-finance/fiat-checkpoints/issues/1),
also called `S-862A`. Its output is a trusted validation-evidence object and an
immutable publication intent. Successful acceptance, finalization, download
and rebuild belong to subsequent packets.

The normative input is the
[adopted specification](https://github.com/user-attachments/files/32263127/862-r2-service-specification.md),
sections 7 through 11 and implementation steps 1 through 6. Its exact bytes are preserved in
`.hexaemeron/sources/specification.md`; Step 1 ships those bytes unchanged as
`docs/specification.md`. The source's proposed-status sentence is historical;
the adoption and this packet's narrower scope come from issue #1.

There are two separate outcomes:

- Step 1 establishes a reproducible local scaffold with pinned tools,
  dependency hashes, strict service configuration, public-repository hygiene,
  a test runner, CI, licence, and preserved specification/study/runbook. Local
  health can report process liveness; readiness refuses missing protocol
  evidence. `./scripts/check.sh --group scaffold` is its product check.
- Issue #1 completes only when real HTTP announce, endorsement, upload,
  complete and status paths feed the actual pinned inspect, restore,
  controller verification and identity commands through the isolated
  validator. `./scripts/demo.sh --scenario intake-validation --profile local`
  then demonstrates one successful intent and bounded negative cases.

The final demo runs the real API, PostgreSQL migrations, production intake
algorithm and pinned inspector, with synthetic public fixtures and explicitly
local identity/storage substitutes. It records source, runtime, fixture and
protocol digests, command exits, exact report hashes and observed refusals.
It must show wrong actor, changed bytes, forged carried identity, revoked
scope and unavailable isolation producing no publication intent. It also
checks that no authority object or signature is created. These observations
cover those cases; they do not prove all possible inputs safe.

Completion also requires
`./scripts/check.sh --group protocol,domain,auth,upload,quarantine,validation,sandbox`,
`./scripts/check.sh --group persistence,concurrency,performance`, and
`./scripts/reject-case.sh --all`. Preserve every upstream fixture ID at its
producer, inspector or restore stage. The full-service
`./scripts/demo.sh --scenario end-to-end --profile local` remains with service
issue #3 after issue #2 supplies publication.

## 2. Prior art, audit sources and carried work

The starting tree contains only `README.md` and
`docs/deployment-substrate.md`. `git ls-files` found no target audit source,
code, tests, dependency manifest or instructions file. The current target
pull-request listing was empty. There are no target implementation PRs or
target known failures to claim reviewed or guarded.

The existing substrate chooses R2, content-addressed objects, a second
Cloudflare account and a derived database. Its presigned transfer language,
delete-permission claim, undecided jurisdiction and signer assumptions are
historical. The adopted specification supplies service-mediated transfers,
separate EU accounts, effective lock protection and the external policy signer.
Step 1 preserves the original record and appends the adopted correction; it
cannot silently rewrite its earlier decision.

The two upstream deliveries named by the specification were read through their
complete current PR bodies:

| Source | Result retained | Remaining boundary |
| --- | --- | --- |
| [Skills PR #1652](https://github.com/wildcat-finance/skills/pull/1652), merge `6982793334003dc0a441d6e90e753a143e3f2a6c` | Native stored-ZIP export, inspect and restore; declared 35 fixtures and 24 refusal classes | Carried signatures establish internal consistency; service ownership, complete prior evidence and secret absence are separate |
| [Skills PR #1413](https://github.com/wildcat-finance/skills/pull/1413), merge `0bc39f278e24d8cdd79abed5da16bd5ce81e4c5a` | One verified relocation preserves semantic identity | Nested restore prefixes remain refused; userspace rereads do not exclude later same-account mutation |

Their complete body bytes, including every carryover row, are preserved in
`.hexaemeron/sources/skills-pr-1652.json` and
`.hexaemeron/sources/skills-pr-1413.json`. The old PRs are the specification's
relevant archive/identity baseline, not a claim that no later controller PR
exists. The released prerequisite must establish its own supported version.

The CP-2 source `audit/rounds/fiat-860-restore-identity-continuation-r2.md` was
read directly. Its `S1-R1-01` semantic repair is fixed and guarded;
`S1-R2-01` is a fixed, unguarded generated-count repair; round 3 has no finding
and `Elenchus verdict: null`. Its twelve named Covered risks, exclusions for
service/outer-archive/live-host work, same-account post-read limit and
manifest-evidence lead remain in the preserved source bytes.

The discovered CP-3 sources remain authoritative: the current
`audit/rounds/fiat-861-outer-checkpoint-archive-export-and-restore.md` and the
[original Step 2 rounds](https://github.com/wildcat-finance/skills/blob/70bcb261dec0503344a722174b6a91a1dbc9076e/audit/rounds/fiat-861-outer-checkpoint-archive-export-and-restore.md).
The current source and synopsis were preserved; this study read the PR's
complete audit/carryover account and the three filed service-relevant
follow-ups, not all 376,713 current audit bytes or the original eight rounds.
No claim of full CP-3 audit reading or known-failure inventory completeness is
made. A whole-set synopsis currency command passed in the Skills checkout at
`41116f4f9901b7b70a22db9f42235af65951957e` under its Python 3.14.6; its output
is `.hexaemeron/sources/audit-synopsis-check.txt`. Currency does not establish
that this study read those synopses.

Before Step 2 begins any protocol-dependent edit, read every audit source
applicable to the exact proposed release, preserve each finding/status,
Covered, Not checked, Elenchus verdict and Leads not pursued, and derive the
source-bound inventory with independent expected IDs and real consuming
steps. Refresh against the release rather than treating this scaffold's absent
target inventory as a protocol clean bill. A missing original source, stale
view or unsupported carryover dependency blocks that entry. Known findings
must earn their owning inoculation gate before the affected product work.
Fiat binds inventory admission when it receipts the initial runbook. A later
study amendment cannot manufacture that capture or retrofit inoculation.
Step 2 Entry must establish that the current controller supports admitting the
release-bound inventory for this run. If it does not, stop and continue only
through a supported fresh or separately governed run; retain the scaffold
checkpoint and its original receipts.

Current named carryovers are disposed as follows:

| Carryover | This packet's disposition |
| --- | --- |
| [#1647](https://github.com/wildcat-finance/skills/issues/1647), signing-key diagnostics | Open upstream; bound stderr, return fixed service codes and inject approved public verification keys into each job |
| [#1648](https://github.com/wildcat-finance/skills/issues/1648), destination-name replacement | Open upstream; require a private job parent, no untrusted sibling writer, no-follow staging and deterministic containment tests |
| [#1649](https://github.com/wildcat-finance/skills/issues/1649), local restore concurrency | Open upstream; one job owns one fresh destination; test competing processes without claiming upstream serialization |
| PR #1652 secret-scan-reach, secret-pattern-geometry, secret-scan-member-scope, adjacent-key-markers | Retain finite scanning limits and declared expected failure; bounded decompressed Git-object scanning needs separate service coverage and cannot prove no secrets |
| signer-trust, keyring-platforms, operator-environment, operator-scratch, repository-identity-scope, unbound-origin | Exact enrollment/history, controlled trust injection/environment, private scratch and approved run registration are required; unsupported profiles refuse |
| failed-helper-output, restore-origin-admission, hexadecimal-ref-shape, zip-layout-conservatism | Require every current-attempt zero exit and digest join; preserve upstream layout/ref refusals and untested cases |
| measurement-scope, rounded-expanded-budget, future-package-resolution | Record fresh resource measurements and exact runtime/image pins; historical values are observations, not current results |
| orphan-export-stage, redundant-control-tests, exception-diagnostics, test-temporary-root, refusal-fallback | Preserve as source limits; add service cleanup/redaction/isolation guards where the service opens those paths |
| historical-preamble, historical-amendment-presentation, record-test-coupling, reference-underdescription, phylax-name-heuristic, export-self-check, historical-provenance, historical-colour-failures, pre-loss-audit-custody | Historical evidence retained, not rewritten or represented as new service fixes |
| #1586, #1524, #1130, #1433 from PR #1652 | Existing upstream owners retain runner, design-amendment, census and amendment-diagnostic work; do not duplicate or claim closure |
| CP-2 outer-archive-and-clean-machine-proof | Supplied by CP-3 at its stated bounds; current release compatibility still requires verification |
| CP-2 service-intake-validation-and-publication | Intake/validation here; publication in service issue #2 |
| CP-2 locked-authority-and-signed-receipts, external-run-transition-fence, concurrent-descendant-lineage-and-resolution, reconciliation-revocation-and-recovery-drills, atlas-resume-redraw-or-start-routing | Existing Skills #863 through #867 remain the named owners |

Skills #1673 and #1674 are closed as observed on 2026-09-18. Their prior
inoculation-recovery and CLI-registration failures are not claimed reproduced
or repaired by this service study. Their issue records remain preserved.

External prior art is the specification's provider/standard interface set:
[GitHub App user authorization](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app),
[R2 S3 API](https://developers.cloudflare.com/r2/api/s3/api/),
[DSSE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) and
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md).
These are interface references, not evidence of deployed accounts, provider
conformance or a signer available to this run.

## 3. Constraints, entry gates and non-goals

The exact service starting ref is
`61b8dc4be1587d1c6ef46f2f228833214965e7f1` on `main`.
The managed run uses installed Hexaemeron 1.6.54. The service interpreter is
Python 3.12.13; Skills governance commands use their source's Python 3.14.6.
The observed local platform is Linux 6.8.0-139-generic x86_64 with uv 0.12.13
and Docker server 29.1.3. This records a local host, not the production profile.

The adopted runtime profile is FastAPI/ASGI, psycopg 3, PostgreSQL 16,
Ubuntu 24.04 LTS and pinned gVisor `runsc`. Step 1 locks exact direct/transitive
versions and hashes. The observed Python 3.12.13 slim-bookworm Linux amd64
image digest is
`sha256:6e13e65c55e33adf203d77ee371cf8bf5d81bd4902ef07565721f46bf44917af`;
using it for local scaffold checks does not change the Ubuntu production host
profile or supply a validator sandbox. No runtime or package install floats.

`protocol.lock.json` may be absent during Step 1. Production readiness must
refuse that absence. A draft with invented protocol fields or placeholder
hashes must not stand in for a release pin. The future lock binds repository,
full commit, protocol/artifact, inspector, schema, verifier and corpus digests,
with a separate CP-3 pin when needed.

[Skills #1676](https://github.com/wildcat-finance/skills/issues/1676) is open.
Step 2 Entry requires its released schema/verifier/fixture manifest, adopted
R2/ownership amendments, supported external-custody/relocation profile and the
complete source review described in section 2 before any dependent edit.
The design gate is due at `step:3`, so Step 2 cannot complete without that
proof. This scheduling permits Step 1's checkpoint. Opening a controller step
does not satisfy its Entry. If the prerequisite is still absent after Step 1,
stop at the scaffold checkpoint with issue #1 unfinished.

Always verify the worktree, pins and source digests; use synthetic fixtures;
keep every required negative case; execute the receipted checks; preserve
failed results and bounded coverage. The initial CI, dependency locks and
configuration are ordinary authorized scaffold work.

Ask first before spending, creating cloud accounts/resources/keys, deploying,
changing DNS/access, changing the adopted provider or cross-repository
protocol, or physically removing locked objects. These are outside this run.

Never commit a real archive, observation, credential, deployment value or
private evidence; edit Skills under this service packet; self-enroll a carried
key; run archive-carried code; fetch recorded private paths; execute
replacement/worker/guard commands to repair admission; or report an accepted
checkpoint from this intake-only packet.

Service issue [#2](https://github.com/wildcat-finance/fiat-checkpoints/issues/2)
owns authority copies, replication, signer orchestration and finalization.
Service issue [#3](https://github.com/wildcat-finance/fiat-checkpoints/issues/3)
owns authenticated retrieval, reconstruction and the whole-service demo.
Skills [#863](https://github.com/wildcat-finance/skills/issues/863) owns live
identity/storage/compute/signer deployment and proof. Full frontier/resolution
and public discovery remain Skills #865. None of those owners is discharged
by this study or by a local scaffold.

## 4. Designs and checked selection

The specification already mandates mediated transfers and an isolated
validator. This study compares three declared topologies under those mandates.
The source probe `.hexaemeron/evaluate_design.py` checks the immutable
specification digest, each declaration's transfer/validator choices, and the
number of distinct declared process roles. It executes no service code.

| Candidate | Declared roles | Trade and selection result |
| --- | ---: | --- |
| `mediated-isolated` | 4 | API/coordinator, gateway, trusted stager and credential-free validator; additional interprocess I/O preserves the required trust boundaries |
| `direct-provider` | 3 | Removes the gateway role; direct provider URLs fail the mandated service-mediated transfer gate |
| `in-process-validation` | 2 | Combines API and validator; fewer roles fail the mandated credential-free sandbox gate |

All nine selection commands ran and returned zero with closed
`protasis-design-report/v1` reports. A successful probe can record a false
design-gate value; that removes the candidate. The `declared-process-roles`
metric counts the descriptors and supplies a structural comparison only. It
is not a measurement of memory, latency or deployed processes. The only
candidate surviving both hard gates is `mediated-isolated`; the record uses
`unique-frontier`.

`.hexaemeron/design-evidence.json` contains 3 candidates × 8 criteria, with
9 resolved selection cells and 15 pending conformance cells. The five
required concerns are represented:

| Concern | Evidence due for the selected candidate | Stop |
| --- | --- | --- |
| Correctness | Declared transfer/isolation gates now; actual intake and hostile suites later | `design-lock`; runtime evidence at `integration` |
| Compatibility | Released protocol lock, source review, golden/hostile vectors and supported custody profile | `step:3`, plus Step 2 Entry before any dependent edit |
| Time | Performance suite measures the current valid fixture and asserts validation within 900 seconds | `integration` |
| Space | Declared role count now; measured gateway incremental memory at most 64 MiB per stream later | `design-lock`; runtime evidence at `integration` |
| Recovery | Real migration/restart, sealed-input and stale-fence tests produce no unauthorized intent | `integration` |

Each pending cell names an exact future `python3 scripts/check.py` resolver,
its group, candidate/criterion and report path. Those commands are planned
interfaces and have not run. The runtime report value is a boolean from the
criterion's actual suite; time/space suites must retain measured samples and
assert the named threshold. Passing unrelated tests cannot satisfy them.
The record is checked at `design-lock`; later reports may fill its declared
paths without changing the locked candidate matrix.

The runbook follows the issue's dependency chain: scaffold; pin protocol and
domain; persistence/leases; authentication/endorsement; quarantine upload;
isolated validation; then the intake-validation demo and publication handoff.
These are steps of one intake outcome. The programme already split authority
publication and retrieval into separate issues. The scaffold's registered
research reporter must run real target tests and refuse an absent or empty
suite. Once the product reporter exists, any source/CLI replacement follows
the checked append-only runbook amendment route.

## 5. Risk register

```risk-register
protocol-gap | draft protocol to service implementation | missing released schema verifier fixture or amendment evidence blocks Step 2 dependent edits
actor-confusion | GitHub numeric actor to signed run grant | actor repository run key history and exact upload endorsement agree
grant-replay | contributor to upload gateway | actor attempt expiry size digest lease and idempotency bindings refuse substitutions
resource-exhaustion | admitted request to host reservations | byte stream disk node memory process and time limits hold under concurrency
quarantine-swap | completed object to inspected file | exact read-back and sealed descriptor-bound bytes survive substitution attempts
archive-escape | hostile carrier to validation sandbox | no network host socket credentials hooks shared parents or other-job access
false-inspect-success | inspect result to validation intent | current-attempt restore verify observations reminted identity and authority checks all succeed
signature-coverage | carried keys to approved history | independently derived required commit set matches exact verified signature coverage
prior-evidence | parent and prior records to current policy | released verifier establishes run base ancestry denial and freshness coverage
external-custody | restored source references to dependencies | unsupported carryover replacement and private path dependencies refuse without fetch or execution
stale-result | prior worker output to current lease | job input command exits digests and fencing number bind one attempt
restore-diagnostics | child output to API and logs | fixed public codes and bounded private stderr retain signature refusal without leaking diagnostics
restore-destination | admitted name to later filesystem use | private job parent and unique destination contain the known upstream replacement window
restore-concurrency | workers to imported state | each fresh destination has one owner and deterministic concurrency tests preserve allowed outcomes
premature-authority | validation intent to later publication | intake creates no authority object signature accepted receipt or download success
partial-commit | database and quarantine to restart | transactions outbox and fences recover without inventing a valid intent
source-provenance | mutable dependency or copied spec to build | exact source digest locks report hashes and immutable source bytes remain checked
repository-hygiene | local evidence to public source tree | tracked files contain only code governance and synthetic public fixtures
```

The known upstream issues remain open even if the service's containment cases
pass. A profile that still permits an escape or false identity must stop
admission until its owner fixes the cause.

## 6. Glossary

- `archive_sha256`: digest of every byte of the stored ZIP carrier.
- `controller_manifest_sha256`: the pinned controller's exact manifest digest.
- `snapshot_id`: semantic checkpoint identity; repacking can change the ZIP
  digest while leaving it unchanged.
- Endorsement: the enrolled contributor's signed binding of one submission to
  actor, service/environment, run, identities, length, nonce and expiry.
- Validation intent: immutable handoff of exact input and complete validated
  evidence to service issue #2; it grants no accepted status by itself.
- Fence: a work-lease number that only increases; its stale owner cannot
  advance candidate state.
- Current authority: verified signed run/key/denial inputs under a fresh
  trusted control head, distinct from an archive's carried assertions.
- `intake_closed`: production mode refusing admission until all declared
  deployment and protocol prerequisites exist.

## 7. Source register

The complete adopted source and current GitHub response bytes live under
`.hexaemeron/sources/`. All `.hexaemeron/` paths in this study are
controller-local evidence retained with the run, not promised public files.
Step 1 ships the immutable specification, study and runbook, and a public
source manifest with source URLs, digests and recorded reading limits. It
need not publish raw API responses or other private controller evidence. Every response is a dated observation of that host's
record, not proof that a referenced implementation or test exists.

| Source | Binding used here |
| --- | --- |
| [Service baseline](https://github.com/wildcat-finance/fiat-checkpoints/tree/61b8dc4be1587d1c6ef46f2f228833214965e7f1) | Starting commit and the only two tracked documents |
| [Adopted specification](https://github.com/user-attachments/files/32263127/862-r2-service-specification.md) | SHA-256 `8ee755c1f9e5c29703af30bd08caffb6fad80c8a0990ee0acecebef09b02f541`; exact immutable bytes |
| [Service issue #1](https://github.com/wildcat-finance/fiat-checkpoints/issues/1) | Scope and acceptance criteria; observed open on 2026-09-18 |
| [Skills #1676](https://github.com/wildcat-finance/skills/issues/1676) | Missing authority protocol release; observed open on 2026-09-18 |
| [CP-2 source](https://github.com/wildcat-finance/skills/blob/0bc39f278e24d8cdd79abed5da16bd5ce81e4c5a/audit/rounds/fiat-860-restore-identity-continuation-r2.md) | Directly read audit, retaining findings and exclusions |
| [CP-3 current audit](https://github.com/wildcat-finance/skills/blob/41116f4f9901b7b70a22db9f42235af65951957e/audit/rounds/fiat-861-outer-checkpoint-archive-export-and-restore.md) | Source/synopsis preserved; full source reading deferred to release-bound Step 2 Entry |
| [CP-3 original Step 2 source](https://github.com/wildcat-finance/skills/blob/70bcb261dec0503344a722174b6a91a1dbc9076e/audit/rounds/fiat-861-outer-checkpoint-archive-export-and-restore.md) | Authoritative prior rounds; unread in this scaffold study and required before protocol integration |
| [Protasis](https://github.com/wildcat-finance/skills/blob/41116f4f9901b7b70a22db9f42235af65951957e/plugins/hexaemeron/skills/protasis/SKILL.md) | Installed Hexaemeron 1.6.54 content/design contract |

Source precedence is the adopted contract and accepted amendments, then the
released pinned protocol, then service design/deployment records. Historical
issue/provider drafts supply context. A conflict among the first three stops
the affected work; a service-side compatibility workaround cannot settle it.

## 8. Signals and on-call questions

[Ephoros](https://github.com/wildcat-finance/skills/blob/41116f4f9901b7b70a22db9f42235af65951957e/plugins/hexaemeron/skills/ephoros/SKILL.md)
owns the signal contract. Step 1 records local liveness/readiness and the
reference host; later steps emit bounded events where the following
questions become real:

| Question | Signal and owning step |
| --- | --- |
| Why is this candidate waiting? | Step 3 state/lease transitions, age and fixed retry reason; Step 5 transfer expiry and Step 6 validation outcome |
| Which exact bytes were validated? | Steps 5 and 6 correlate candidate, attempt, job, lease, input digest and bounded result digest in private logs |
| Is authorization current? | Step 4 signed grant/key projection and freshness refusal; Step 6 policy/parent verification status |
| Can the host admit another job? | Steps 3, 5 and 6 expose reserved/used bytes, concurrency, scratch headroom, cleanup lag and sandbox-limit kills |

Logs exclude tokens, authorization headers, archive/observation bodies,
provider URLs and raw subprocess text. Actor/digest values do not become
metric labels. Detailed failure evidence stays private and bounded. No
unattended service or alert is claimed present in Step 1. Later symptom alerts
must point to the operator records named in section 12.

## 9. Trust boundaries and controls

[Phylax](https://github.com/wildcat-finance/skills/blob/41116f4f9901b7b70a22db9f42235af65951957e/plugins/hexaemeron/skills/phylax/SKILL.md)
owns the boundary controls. The specification's capability matrix applies to
this packet's API, upload gateway, staging broker, inspector and quarantine
sweeper. The service does not possess authority-write or signing permission.

The API establishes immutable GitHub numeric identity through the dedicated
login flow. Signed operator approval separately establishes repository/run
scope and contributor key history. Sessions and exact-submission endorsements
cannot enroll their own keys. Each protected request checks current scope;
renames do not change numeric identity.

The gateway reserves quota before admitting exact Content-Length bytes,
rejects ambiguous framing/encoding, streams a hash to exclusive no-follow
staging, commits a unique attempt and fully reads it back. No contributor
receives an R2 credential or direct provider URL. A trusted stager supplies
immutable exact input to an unprivileged network-denied sandbox.

Validation runs inspect, fresh restore, controller verify with observations,
and identity in fixed argv order. Every command needs a current-attempt zero
exit and structured digest/attempt binding. A later successful verify cannot
rescue a failed restore. Approved historical public keys are injected into a
private ephemeral verification context; no private key or agent enters it.
The pinned verifier supplies semantic/manifest calculations and required
signature coverage. Service rules add enrollment, run, parent and policy
checks. No native schema gains a service-only field.

The initial limits are the minimum of service policy and released protocol
caps: 1 GiB carrier, 4,200 entries, 1,300 MiB extracted members, 1 GiB Git bundle
member and 64 MiB other members. Stored ZIP method 0 remains required. Request
JSON is capped at 64 KiB. Quotas reserve both candidates and bytes; upload
start expiry is 15 minutes, with 30-minute duration and 60-second idle limits.
The specification's per-actor/run/global quotas remain binding.

Each validation job has at most 2 vCPUs, 4 GiB memory with swap disabled,
8 GiB scratch, 256 processes, 100,000 filesystem nodes, 300 CPU seconds and
900 wall seconds. Stdout is at most 64 KiB; stderr at most 16 KiB and private.
The supervisor kills the whole sandbox. Missing gVisor containment refuses;
plain subprocess execution cannot stand in for this boundary.

## 10. Performance budget

[Metron](https://github.com/wildcat-finance/skills/blob/41116f4f9901b7b70a22db9f42235af65951957e/plugins/hexaemeron/skills/metron/SKILL.md)
owns measurement. Step 1 records the host and performs no performance
optimization. No service baseline, memory result or latency claim exists yet.

Before intake validation can integrate,
`./scripts/benchmark.sh --profile local --corpus protocol.lock.json` must
record runtime/image/kernel and fixture digests, command, concurrency,
repetitions, raw samples, median/p95, CPU, peak RSS, scratch and request counts.
The performance suite asserts gateway incremental memory at most 64 MiB per
stream, no buffering proportional to carrier size, metadata p95 at most
500 ms excluding identity-provider calls, and the current valid fixture's
validation within 900 seconds. Section 9's whole-job ceilings also apply.

The 111,860,548-byte and 100,790,501-byte carriers in the adopted specification
are historical observations. Use the actual released corpus and record its
size; do not substitute the old S3 64/256/512 MiB budgets. Time and space design
reports carry true only after the named measurements and threshold assertions
succeed. Provider throughput, gateway cost and production capacity remain
Skills #863 evidence.

## 11. Failure, recovery and guards

[Elenchus](https://github.com/wildcat-finance/skills/blob/41116f4f9901b7b70a22db9f42235af65951957e/plugins/hexaemeron/skills/elenchus/SKILL.md)
owns diagnosis and guard evidence. Missing protocol or freshness, malformed or
unsupported records, failed command/identity/signature joins, exhausted
resources and stale leases prevent validation intent. Dependency outages
remain typed unavailability. A resource kill alone does not classify the
archive as malicious.

Public responses distinguish bounded input refusal, denied scope,
concurrency conflict and dependency failure while hiding unauthorized object
existence. Unexpected child failures become fixed service codes. Preserve the
pinned protocol code only when the named producer actually emitted it.

PostgreSQL coordinates candidates, attempts, validation jobs, reservations and
outbox work with uniqueness constraints, transactions and compare-and-swap
state/fence checks. Retry owns the same sealed bytes or revalidates a fresh
copy. Stale workers cannot advance an intent. Startup and restart invalidate
unproved temporary state; no SQL-only flag creates authority.

The runbook declares each step's exact test command, one `{report}` operand,
`unittest-json-v1` format and distinct report path. The reporter must refuse
zero tests. An observed failure is preserved and reproduced before repair;
its guard must fail without the fix. A check run on different bytes, a stale
report, a changed registered runner or an absent hostile corpus supplies no
receipt. This study creates no Elenchus verdict or controller receipt.

## 12. Decisions and their homes

[Hypomnema](https://github.com/wildcat-finance/skills/blob/41116f4f9901b7b70a22db9f42235af65951957e/plugins/hexaemeron/skills/hypomnema/SKILL.md)
owns placement. The baseline has one substrate record and no ADR numbering
scheme. Preserve that record with a dated adopted amendment. New
cross-service design records use `docs/decisions/drafts/` and stable names;
integration assigns numbers through the governed tool.

Step 1 creates `docs/decisions/drafts/isolate-checkpoint-intake.md`, recording
`mediated-isolated`, both rejected alternatives, the trust/cost trade and the
scaffold-only release boundary. The following declaration is planned for the shipped study and names the
record Step 1 must create. Its ordinary pointer lint passes now; the explicit
Hypomnema design-bridge check must wait for that real record:

```design-bridge
schema | hypomnema-design-bridge/v1
decision | mediated-isolated
record | docs/decisions/drafts/isolate-checkpoint-intake.md
```

Later expensive choices belong in
`docs/decisions/drafts/pin-authority-protocol.md`,
`docs/decisions/drafts/coordinate-intake-with-fenced-leases.md` and
`docs/decisions/drafts/isolate-validator-trust.md`. The protocol record is
written only after the released contract is available. Each records rejected
alternatives and source bindings, not a guessed reason for an upstream choice.

Operator records belong under `docs/runbooks/` for candidate stalls,
validation failures, policy freshness and quarantine cleanup. Each supplies
What fired, First check and Who to wake. README carries the exact local start,
check and scope/blocked-state commands. Interface schemas and docstrings name
inputs, results and fixed failures next to the interface.

After scaffold delivery, the durable checkpoint must say that Step 1 is
complete and issue #1 remains open. Protocol/source evidence, intake behavior,
resource measurements, upstream containment and the final local demonstration
remain unproved until their named steps run. No deployment, acceptance or
whole-service completion follows from this study.
