# Authenticated checkpoint intake and isolated validation

Assuming, unless corrected (the study proceeds on these):

1. The adopted specification is fixed at SHA-256
   `8ee755c1f9e5c29703af30bd08caffb6fad80c8a0990ee0acecebef09b02f541`, and
   only its implementation steps 1 to 6 and sections 7 to 11 bind this packet.
   Its "proposed" status line is historical; issue #1 records the adoption.
2. The authority protocol is consumed from Skills commit
   `685158cdc5407ca5559bf9ef4a021d664e764ece`, the Skills `main` this run's
   controller pins. The release that closed Skills #1676 is
   `d9b984701999622ae72ad89a5373f26a435ad064`; both trees pass the released
   `release` check. The later commit adds the Linux network-denial backend and a
   verifier process-group repair under the same `checkpoint-authority/v1`
   protocol.
3. Every service role runs CPython 3.14.6, the interpreter the released lock
   names in `tools.python`, not the specification's 3.12 reference profile. The
   specification ranks a released protocol above service records (its section
   2), calls its runtime a "proposed deployment profile", and issue #1 tells a
   newer protocol pin to keep the prerequisite's supported profile. Section 4
   selects this mechanically. Correct this if 3.12 is meant to be binding.
4. The validator, PostgreSQL and every sandbox check run on Linux: Ubuntu
   24.04 x86_64 in hosted CI and a local Linux VM or container on a developer
   Mac. The development host is macOS 26.5.1 arm64 with colima installed but
   not running, and no PostgreSQL, gVisor or Bubblewrap.
5. Authority records used in tests are synthetic and signed with keys the tests
   generate. The released public fixtures are consumed by digest only.

## 1. Problem statement and demo path

A contributor who holds an operator-approved key for one run needs to upload
one checkpoint archive and get back a validation result bound to the exact
bytes the service sealed. This packet is `S-862A`,
[service issue #1](https://github.com/wildcat-finance/fiat-checkpoints/issues/1).
It ends at a trusted validation-evidence object and an immutable publication
intent. It creates no accepted checkpoint, receipt, signature, authority object
or download. Publication belongs to
[issue #2](https://github.com/wildcat-finance/fiat-checkpoints/issues/2) and
retrieval to [issue #3](https://github.com/wildcat-finance/fiat-checkpoints/issues/3).

A working prototype here means the real HTTP API, PostgreSQL migrations,
bounded upload gateway and isolated validator run locally against synthetic
authority fixtures. One authorized upload yields one publication intent, and
each named hostile case yields a fixed refusal and no intent. The demo path is:

```sh
./scripts/demo.sh --scenario intake-validation --profile local
```

It runs a wrapper over a `python3` entry point. It must record the source,
protocol, runtime, image and fixture digests, each command's exit, the report
hashes and the observed refusals. It must show that a wrong actor, changed
bytes, a forged carried identity, a revoked scope and unavailable isolation
each produce no intent and no authority object. Those observations cover the
cases named; they do not prove every input safe. The whole-service
`--scenario end-to-end` demonstration stays with issue #3.

Success criteria, each settled by a command the runbook must declare:

| Issue criterion | Command |
| --- | --- |
| Announce, endorsement, upload, complete and status enforce actor, run, key, bounds and idempotency without cross-run leakage | `./scripts/check.sh --group auth,upload` |
| Wrong, oversized, truncated or extra bytes, replayed or concurrent grants, slow streams, expiry, disk exhaustion and quarantine substitution cannot yield an intent | `./scripts/check.sh --group upload,quarantine` |
| The real pinned inspect, restore, verify and identity commands run on the staged bytes; a self-consistent but unauthorized archive fails | `./scripts/check.sh --group validation` |
| Sandbox network, credential, hook and config, other-job, path-swap and resource-limit cases leave nothing behind; the 35 upstream fixture ids keep their producer, inspect or restore stage | `./scripts/check.sh --group sandbox` and `./scripts/reject-case.sh --all` |
| The seven named groups pass with fixture digests and bounded reports | `./scripts/check.sh --group protocol,domain,auth,upload,quarantine,validation,sandbox` |
| Migration, restart and lease tests and measured memory, disk and job ceilings pass; the next packet gets a pinned evidence contract, one example intent and every stable refusal | `./scripts/check.sh --group persistence,concurrency,performance` and `./scripts/benchmark.sh --profile local --corpus protocol.lock.json` |
| Production startup refuses absent pins, test trust roots and unavailable isolation | `./scripts/check.sh --group scaffold` |

The shell wrappers are what the issue names. Each calls one registered
`python3` runner, because a Fiat Exit can only name such a runner.

## 2. Prior art, audit sources and carried work

**Target.** The run base contains `README.md` and
`docs/deployment-substrate.md` only. It has no code, tests, audit record or
agent instructions. The target has no merged pull request; the one open pull
request, [#4](https://github.com/wildcat-finance/fiat-checkpoints/pull/4), is
the inherited scaffold below and is not in this run's base.

The substrate record chooses R2, content-addressed keys, a second Cloudflare
account and a derived database. Its presigned-transfer wording, its
runtime-deletion claim and its open signer and jurisdiction sections predate
the specification. Step 1 keeps its bytes and appends a dated correction
pointing at specification sections 4.2, 6 and 9.

**Inherited run.** An earlier contributor ran Fiat on this issue on
2026-09-18 and stopped after Step 1. Its controller state is gone. Its
artefacts are on branch
`fiat/1-authenticated-checkpoint-intake-and-isolated-v-step-1-scaffold-the-isolated-service`
at `f81f119b1984c9379b6a4405b1492ab4a5e007fa`. They were read from that
commit and carry no receipt here.

| Inherited item | Decision in this study |
| --- | --- |
| `docs/study.md`, 480 lines | Reused as the main input. Its trust boundaries, limits, risk ids, glossary, carryover table and decision homes are confirmed against the specification and kept. |
| Protocol gate at Step 2 | Changed. Skills #1676 closed on 2026-09-20, so Step 2 consumes a released lock instead of halting. |
| Service interpreter 3.12.13 | Changed to 3.14.6. The released lock pins 3.14.6 and section 4 selects it. |
| `mediated-isolated` topology | Kept, and rechecked in section 4 as the `validator-isolated` gate. |
| Design record of 3 candidates by 8 criteria | Replaced. Its selection probe `.hexaemeron/evaluate_design.py` was controller-local and is lost, so section 4 measures again. |
| Scaffold: `scripts/check.py`, `scripts/check.sh`, `scripts/serve.py`, `config/`, `containers/api.Dockerfile`, locks and `.github/workflows/check.yml` | Step 1 may reuse this code. It must re-pin for 3.14.6 and re-author every commit under this run's identity. The inherited container base image digest is for 3.12.13 and cannot be reused. |
| `docs/decisions/drafts/isolate-checkpoint-intake.md` | Rewritten at the same path to record the runtime decision as well. |
| Step 1 audit round: 0 findings, `Elenchus verdict: null` | Read directly; it is 15 lines. Its one lead, that Starlette's HTTPX test adapter is deprecated, is carried to Step 1 as a dependency check. |

**Upstream prior art.** The last two run-level merges that changed the
checkpoint authority surface in Skills are
[PR #1784](https://github.com/wildcat-finance/skills/pull/1784) (merge
`d9b984701999622ae72ad89a5373f26a435ad064`, closes #1676) and
[PR #1800](https://github.com/wildcat-finance/skills/pull/1800) (merge
`daa382ec73dda581e684f9d026228f7b81bd6035`, Linux and macOS sandboxes). Both
Carried forward sections were read in full. The released protocol already
ships most of section 10's sequence as a library: `verify_native` runs the four
native commands in fixed order, `coverage.py` derives the required signed
commit set, `TrustPrefix` checks enrollment, grants and endorsements, and
`parents.py` joins parent links. The service calls these and does not
reimplement them.

**Audit sources.** `audit_synopsis.py --check .` ran at the pinned Skills tree
and exited 0 with all 113 committed views current, so the five in-scope
synopses below are verified reading views. They were read by extracting every
round heading, finding row, `Elenchus verdict` and `Leads not pursued` line,
not in full. The authoritative sources were not read in full.

| Source (Skills, at the pin) | View read | What it leaves open for this packet |
| --- | --- | --- |
| `audit/rounds/fiat-1676-publish-checkpoint-authority-protocol-and-r.md` | synopsis | Nothing open. S2-R1-01, S4-R1-01, S4-R1-02, S5-R1-01 and S5-R1-02 are fixed. Steps 2, 4 and 5 kept an `inconclusive` Elenchus verdict. |
| `audit/rounds/fiat-1794-support-macos-and-linux-checkpoint-sandboxe.md` | synopsis | Nothing open. S1-R1-01, S2-R1-01 and S2-R1-02 are fixed; the AppArmor cause of the first hosted failure is unconfirmed. |
| `audit/rounds/fiat-1755-repair-checkpoint-key-marker-false-positive.md` | synopsis | No findings. Leads keep #1647, #1648, #1649 and #1756 with their owners and name issue #1676 as owning service admission. |
| `audit/rounds/fiat-861-outer-checkpoint-archive-export-and-restore.md` | synopsis | S1-R3b-01, S1-R6-03, S2-R1b-01, S2-R1b-02 and S4-R1-01 are last recorded open. All concern CP-3's own records except S2-R1b-01: the truncated-key-block rule refuses a member with a matching key header and footer and nothing between them. The service keeps that refusal as an upstream protocol code. |
| `audit/rounds/fiat-860-restore-identity-continuation-r2.md` | synopsis | S1-R1-01 guarded; S1-R2-01 fixed but `unguarded`; round 3 has no finding. |

The target has no audit source at its base, and the inherited round lives on
an unmerged branch. This study therefore carries **no known-failure
inventory**. The open upstream items name failures in Skills code, which this
packet may not edit. The service answers them with its own containment tests
in Step 6, not by inoculating target code.

**Carried items and their disposition here.**

| Item | Owner | This packet |
| --- | --- | --- |
| `native-local-errors`, carried by #1784 to this issue: a caller-owned malformed native-result exception path | here | Step 6 wraps `verify_native` and every parser so that any exception maps to fixed `validation_failed`. A test feeds malformed native output. |
| No aggregate native descendant CPU, memory, process or filesystem limit in the protocol (#1784) | here | Step 6's supervisor enforces the specification's whole-job limits. |
| [#1647](https://github.com/wildcat-finance/skills/issues/1647) signing-key diagnostics, [#1648](https://github.com/wildcat-finance/skills/issues/1648) destination name, [#1649](https://github.com/wildcat-finance/skills/issues/1649) restore concurrency, all open | Skills | Contained, not fixed: private stderr, a private job parent, one owner per fresh destination, with tests. |
| `service-intake` from #1800 | here | This packet. |
| [#873](https://github.com/wildcat-finance/skills/issues/873) disposable worker, [#1541](https://github.com/wildcat-finance/skills/issues/1541) runner verdict | Skills | Not taken. The service sandbox is its own control; an `inconclusive` Elenchus verdict from #1541 is recorded, not reclassified. |
| Production signer, journal, keys, storage and activation | [Skills #863](https://github.com/wildcat-finance/skills/issues/863) | Non-goal. |
| Frontier, fork resolution, public discovery | [Skills #865](https://github.com/wildcat-finance/skills/issues/865), #867 | Non-goal; any such request returns `capability_not_enabled`. |
| Scaffold lead: Starlette HTTPX test adapter deprecated | here | Step 1 re-checks it at the new pins. |

[Skills #1673](https://github.com/wildcat-finance/skills/issues/1673) and
[#1674](https://github.com/wildcat-finance/skills/issues/1674), which the
issue's delivery-map comment named as blocking, closed on 2026-09-16.

## 3. Constraints and non-goals

**Starting point.** Target `wildcat-finance/fiat-checkpoints`, `main` at
`61b8dc4be1587d1c6ef46f2f228833214965e7f1`. Controller `hexctl` from
Hexaemeron 1.6.88, ledger version `fiat-v6.76.1`.

**Protocol pins**, all taken from the released `release` check at the
authority commit and reproduced by the resolver in section 4:

| Pin | Value |
| --- | --- |
| Authority source commit | `685158cdc5407ca5559bf9ef4a021d664e764ece` |
| Release manifest SHA-256 | `fb24ac3d2e9875a11c37c2ebcdb6ef76fd3dc6a440f27bfe2c8070341dc7069c` |
| Artifact SHA-256 | `3b67ca2c0e474f3d2cc67240a712cd806d57f1f03354726400743d770d964615` |
| Schema set SHA-256 | `b94bae8b24bd56c233cb10bc6b295d07985c8ad6245f26cff9b8abbc7612fe7d` |
| Verifier SHA-256 | `de7774287ce7cb459608ddc56a68d5cb7f94ad0d5f17fc127946e2498324c149` |
| Fixture corpus SHA-256 | `1a259027b38040f3472cf00599aa0eb35b0c02721f47c41782223819bb175a62` |
| Native source commit and profile | `1d4e4eebcba1825d0eb3192bf08a6c509bdc0d74`, `native-1d4e4eeb-openpgp-v1` |
| Native executable SHA-256 | `326817a508a2d0be382e8e44071ec1d5957411a9cb6091764d7a33e9e032ff30` |
| Tools | Python 3.14.6; cosign 3.1.3, linux-amd64 asset SHA-256 `4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71` |

The release commit `d9b98470` differs only in its verifier digest
(`358f4160d5c401fde67639dcd7f3bd7e462cf583bfce2fac0b55dc0202adc49a`), its
fixture and documentation digests, and release manifest
`b3bc5d5359765c6fa8e1b392419875f097950ac147770c03580b8dbda3b93d62`; its schema
set and native pins are identical. The service lock is the released example
lock with `authority.source_commit` set to the authority commit. The released
`lock` command accepts it under both interpreters. The validator image holds
two read-only trees: the authority tree and the native source tree, whose 238
profile files `NativePin.check` hashes on every attempt. Neither tree is
fetched at runtime or from a mutable reference.

**Runtime.** CPython 3.14.6 for every role. FastAPI, psycopg 3 and uvicorn
at the inherited pins (`fastapi==0.141.1`, `psycopg[binary]==3.3.6`,
`uvicorn==0.53.0`) resolve to 15 hashed manylinux x86_64 wheels under 3.14.6.
PostgreSQL 16. The validator sandbox is gVisor `runsc` on Linux x86_64; Step
6 Entry pins its release and digest after measuring it on that host. The
Skills test dependency lock names versions without hashes, so Step 2 must
hash-lock any test dependency it adopts. uv is pinned in Step 1; the inherited
scaffold used 0.12.13 and this host has 0.12.5.

**Host facts.** On this macOS arm64 host, the released native criterion
ran 74 cases under 3.14.6 and failed 2 integration cases. Its tool pin refuses
Apple's `/usr/bin/git`, which carries 78 hard links (`native-file-limit-or-kind`).
A single-link copy then failed at `native-command-failed`. The released
native evidence is Linux, so native conformance is scheduled inside the Linux
validator image.

**Identity.** Every commit in this run has author and committer
`Dr Laurence E. Day <laurence@wildcat.finance>` and a valid signature. No
Shoggoth identity, bot login or provenance trailer appears in any commit,
pull request or record.

**Always.** Run the step's checks on the committed tree before each commit.
Run Imprimatur and the Hypomnema check on every shipped document. Use
synthetic fixtures generated in ignored temporary paths. Keep every required
negative case. Record a measurement before any performance change. Verify the
protocol trees against the lock before use.

**Ask first.** Adding a runtime dependency beyond those named here. Changing
the protocol pin or interpreter. Changing a storage layout after Step 3
ships it. Widening any trust boundary in section 9. Touching another
repository.

**Never.** Commit a real archive, observation, credential, account id,
deployment value or private path. Edit Skills from this packet. Self-enroll a
carried key. Run archive-carried code, hooks or tests to decide admission.
Fetch a recorded private path. Execute a replacement, worker or guard command
to make admission pass. Report an accepted checkpoint. Provision
infrastructure or configure a live cloud account or GitHub App (Skills #863).
Push from a worker.

**Non-goals.** Authority copies, replication, signer orchestration and
finalization (issue #2). Retrieval, rebuild and the end-to-end demo (issue
#3). Live identity, storage, compute and signer (Skills #863). Lineage,
frontier and public discovery (Skills #865, #867).

## 4. Designs and checked selection

The specification fixes mediated transfer. Direct provider URLs are
not drawn again: its sections 4.2 and 9 replace them explicitly, and the
inherited study eliminated them. What the released protocol leaves open is
where protocol code runs and on which interpreter. Four constructions are
compared:

| Candidate | Construction | Trade |
| --- | --- | --- |
| `isolated-pinned-runtime` | API, gateway, stager and a credential-free sandboxed validator, all on 3.14.6; API and validator import the pinned protocol tree | One interpreter everywhere; departs from the specification's 3.12 reference |
| `isolated-split-runtime` | Same roles; API, gateway and stager on 3.12.13; every protocol check delegated to 3.14.6 verifier and validator processes | Keeps 3.12 for the web tier; a second interpreter and an extra local process hop for endorsement checks |
| `isolated-reference-runtime` | Same roles, all on 3.12.13 including protocol and native code | Follows the reference profile; runs the protocol on an interpreter its release does not name |
| `in-process-validation` | API on 3.14.6 runs the native commands itself | Fewest roles; hostile archive code shares a process with API credentials |

The resolver `.hexaemeron/design/resolve.py` reads the role declarations in
`.hexaemeron/design/candidates.json`. It then extracts the authority commit
with `git archive` and runs the released `release` check 5 times under each
interpreter, recording wall time and peak child RSS. It runs the released
`lock` check on `.hexaemeron/design/protocol.lock.json`, and resolves
`.hexaemeron/design/runtime-deps.in` to hashed wheels with
`uv pip compile --only-binary :all:` for `x86_64-manylinux_2_28`. It wrote 28
closed `protasis-design-report/v1` reports, all with exit 0, and the raw
samples in `.hexaemeron/design/reports/measurements.json`.

| Criterion | Kind | pinned | split | reference | in-process |
| --- | --- | ---: | ---: | ---: | ---: |
| `validator-isolated` | gate | true | true | true | **false** |
| `runtime-wheels-resolve` | gate | true | true | true | true |
| `released-lock-verifies` | gate | true | true | true | true |
| `lock-interpreter` | gate | true | true | **false** | true |
| `interpreter-pins` | min, count | 1 | 2 | 1 | 1 |
| `protocol-check-time` | min, ms | 166 | 166 | 173 | 166 |
| `protocol-check-rss` | min, bytes | 34,930,688 | 34,930,688 | 36,814,848 | 34,930,688 |

`isolated-reference-runtime` fails `lock-interpreter`, and
`in-process-validation` fails `validator-isolated`. Of the two survivors, both
run the protocol on the same 3.14.6 binary, so their time and space values
are the same measurement. `isolated-pinned-runtime` needs one interpreter
against two, so it dominates, and the record selects it under
`unique-frontier`. The time and space metrics measure the released release
check, a fixed protocol workload; they say nothing about service latency. The
split candidate's extra process hop was not measured, and measuring it would
only widen its loss.

Conformance evidence is pending for every candidate and checked for the
selected one at its stop point. Each resolver is
`python3 scripts/check.py design --candidate <id> --criterion <id> --out .hexaemeron/design/reports/<id>-<id>.json`,
an interface Step 1's runner must provide:

| Criterion | Concern | Gate | Due |
| --- | --- | --- | --- |
| `protocol-lock-shipped` | compatibility | shipped `protocol.lock.json` passes the released `lock` check and startup refuses without it | `step:3` |
| `restart-recovery` | recovery | migration, restart and stale-fence tests produce no unauthorized intent | `step:4` |
| `native-sequence-linux` | correctness | released native criterion passes all cases inside the validator image | `integration` |
| `intake-hostile-suites` | correctness | the seven groups and `reject-case --all` pass | `integration` |
| `validation-wall-time` | time | current valid fixture validates in at most 900,000 ms | `integration` |
| `gateway-stream-memory` | space | gateway incremental memory at most 67,108,864 bytes per stream | `integration` |

The record is `.hexaemeron/design-evidence.json`, 4 candidates by 13
criteria: 28 resolved and 24 pending cells. The `design-lock` check exits 0.

**Build order.** Scaffold; pin protocol and domain; persistence and leases;
authentication and endorsement; bounded quarantine upload; isolated
validation; then the intake-validation demonstration. Each depends on the one
before. They are steps of one outcome, since issues #2 and #3 already hold the
separable deliveries.

## 5. Risk register

```risk-register
protocol-gap | released protocol to service code | lock, release and native pins verify before any protocol-dependent code runs and a mismatch refuses startup
protocol-tree-drift | read-only authority and native trees to validator | each attempt rechecks the release components and the 238 native profile files and refuses on any change
actor-confusion | GitHub numeric actor to signed run grant | actor, repository, run, key history and exact upload endorsement agree
grant-replay | contributor to upload gateway | actor, attempt, expiry, size, digest, lease and idempotency bindings refuse substitutions
resource-exhaustion | admitted request to host reservations | byte stream, disk, node, memory, process and time limits hold under concurrency
quarantine-swap | completed object to inspected file | exact read-back and sealed descriptor-bound bytes survive substitution attempts
archive-escape | hostile carrier to validation sandbox | no network, host socket, credential, hook, shared parent or other-job access
aggregate-limits | native descendants to host | the supervisor enforces whole-job CPU, memory, process, node and scratch ceilings the protocol does not
false-inspect-success | inspect result to validation intent | current-attempt restore, verify, observations, reminted identity and authority checks all succeed
native-local-errors | native result to service code | any malformed native output or exception becomes a fixed refusal with no traceback and no intent
signature-coverage | carried keys to approved history | the released coverage derivation matches exact verified signature coverage
prior-evidence | parent and prior records to current policy | the released verifier establishes run, base, ancestry, denial and freshness coverage
external-custody | restored source references to dependencies | unsupported carryover, replacement and private path dependencies refuse without fetch or execution
host-tool-identity | pinned python, git and gpg executables to the native adapter | tool digests and link counts match the image and a mismatch refuses
stale-result | prior worker output to current lease | job input, command exits, digests and fencing number bind one attempt
restore-diagnostics | child output to API and logs | fixed public codes and bounded private stderr keep signature refusals without leaking diagnostics
restore-destination | admitted name to later filesystem use | a private job parent and unique destination contain the known upstream replacement window
restore-concurrency | workers to imported state | each fresh destination has one owner and concurrency tests keep the allowed outcomes
premature-authority | validation intent to later publication | intake creates no authority object, signature, accepted receipt or download success
partial-commit | database and quarantine to restart | transactions, outbox and fences recover without inventing a valid intent
source-provenance | dependency locks and copied specification to build | exact digests, hash-locked wheels and immutable source bytes stay checked
repository-hygiene | local evidence to public source tree | tracked files hold only code, governance and synthetic public fixtures
```

The three upstream issues stay open even when the service's containment tests
pass. A profile that still permits an escape or a false identity stops
admission until the owner fixes the cause.

## 6. Glossary

- `archive_sha256`, called `outer_sha256` by the protocol: digest of every byte of the stored ZIP carrier.
- `controller_manifest_sha256`: the pinned controller's manifest digest, over its canonical JSON plus one LF.
- `snapshot_id`: semantic checkpoint identity; repacking can change the ZIP digest and leave it unchanged.
- Authority tree: the Skills tree at the authority commit, mounted read-only.
- Native tree: the Skills tree at the native source commit that `verify_native` executes.
- Endorsement: the enrolled key's signed binding of one submission to actor, service, run, the three digests, length, nonce and expiry.
- Validation intent: immutable handoff of exact input and complete evidence to issue #2; it grants no accepted status.
- Fence: a lease number that only increases; a stale owner cannot advance state.
- `intake_closed`: production mode that refuses admission until every declared prerequisite exists.

## 7. Sources

| Source | Binding |
| --- | --- |
| [Service base](https://github.com/wildcat-finance/fiat-checkpoints/tree/61b8dc4be1587d1c6ef46f2f228833214965e7f1) | Starting commit |
| [Service issue #1](https://github.com/wildcat-finance/fiat-checkpoints/issues/1) | Scope 1 to 6 and acceptance criteria; open on 2026-09-29 |
| [Adopted specification](https://github.com/user-attachments/files/32263127/862-r2-service-specification.md) | SHA-256 `8ee755c1f9e5c29703af30bd08caffb6fad80c8a0990ee0acecebef09b02f541`, verified on download on 2026-09-29 |
| [Inherited artefacts](https://github.com/wildcat-finance/fiat-checkpoints/tree/f81f119b1984c9379b6a4405b1492ab4a5e007fa) | Prior study, runbook, scaffold and audit round |
| [Skills #1676](https://github.com/wildcat-finance/skills/issues/1676) | Closed 2026-09-20 by PR #1784 |
| [Protocol reference](https://github.com/wildcat-finance/skills/blob/685158cdc5407ca5559bf9ef4a021d664e764ece/plugins/hexaemeron/skills/fiat/references/checkpoint-authority.md) | Records, signatures, native adapter, replay, release and limits |
| [Release guide](https://github.com/wildcat-finance/skills/blob/685158cdc5407ca5559bf9ef4a021d664e764ece/docs/checkpoint-authority/release.md) | Lock, verifier operands and demonstration |
| [Example lock](https://github.com/wildcat-finance/skills/blob/685158cdc5407ca5559bf9ef4a021d664e764ece/docs/checkpoint-authority/protocol.lock.json) | Source of the service lock |
| [Archive reference](https://github.com/wildcat-finance/skills/blob/685158cdc5407ca5559bf9ef4a021d664e764ece/plugins/hexaemeron/skills/fiat/references/checkpoint-archive.md) | CP-3 carrier, inspect and restore contract |
| [PR #1784](https://github.com/wildcat-finance/skills/pull/1784), [PR #1800](https://github.com/wildcat-finance/skills/pull/1800) | Carried forward sections |
| [Protasis](https://github.com/wildcat-finance/skills/blob/685158cdc5407ca5559bf9ef4a021d664e764ece/plugins/hexaemeron/skills/protasis/SKILL.md) | This study's content and design contract |

Source precedence is the specification's: adopted contract, then the released
pinned protocol, then service records. An unresolved conflict among those
three stops the affected step.

## 8. Signals and on-call questions

[Ephoros](https://github.com/wildcat-finance/skills/blob/685158cdc5407ca5559bf9ef4a021d664e764ece/plugins/hexaemeron/skills/ephoros/SKILL.md)
owns the signal contract. Nothing runs unattended until #863 deploys it, but
the service is built to, so its events ship with the code that causes them:

| Question | Signal and owning step |
| --- | --- |
| Why has this candidate stopped? | Step 3 state and lease transitions with age and fixed retry reason; Step 5 transfer expiry; Step 6 validation outcome |
| Which exact bytes were validated? | Steps 5 and 6 correlate candidate, attempt, job, lease, input digest and result digest in private logs |
| Is authorization current? | Step 4 grant and key projection with freshness refusals; Step 6 parent and policy verification status |
| Can the host take another job? | Steps 3, 5 and 6 report reserved and used bytes, concurrency, scratch headroom, cleanup lag and sandbox kills |

Logs never carry tokens, authorization headers, archive or observation bodies,
provider URLs or raw subprocess output. Actor and digest values never become
metric labels. Alerts that later point at these signals name the operator
records in section 12.

## 9. Trust boundaries and controls

[Phylax](https://github.com/wildcat-finance/skills/blob/685158cdc5407ca5559bf9ef4a021d664e764ece/plugins/hexaemeron/skills/phylax/SKILL.md)
owns the controls. The specification's capability matrix (section 6) applies
to the API, gateway, stager, validator and sweeper. No role here holds
authority-write or signing permission.

- **Identity.** The API takes the immutable numeric user id from the login
  exchange. Operator-signed records alone set repository, run and key history,
  checked through the released `TrustPrefix`. A carried key never enrolls
  itself.
- **Transfer.** The gateway reserves quota first, then admits an exact
  Content-Length with no encoding and streams through a counter and SHA-256
  into an exclusive no-follow file. It commits one attempt and reads it back
  in full. No contributor receives a provider credential or URL.
- **Validation.** The stager hands immutable bytes to a network-denied gVisor
  sandbox. Inside it, `verify_native` runs inspect, fresh restore, verify with
  observations and identity; every command needs a current-attempt zero exit.
  A later verify cannot rescue a failed restore. Only approved historical
  public keys enter a per-job keyring.
- **Protocol trees.** Read-only, lock-verified, never fetched at runtime.
  Tool executables are pinned by digest, and a hard-linked or substituted tool
  refuses.
- **Limits.** The lower of service policy and protocol caps: 1 GiB carrier,
  4,200 entries, 1,300 MiB expanded, 1 GiB bundle member, 64 MiB other member,
  stored method 0 only, 64 KiB request JSON. The specification's quotas,
  15-minute capability, 30-minute stream and 60-second idle limits apply. Each
  job gets 2 vCPUs, 4 GiB memory without swap, 8 GiB scratch, 256 processes,
  100,000 filesystem nodes, 300 CPU seconds and 900 wall seconds. Stdout is
  capped at 64 KiB and private stderr at 16 KiB. The native adapter's own
  120-second per-command and 900-second attempt limits also hold.

Missing gVisor containment refuses; a plain subprocess cannot stand in for it.

## 10. Performance budget

[Metron](https://github.com/wildcat-finance/skills/blob/685158cdc5407ca5559bf9ef4a021d664e764ece/plugins/hexaemeron/skills/metron/SKILL.md)
owns measurement. No service measurement exists yet. Step 6 and the final
step run:

```sh
./scripts/benchmark.sh --profile local --corpus protocol.lock.json
```

It records hardware, kernel, sandbox, runtime, image and fixture digests,
command, concurrency, repetitions, raw samples, median and p95, CPU, peak RSS,
scratch peak and request counts. Asserted ceilings: no buffering in
proportion to carrier size; gateway incremental memory at most 64 MiB per
stream; metadata p95 at most 500 ms excluding identity-provider calls; the
current valid fixture validated in at most 900 seconds. The last two are the
design record's `gateway-stream-memory` and `validation-wall-time` gates. The
111,860,548-byte and 100,790,501-byte carriers are historical observations;
the protocol reference records that the larger one lacks observation bindings
and its observation precondition returns `FOB001`. Use
the released corpus at its actual size. Provider throughput and cost remain
#863 evidence.

## 11. Fail-closed posture and guards

[Elenchus](https://github.com/wildcat-finance/skills/blob/685158cdc5407ca5559bf9ef4a021d664e764ece/plugins/hexaemeron/skills/elenchus/SKILL.md)
owns diagnosis and the guard rule. Missing pins or freshness, malformed or
unsupported records, a failed command, identity or signature join, an
exhausted resource and a stale lease each prevent an intent. Dependency
outages stay typed unavailability. A resource kill does not by itself mark
an archive malicious. Unexpected exceptions become fixed service codes. A
protocol code passes through only when the named producer emitted it.

Each runbook step declares one Elenchus command with a single `{report}`
argument, `unittest-json-v1` format and a distinct report file. The runner
refuses zero tests and absent groups. An observed failure is kept and
reproduced before any repair, and its guard must fail without the fix. The
native criterion may return an Elenchus verdict of `inconclusive` for the
upstream reason in #1541; such a verdict is recorded as observed. No known-failure
inventory applies (section 2).

## 12. Decisions and their homes

[Hypomnema](https://github.com/wildcat-finance/skills/blob/685158cdc5407ca5559bf9ef4a021d664e764ece/plugins/hexaemeron/skills/hypomnema/SKILL.md)
owns placement. The base has one substrate record and no numbering scheme.
Decision records live under `docs/decisions/drafts/` with stable names, and
integration assigns numbers.

Step 1 writes `docs/decisions/drafts/isolate-checkpoint-intake.md`. It records
`isolated-pinned-runtime`, the three eliminated candidates with their failing
gate or dominated metric, the departure from the 3.12 reference profile, and
the two pinned Skills trees:

```design-bridge
schema | hypomnema-design-bridge/v1
decision | isolated-pinned-runtime
record | docs/decisions/drafts/isolate-checkpoint-intake.md
```

Later expensive-to-reverse choices and their homes:

- Protocol pin, identity handling and DSSE byte preservation:
  `docs/decisions/drafts/pin-authority-protocol.md`, Step 2.
- Table layout, idempotency scope and fenced leases:
  `docs/decisions/drafts/coordinate-intake-with-fenced-leases.md`, Step 3.
- Session, key and endorsement custody:
  `docs/decisions/drafts/bind-uploads-to-enrolled-keys.md`, Step 4.
- Sandbox profile, trust injection and coverage exclusions:
  `docs/decisions/drafts/isolate-validator-trust.md`, Step 6.

The substrate record gets a dated appended correction in Step 1. Operator
records for candidate stalls, validation failures, policy freshness and
quarantine cleanup live under `docs/runbooks/`, each naming what fired, the
first check and who to wake. The README carries the exact local start, check
and demo commands. After this packet, issue #1's evidence contract, one
example intent and every stable refusal are the input issue #2 consumes.
