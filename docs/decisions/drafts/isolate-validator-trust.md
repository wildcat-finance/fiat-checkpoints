# Decision: Validate each sealed input in a fresh gVisor sandbox with injected public trust

## Status

Accepted, 2026-11-06. Covers the sandbox profile, the gVisor pin, trust
injection, the whole-job ceilings, output binding, the service checks before
an intent, the rejection corpus and what validation does not cover.
Publication belongs to issue #2.

## Context

Specification section 10 fixes the native sequence (inspect, a fresh restore,
`verify --observations`, `checkpoint identity`) and the sandbox contract. The
released `verify_native` runs that sequence and derives commit-signature
coverage, but its own docstring leaves isolation, aggregate descendant limits
and pathname ownership to its caller. Skills #1647, #1648 and #1649 stay open
upstream and are the caller's to contain. Step 4 left the validator role to pin
`ssh-keygen` and `gpg`; Step 5 left `stage_sealed` as the only input.

Two facts surfaced on the Linux environment while building this step:

- The native restore publishes with `renameat2(RENAME_NOREPLACE)`. On a
  gofer-backed bind mount gVisor answers `EINVAL`, and restore stopped with
  "checkpoint stage could not be published atomically". On gVisor's own tmpfs
  the call succeeds.
- The released 238-file native profile omits `scripts/run_observation.py`.
  Restore, verify and identity import it; without it, identity minting fails
  with `FOB003` and restore refuses as `identity-unavailable`. The upstream
  native suite passes because it runs from a full Skills checkout.

## Decision

### Sandbox profile

The validator image (`containers/validator.Dockerfile`) has two stages. The
`rootfs` stage is what a job sees: the pinned Python base, Debian trixie
packages from the base image's own snapshot (2026-08-03) at exact versions,
the two read-only protocol trees, a native runtime tree and the service code.
The `supervisor` stage holds the tools, the locked wheels, gVisor and a copy of
that root filesystem. The build checks every executable digest:

| Executable | Version | SHA-256 |
| --- | --- | --- |
| `/usr/local/bin/python3.14` | 3.14.6 | `30a7def0b3e8d24a36d3829202717542bef124c0a40608b2232b7c837b271bc9` |
| `/usr/bin/git` | 1:2.47.3-0+deb13u1 | `356db14e102d68a1a37d8a1ac577dfd678d45d46e92f468bef8b7154e7bfdc60` |
| `/usr/bin/gpg` | 2.4.7-21+deb13u1+b4 | `7c9d2f9416aabcd10199e2984439f49612644a948279ac56bdf70d69c8958ddf` |
| `/usr/bin/gpgconf` | 2.4.7-21+deb13u1+b4 | `17ea11378c9d71166df855b73a66333fbf8095cb8da7d3a474bd325e3ca726db` |
| `/usr/bin/ssh-keygen` | 1:10.0p1-7+deb13u4 | `4a16f170f7c80d6643d3ffada36d396c9d7b1d63238a218628e37af38d6107c0` |

gVisor is release `release-20261019.0` for x86_64, archive SHA-512
`7cbc2aee...0d8881` (SHA-256 `1298e8ed...41a3`), `runsc` SHA-512
`1ab7bb68...94f266`, on the `systrap` platform. It ran on 2026-11-06 in the colima
profile `fiat-s862a` (x86_64 under qemu TCG on an arm64 Mac, kernel
6.8.0-117-generic, cgroup v2): a trivial container under both `systrap` and
`ptrace`, then the full native sequence. `src/fiat_checkpoints/validation/pins.py`
holds the full digests.

Each job gets a fresh sandbox: `runsc --network=none --host-uds=none
--host-fifo=none`, a read-only root, uid 65532, no capabilities,
`noNewPrivileges`, and its own PID, network, IPC, UTS and mount namespaces.
Its environment is a fixed allowlist of six names; any other name refuses
before launch. `/job` is a gVisor tmpfs owned by the job user, mode 0700.
`/tmp` is a second one with the same options: native Git writes temporary
files there, and without it runsc mounts a world-writable, executable `/tmp`.
The sealed input, the trust document and the service code are read-only binds.

The supervisor runs as root because runsc, cgroups and per-job state need it.
`scripts/sandbox-env.sh run` starts it in a privileged container with no
network and a read-only root, so the loader's write check still refuses the
trees to root. A job's state lives in a fresh root-only directory named by 32
random hex characters. The supervisor copies the sealed input into it through
the staging broker's held descriptor and checks length and digest again, so
no path is ever reopened (Skills #1648). It confirms the directory is the one
it created before and after the run. Jobs naming the same owner, the
candidate, never overlap, and at most `slots` jobs run at once (Skills #1649).
A missing or altered runsc, root filesystem tool or cgroup controller refuses
as `sandbox_unavailable`. The validator then claims no work, and nothing falls
back to a plain subprocess.

### Native runtime tree

`scripts/sandbox-env.sh build` adds `scripts/run_observation.py` from native
commit `1d4e4eebcba1825d0eb3192bf08a6c509bdc0d74` beside a copy of the profile
files, at `/opt/fiat-checkpoints/native-runtime`. The image checks its SHA-256,
`712f2afc40f7703cc64a92cd850559684a28f1b98e3241652a67ac6b48124d40`. Before each
job the runner requires that tree to hold exactly the profile files plus this
one, and `NativePin.check` hashes every profile file on every use. The
release-bound trees stay byte for byte as Step 2 pinned them.

### Trust injection

The supervisor writes one canonical job document and binds it read-only: the
request it derived from its own records, the approved history of public
OpenPGP keys, and the four native tool pins. No archive field, upload request
field or earlier job reaches it. `ProjectionTrust` takes every
operator-enrolled `openpgp-v4` key in the run's verified projection, each
approved for steps 1 to 4096. The start commit comes from operator
configuration, because the released run registration has no field for it.
After the job, every `(enrollment, fingerprint)` that signed must resolve
through `Projection.historical_signers`. The released native fixture's private
key was destroyed by its producer, so no Step 4 enrollment of it can exist;
its checks use `FixedTrust` with the fixture's own test issuer reference.

### Ceilings

| Ceiling | Value | Enforced by |
| --- | ---: | --- |
| CPUs | 2 | cgroup `cpu.max` 200000/100000 |
| Memory, swap disabled | 4 GiB | cgroup `memory.max`, `memory.swap.max` 0, `memory.oom.group` 1 |
| Scratch | 8 GiB | `/job` and `/tmp` tmpfs sizes and `RLIMIT_FSIZE`; both are job memory |
| Processes | 256 | cgroup `pids.max`; the sentry's host threads count too |
| CPU time | 300 s | cgroup `cpu.stat` polled by the supervisor; `RLIMIT_CPU` inside |
| Wall time | 900 s, less the lease margin | supervisor deadline |
| Stdout, stderr | 64 KiB, 16 KiB | supervisor; over either kills the job |
| Open files | 1,024 | `RLIMIT_NOFILE` |

At a ceiling the supervisor writes `cgroup.kill`, kills the sandbox with
`runsc kill --all`, then deletes it, its cgroup and its state directory. The
outcome is `validation_failed` with reason `sandbox-<ceiling>`: a resource kill
is not evidence that the archive is hostile. Configuration lowers a ceiling;
`ResourcePolicy` refuses any raise.

### Output and service checks

The runner writes one canonical JSON line. `outputs.read` accepts it only if
it names the current job and, for a result, matches the request, the native
commit, profile and executable, the four tool pins and the injected trust
digest. All four stages must run in order with exit 0 (a failed restore is
never rescued by a later verify), the reminted identity must equal the
announced one, and coverage must be complete. A refusal carries a protocol
code only when the whole stage stderr is one class the release lists for that
stage. Anything else maps to fixed `validation_failed` (`native-local-errors`),
and stderr leaves the sandbox only as its SHA-256 (Skills #1647).

Before the job the validator reads the candidate's latest endorsement and
challenge, requires the uploader's grant current for `upload`, requires a
`root_authorized` run registration with no initial parent, and stages the
sealed object. After it, the validator approves the signers, requires the
reminted run anchor and initial base to equal the registration's, reads the
projection again and requires the same trust head and a current grant. Only
then does `complete_validation` record the intent. The evidence (schema
`fiat-checkpoints-validation-evidence/v1`) carries the native result, its
digest, the trust and pin digests, the endorsement, registration, parent
reference, trust head, resources and the coverage table below.

| Code | Outcome |
| --- | --- |
| `protocol_refused`, `identity_mismatch`, `signer_not_enrolled`, `endorsement_invalid`, `checkpoint_ineligible`, `capability_not_enabled` | candidate rejected |
| `validation_failed`, `sandbox_unavailable`, `policy_unavailable`, `storage_unavailable` | same phase, retried; `validation_failed` is held after the attempt limit |

### Rejection corpus

The release lists 35 hostile fixture ids, all at stage `inspect`, covering 17
of the 24 refusal classes; the other 7 have no fixture and stay visible in a
check. The released corpus ships only the valid archive, so
`validation/specimens.py` rebuilds each specimen by mutating exactly the bytes
its id names, with its own ZIP writer. `scripts/reject-case.sh --all` runs each
through the pinned inspect in its own sandbox and requires the declared class
at the declared stage.

## Coverage and exclusions

| Covered here | Not covered |
| --- | --- |
| Inspect, fresh restore, verify with observations, identity on one exact input | The signed parent-link record: its signer role belongs to issue #2, so only its reference is carried |
| Complete commit-signature coverage against approved public keys | The external authority-head freshness check (`eligibility.current`); the intent records the trust head it used |
| Registered root anchor and initial base | Parent chains other than a registered root (`capability_not_enabled`) |
| Uploader grant and key current at the start and the end | A decompressed Git-object secret scan; the inspector's raw-member scan stands |
| No network, credential, host socket, shared parent or other job | An exact 100,000-node ceiling: gVisor's tmpfs ignores `nr_inodes`, so nodes are bounded only by memory |
| Memory, processes, CPU time, wall time, output ceilings | Scratch measured apart from memory: tmpfs pages are sentry memory |

## Measured

Measured on 2026-11-06 with `scripts/benchmark.sh --profile local --corpus
protocol.lock.json --repetitions 3`, one job at a time, in the colima
`fiat-s862a` VM: x86_64 under qemu TCG emulation on an arm64 Mac, 4 vCPUs,
8,321,294,336 bytes of memory, kernel 6.8.0-117-generic, CPython 3.14.6,
`runsc` `systrap`. The workload is the released valid fixture at its real
size, 59,603 bytes, through the whole native sequence. No optimization was
made.

| Run | Wall | CPU | Peak memory | Peak host tasks |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 127,935 ms | 160.6 s | 142,884,864 bytes | 40 |
| 2 | 129,552 ms | 162.9 s | 141,508,608 bytes | 39 |
| 3 | 128,674 ms | 162.1 s | 142,176,256 bytes | 39 |
| Median | 128,674 ms | 162.1 s | 142,176,256 bytes | 39 |

Peak memory is the job cgroup's `memory.peak`: the sentry, the gofer, the job's
processes and its tmpfs scratch together, so scratch has no separate figure.
Peak host tasks are the cgroup's `pids.peak`, which counts the sentry's own
threads. The 35 rejection cases, each a sandboxed inspect only, took between
18,511 and 21,550 ms (median 19,474 ms). Every run stayed inside its
ceilings; the largest values were 14.4% of the 900,000 ms wall budget, 3.3%
of 4 GiB memory and 54% of 300 CPU seconds. Under emulation, CPU time is the ceiling nearest to its
limit; a carrier near the 111,860,548-byte historical size was not measured
and may reach it on this host. These numbers come from an emulated VM and
say nothing about production latency.

## Alternatives

- A plain subprocess or `runc` when gVisor is missing. Rejected by section 10
  and by the runbook: missing isolation refuses.
- A host tmpfs bound as `/job`, which would make node counts exact and scratch
  observable. Rejected after an observed failure: gVisor refuses
  `renameat2(RENAME_NOREPLACE)` on a gofer-backed mount, so restore cannot
  publish.
- Docker's API with `--runtime=runsc` from the supervisor. Rejected: it would
  hand the supervisor a daemon socket and a second policy layer, where runsc
  with an OCI bundle needs neither.
- Running the native commands from the profile tree alone. Rejected: restore
  cannot mint identity without `scripts/run_observation.py`.
- Reading a job's trust from the archive or the upload request. Rejected by
  section 10: only independently approved public keys enter a job.

## Consequences

Validation needs a Linux host with cgroup v2 and a privileged supervisor.
Validation and sandbox checks run only through `scripts/sandbox-env.sh`, not
`scripts/linux-env.sh`. A new gVisor release, Debian package or native profile
changes the image, `pins.py` and this record together. The missing native file
is an upstream release gap. Until the native profile names it, this image adds
the file and checks its digest. The three Skills findings stay open; this step
contains them and does not fix them.
