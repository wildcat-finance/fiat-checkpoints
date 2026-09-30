# Decision: Run every service role on the pinned 3.14.6 runtime with an isolated validator

## Status

Accepted, 2026-09-30. Covers the scaffold and the construction later steps
build on. It does not claim that isolation, protocol checks or intake work yet;
each owning step must pass its own checks.

## Context

The adopted specification fixes service-mediated transfer and a
credential-free validator (sections 4.2, 6 and 9), so direct provider URLs are
not considered again. It leaves two questions open: where protocol code runs,
and on which interpreter. Its reference deployment profile names Python 3.12.
The released authority protocol, Skills commit
`685158cdc5407ca5559bf9ef4a021d664e764ece`, names CPython 3.14.6 in its lock's
`tools.python`. Its native commands come from Skills commit
`1d4e4eebcba1825d0eb3192bf08a6c509bdc0d74`, profile
`native-1d4e4eeb-openpgp-v1`. The specification ranks a released protocol
above service records and calls its runtime a proposed profile. The operator
confirmed 3.14.6 on 2026-09-29.

## Decision

Build `isolated-pinned-runtime`: API, upload gateway, staging broker and a
credential-free sandboxed validator as separate roles, all on CPython 3.14.6,
with API and validator importing the two pinned Skills trees read-only.

## Alternatives

The study's resolver compared four candidates on the released `release` and
`lock` checks and on hashed wheel resolution.

- `in-process-validation`: the API runs the native commands itself. It needs
  the fewest roles, but hostile archive code would share a process with API
  credentials. It fails the `validator-isolated` gate.
- `isolated-reference-runtime`: the same roles, all on 3.12.13. It follows the
  reference profile, but runs the protocol on an interpreter its release does
  not name. It fails the `lock-interpreter` gate.
- `isolated-split-runtime`: web roles on 3.12.13, every protocol check handed
  to 3.14.6 processes. It passes every gate, but needs two interpreter pins
  against one. Its protocol check time (166 ms) and peak RSS (34,930,688 bytes)
  equal the selected candidate's because both run the same 3.14.6 binary, so
  it is dominated. Its extra process hop was not measured.

Those time and memory figures measure the released `release` check, a fixed
protocol workload. They say nothing about service latency.

## Consequences

One interpreter serves every role, so one set of hashed wheels and one image
base cover the service. The service departs from the specification's 3.12
reference profile, and a later protocol release that names another interpreter
moves every role with it.

Scaffold pins: `python:3.14.6-slim-trixie` by linux/amd64 digest for both
images, uv 0.12.13, and FastAPI 0.141.1, psycopg 3.3.6 and uvicorn 0.53.0 with
every artefact hash in `uv.lock`. Tests run inside the test image on an x86_64
Linux kernel: the colima profile `fiat-s862a` locally and hosted Ubuntu 24.04
in CI. PostgreSQL 16 and a pinned gVisor `runsc` stay the reference production
profile. Step 6 pins the gVisor release after measuring it on that host.

Production startup refuses test trust, a missing protocol pin and unavailable
isolation, and readiness stays unavailable until the owning steps ship those
checks. Starlette 1.7.0 still deprecates its HTTPX test adapter, so tests call
the app through HTTPX's own ASGI transport instead.
