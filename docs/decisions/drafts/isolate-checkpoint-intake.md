# Decision: Isolate checkpoint intake from validation authority

## Status

Accepted, 2026-09-18. This decision applies to scaffolding. Protocol
implementation awaits Skills #1676 and the study's source-review and admission
conditions.

## Context

The adopted specification requires service-mediated transfers and a
credential-free validator. The checked study selects `mediated-isolated`.
The service starts with no implementation, and a local container supplies no
evidence of validator isolation.

## Decision

Keep API/coordinator, transfer gateway, trusted staging broker and isolated
validator as four separately bounded roles, implementing only local health in
Step 1.

## Alternatives

Direct provider transfers remove the gateway but lose the service's exact
length/hash and request-time denial controls. Validation in the API process
removes a process boundary but gives hostile checkpoint processing access to
API credentials. Both fail the study's declared design gates. Returning to S3
would reopen the maintainer's R2 choice and is outside this packet.

## Consequences

Mediated transfer adds gateway I/O and bandwidth cost. A separate trusted
stager must supply exact immutable input to a credential-free sandbox. Neither
cost nor isolation has been measured here. Four roles count the design's
separation; they are not four deployed processes.

FastAPI/ASGI, psycopg 3, Python 3.12.13 and hashed dependency locks establish the
scaffold runtime. PostgreSQL 16, Ubuntu 24.04 and pinned gVisor remain the
reference production profile. The local pinned slim-bookworm image does not
change that host choice. Admission remains closed until the actual protocol,
authority and containment checks ship and pass their owning steps.
