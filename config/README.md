# Scaffold configuration

Pass one explicit JSON file to `scripts/serve.py --config`. `schema.json`
describes only the current scaffold. `local.json` binds loopback;
`container.json` binds the container interface. Both use a synthetic local
environment and contain no credentials.

The parser requires every declared key, rejects unknown and duplicate keys,
and refuses malformed UTF-8, non-finite numbers, wrong types and values outside
the declared bounds. It reads at most 16,384 bytes from a regular file and
refuses a final symlink, a FIFO and an observed change during the read.
Diagnostics contain fixed codes without values or paths. An operator-controlled
parent directory remains outside the final-component symlink check.

| Field | Meaning |
| --- | --- |
| `schema_version` | Exactly 1 |
| `profile` | `local` or `production`; production always refuses startup |
| `service_id`, `environment_id` | Lowercase names of at most 64 characters; local environments end in `-local` |
| `host`, `port` | Explicit bind address and port; no hostname lookup |
| `trust_profile` | A declaration of `local-test` or `production`; it loads no key |
| `protocol_lock` | Null or `protocol.lock.json`; production runs the released `lock` check on it |
| `sandbox_profile` | `unavailable` or `gvisor`; neither establishes isolation |
| `request_max_bytes`, `carrier_max_bytes` | Positive limits capped at 65,536 and 1,073,741,824 bytes; the upload gateway refuses a declared length above `carrier_max_bytes` and may only lower it |
| `validation_concurrency` | A local declaration from 1 through 4; no worker is launched |

Production returns fixed startup codes for test trust, a missing or refused
protocol pin and unavailable isolation, plus `scaffold-only`. A lock or tree
that fails its check adds its own `protocol-*` code. Even a passing lock cannot
enable production while isolation is unavailable. The upload gateway and the
live quarantine adapter refuse production with the same codes. A local
gateway also refuses `proxy-body-limit` or `proxy-buffering` behind an edge
that cannot carry the carrier ceiling as it arrives, and
`staging-unavailable` or `quarantine-unavailable` for a missing, linked or
shared directory. Health reveals neither
configuration nor private inventory. The production configuration fields in
specification section 18 remain prerequisites for later implementation.

Three questions govern local events: did the process start, is admission
available, and how long did a health request take? `local-health-starting`,
`startup-refused`, HTTP status and `health-request.duration_us` answer them.
Health events include a generated request ID, one of three route values, status
and elapsed microseconds. Request paths outside health, query strings, headers,
bodies and caller-supplied IDs are never event fields. Status counts provide
rate/error observations; duration samples retain individual requests.

This local scaffold has no unattended operator, metrics exporter, percentile
dashboard or alert. Those facilities and their exercised runbooks belong to
the steps that introduce actual intake and workers.
