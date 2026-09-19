# Service repository instructions

This public repository owns the replaceable checkpoint service. Portable
protocol records belong to `wildcat-finance/skills`.

Read `docs/specification.md`, `docs/study.md` and the effective step in
`docs/runbook.md` before changing behavior. Keep the specification's SHA-256
`8ee755c1f9e5c29703af30bd08caffb6fad80c8a0990ee0acecebef09b02f541` unchanged.
Preserve all 3515 original bytes of `docs/deployment-substrate.md`; corrections
are appended. Controller records under `.hexaemeron/` stay local.

## Current boundary

Only the scaffold is implemented. Production startup and readiness remain
closed. Step 2 needs the released contract from Skills #1676, its amendments,
complete applicable source review and supported known-failure admission before
any protocol-dependent edit. Never invent `protocol.lock.json`, a protocol
schema, an accepted checkpoint or successful isolation evidence.

Keep API/coordinator, gateway, trusted staging and credential-free validator
as separate roles in the selected design. Empty module, migration and schema
directories reserve locations; they establish no behavior.

## Checks and records

Use Python 3.12.13 and uv 0.12.13. Run
`./scripts/check.sh --group scaffold --report .reports/scaffold.json` for the
current step. Missing groups and skipped tests refuse success. Add focused
tests when a new boundary ships. Preserve failures and diagnose their cause.

Run authored prose through Sapheneia, Imprimatur, Vulgate and Imprimatur before
publication, retaining its evidence and required structure. Fixed source bytes
and already written history remain unchanged. Expensive decisions begin as
numberless files under `docs/decisions/drafts/`; Fiat owns assignment at final
integration. Receipt-bound source changes use checked append-only amendments.

No real archive, observation, credential, private evidence or deployed value
enters the source tree, test output, logs or command arguments. Use synthetic
fixtures in ignored temporary paths. Keep tests free of production access.
Cloud resources, paid services, deployments, access changes and physical
removal of locked objects require separate authorization.
