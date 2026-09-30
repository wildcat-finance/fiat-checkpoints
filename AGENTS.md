# Service repository instructions

This public repository owns the replaceable checkpoint service. Portable
protocol records belong to `wildcat-finance/skills`.

Read `docs/specification.md`, `docs/study.md` and the current step in
`docs/runbook.md` before changing behaviour. Keep the specification's SHA-256
`8ee755c1f9e5c29703af30bd08caffb6fad80c8a0990ee0acecebef09b02f541`. Keep the
first 3,515 bytes of `docs/deployment-substrate.md` unchanged; corrections are
appended. Controller records under `.hexaemeron/` stay local and untracked.

## Current boundary

The scaffold and the pinned protocol are implemented. Production startup and
readiness stay closed. `protocol.lock.json` and `protocol.trees.json` change
only with a new protocol release; regenerate the manifest with
`scripts/protocol_trees.py manifest`. Call the released library for records,
signatures and trust instead of reimplementing it. Never invent a protocol
schema, an accepted checkpoint or isolation evidence. Keep API, upload gateway, staging broker and
credential-free validator as separate roles. Empty module and migration
locations reserve places; they establish no behaviour.

## Checks

Every role runs CPython 3.14.6; uv is 0.12.13. Tests run in the pinned x86_64
Linux test image, never on a macOS host:
`scripts/linux-env.sh run python3 scripts/check.py --group <groups>`. A new
group is a new `tests/test_<group>*.py` module; `scripts/check.py` itself is
pinned by the runbook. A test class that starts a child process sets
`spawns_child_process = True`. Missing groups, zero tests and skips refuse
success. Keep a failure's evidence and find its cause before changing code.

## Records and data

Decision records start as numberless drafts under `docs/decisions/drafts/`;
integration assigns numbers. Run authored prose through Imprimatur and the
Hypomnema check. No real archive, observation, credential, private path or
deployed value enters the tree, test output, logs or command arguments. Tests
use synthetic data in ignored temporary paths and no production access. Cloud
resources, paid services and deployments need separate authorisation.
