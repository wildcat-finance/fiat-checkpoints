# Validation refused for trust or policy freshness

Before recording an intent, the validator reads the run's verified trust
projection twice: once before the job and once after it. Both reads must name
the same head, and the uploader's own grant must still be current. See the
[validator decision](../decisions/drafts/isolate-validator-trust.md).

## What fired

`validation-finished` events with code `policy_unavailable` (reasons
`trust-head-moved`, `projection-unavailable` or
`historical-signers-unavailable`), or with `endorsement_invalid` and reason
`grant-not-current`, rise for one run.

## First check

1. `trust-head-moved` means an operator record was ingested while a job ran.
   The candidate keeps its phase and is retried with the new head; repeated
   moves point at an ingestion loop, so check `authority-record-ingested`
   events for that run.
2. `projection-unavailable` or `historical-signers-unavailable` means the run's
   stored records no longer verify, or the database is unreachable. Follow the
   `trust-projection-refused` events from the
   [upload-binding decision](../decisions/drafts/bind-uploads-to-enrolled-keys.md).
3. `grant-not-current` rejects the candidate: the uploader's grant or key was
   revoked or expired before validation finished. The contributor needs a new
   grant and a new announce; nothing is retried.

The external freshness head that issue #2's signer checks is not read here; a
validation intent records the trust head it used, nothing more.

## Who to wake

The fiat-checkpoints service operator on call, and the run's operator if a
grant or enrollment changed unexpectedly.
