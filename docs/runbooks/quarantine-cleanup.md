# Quarantine cleanup lag and held objects

The sweeper deletes quarantine keys whose attempt failed or was abandoned,
whose candidate ended, or which passed the 24-hour lifetime. See the
[transfer decision](../decisions/drafts/seal-uploads-in-bounded-quarantine.md)
for the record states.

## What fired

`Transfers.quarantine_usage()` reports `cleanup_lag_seconds` above 172,800
(48 hours, specification section 17), `quarantine-delete-failed` events repeat
across passes, or a `quarantine-object-held` event arrived at error level.

## First check

1. For lag or delete failures, confirm the sweeper is running and that its
   `sweep-completed` events for kind `quarantine` have counts above zero. A
   pass that cannot reach the store leaves each key `deleting`, and the next
   pass retries it; nothing needs to be marked by hand.
2. For a held object, treat it as a storage-integrity incident: the store
   returned other bytes than the gateway wrote under a fresh key. Copy the
   object and its `quarantine_objects` row to the incident record before
   anything else, then freeze uploads to that store.
3. Once the evidence is kept elsewhere, release the key with
   `Transfers.release_held(key, now)`; the next pass deletes it.

Never delete a key whose record is `writing` or `sealed` by hand: a live
stream or a validation job may still need it.

## Who to wake

The fiat-checkpoints service operator on call. For a held object, also the
storage owner named for Skills #863, since the store's integrity is in
question.
