# Upload staging and transfer refusals

The upload gateway streams each body into one staging directory before it
reaches quarantine. See the
[transfer decision](../decisions/drafts/seal-uploads-in-bounded-quarantine.md)
for the lifetimes and codes.

## What fired

Uploads are refused while the service itself is up: `gateway-request` events
at warning level with 429 `quota_exceeded` and reason `staging-full`, or 503
`storage_unavailable` with reason `staging-full`, `staging-unavailable`,
`quarantine-unavailable` or `quarantine-missing`. It can also be a run of
`upload-failed` events with code `upload_integrity` and reason `stream-idle`
or `stream-deadline` from many candidates at once.

## First check

1. Read `StagingArea.usage()` on the gateway host: reserved bytes, live
   streams and free bytes. Reserved bytes near `capacity_bytes` with few
   streams means capacity is set below the carrier ceiling times the stream
   ceiling; free bytes near `floor_bytes` means the filesystem is full of
   something else.
2. List the staging directory. A `.part` file with no live stream is a
   leftover; `StagingArea.sweep()` or a gateway restart removes it. Never
   remove a file while its stream is live.
3. For `quarantine-*` reasons, check the quarantine store is reachable and not
   full. The gateway fails each attempt; contributors ask for a new capability
   once the store answers.
4. For many idle or deadline refusals at once, check the edge in front of the
   gateway: a proxy that buffers or stalls bodies ends streams it did not
   start. The gateway refuses to start behind a proxy that declares
   buffering or a limit below the ceiling, but it cannot see one that changed
   after the gateway started.

Nothing here may raise a limit above specification section 9 or seal an
attempt by hand.

## Who to wake

The fiat-checkpoints service operator on call. If the quarantine store or edge
proxy is at fault, also the deployment owner for Skills #863.
