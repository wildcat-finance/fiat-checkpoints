# Decision: Seal each upload in bounded staging and a fresh quarantine key before it counts

## Status

Accepted, 2026-09-30. Covers the upload capability, the gateway's framing and
staging, the quarantine store, the seal, the staging broker's job input and
the sweeper. Validation belongs to Step 6, publication to issue #2 and the
live R2 adapter to Skills #863.

## Context

Specification section 9 fixes the transfer: after a valid endorsement the
service returns an opaque, actor-bound capability, sent in an `Authorization`
header to a fixed same-origin route and never logged. It names one candidate
and attempt, the exact size and archive SHA-256, the endorsement digest, the
environment and an expiry, and grants no read, list, delete or provider
credential. The gateway needs an exact `Content-Length` and no ambiguous
framing, counts and hashes the bytes into an exclusive no-follow file, and
publishes to a unique quarantine key only after the length and digest match.
It then reads the object back in full; metadata and ETag never stand in.
Section 11 commits the attempt pointer only after that read-back. Section 17
caps gateway incremental memory at 64 MiB per stream.

Step 4 left five things here: checking every capability against
`EndorsementStore.bound`, the sweeper, slow streams, Content-Type checks and
`Retry-After` on new 429 and 503 refusals.

## Decision

### Roles

The API role issues capabilities and answers completion; it holds no
quarantine credential. The gateway, `api/gateway.py`, is its own ASGI app with
one route, `PUT /v1/candidates/{id}/content`, plus health. It holds the
transfer records, the trust projection, one staging directory and one
quarantine store, and no session or identity provider. The sweeper's only
storage power is deleting quarantine keys. Migration `0003_transfer.sql` adds
`upload_capabilities`, `quarantine_objects` and a `stream_started_at` column on
`upload_attempts`.

### Capability

A capability is 32 random bytes, shown once and stored as SHA-256 over a fixed
context and the value. It is presented as `Authorization: Upload <value>`; any
other scheme, a second header or another shape refuses before a lookup, and a
stored hash is compared in constant time. No response other than the one that
issues it, no event, representation, exception or refusal carries it.

It is issued in the endorsement response, and by
`POST /v1/candidates/{id}/upload-attempts` after a failed or expired attempt,
only from the candidate's bound endorsement and only after that endorsement's
own grant is current for `upload`. It names one attempt, its fence, the
declared size and digest, the endorsement sequence and digest and the
environment. The gateway checks each of those against the stored records, and
the lock-held checks repeat them in the same transaction. The capability is
bound to its actor through that record: the gateway checks that actor's bound
endorsement and grant, and the capability can seal only the bytes that actor
endorsed. If no capability can be issued, the endorsement stays recorded and
the response is the refusal; the same request replayed issues one.

| Lifetime | Value | Where it is enforced |
| --- | --- | --- |
| Start window | Earliest of 15 minutes, the endorsement's expiry (at most 300 seconds) and the candidate deadline | Row check; gateway and `start` refuse after it |
| Stream lease | From stream start, the earlier of 30 minutes and the candidate deadline | `start` sets it; the gateway ends the stream at it |
| Idle gap | 60 seconds between body messages | Gateway |
| Stored capability | Deleted a day after its last issue once its attempt is no longer open | Sweeper |
| Staged file | Its stream; removed on every exit, on restart and by `StagingArea.sweep` | Gateway |
| Quarantine object | Until its attempt fails or is abandoned, its candidate ends, or 24 hours | Sweeper and the store lifecycle |

Issuing again while the attempt's stream has not started replaces the stored
hash of the same attempt, at most 1,024 times, so a replayed request opens no
second attempt and holds no second stream. The earlier value stops working. A
started stream makes issue `upload_in_progress`; a sealed attempt answers with
its recorded result and no capability. A newer endorsement supersedes the
capability: the stream refuses to start, and the seal refuses if the
endorsement changed during the transfer. The endorsement may expire during the
stream, because every endorsement of one candidate binds the same identities,
length and parent. Issue #2 binds acceptance through `bound` with its own
`until`. The idempotency key that section 13 asks for on `upload-attempts` is
checked for shape only: the route is idempotent by candidate state, so a second
key reaches the same attempt.

### Framing and staging

The gateway refuses before reading a byte:

| Case | Code |
| --- | --- |
| No capability, another scheme, two headers, unknown or other-environment capability | 401 `auth_required` |
| No `Content-Length`, or `Transfer-Encoding` without one, including chunk extensions | 411 `length_required` |
| Two lengths, a length with a sign, space or exponent, a length with `Transfer-Encoding`, any `Content-Encoding`, a range, a query, another `Expect`, a type other than one `application/octet-stream`, more than 64 headers or 8,192 header bytes | 400 `request_invalid` |
| A length over the carrier ceiling | 413 `upload_too_large` |
| A length other than the capability's, extra, short, slow or disconnected bodies, a changed digest | 422 `upload_integrity` |
| Another candidate's path | 404 `not_found` |
| A spent or closed capability, or a candidate past its deadline | 410 `candidate_expired` |
| A second stream on a live attempt | 409 `upload_in_progress` |
| No staging room | 429 `quota_exceeded`, `Retry-After: 60` |
| Staging or quarantine write, full disk or late object | 503 `storage_unavailable`, `Retry-After: 30` |
| Read-back of other bytes, or an occupied key holding other bytes | 503 `authority_unavailable`, `Retry-After: 30` |

`storage_unavailable` is an implementation choice. Section 16 gives three example
codes for the dependency-unavailable class, and a storage outage is a fourth
member of it (accepted 2026-10-01).

The staging directory is opened once with `O_NOFOLLOW` and refused if group- or
world-writable. A stream reserves its declared size against the area's capacity
before reading, and the filesystem must keep `floor_bytes` free after it. Each
file is created with `O_EXCL|O_NOFOLLOW` through the directory descriptor.
Bytes are hashed and counted as they are written, and a chunk that would pass
the declared size writes nothing. Closing removes the file only if it is still
the one the stream created. One gateway process owns one staging directory.

### Quarantine and the seal

`start` records the attempt's fresh key, `quarantine/<candidate>/<nn>-<32 hex>`,
before any byte reaches the store. After the stream, the gateway checks the
grant again, creates the key from the staged descriptor and reads it back,
counting and hashing every byte. It reads a missing object up to five times,
pausing 50 ms longer before each retry. An occupied key passes only with
exactly the declared bytes. `seal_stream` then seals the quarantine record and the attempt
in one transaction. A trigger refuses to seal a capability's attempt unless its
quarantine record is sealed with the same size and digest. Other triggers
refuse any change to a sealed attempt, to a sealed record's size or digest, and
to a capability after its stream started. A failed stream fails its attempt
and returns its stream reservation in the same transaction. It deletes the
object it wrote only once the attempt is known unsealed. An object that failed
its read-back is held as evidence, outside every sweep, until an operator
releases it.

`DirectoryQuarantine` is the local store: conditional create through a held
directory, read-only objects and no link followed. `R2Quarantine` refuses to
start, with the production startup codes or `scaffold-only`. `stage_sealed`
is the staging broker's read for Step 6: the sealed record's key into an
exclusive read-only job file, counted and hashed against the record, and read
afterwards only through its descriptor.

A gateway behind a proxy starts only when the proxy's tested body limit is at
least the carrier ceiling and it streams requests; otherwise it refuses as
`proxy-body-limit` or `proxy-buffering` (specification section 5).

### Sweeper

One pass reclaims expired stream leases, expires candidates past their deadline,
and drops spent idempotency keys, login state, sessions, tokens and
capabilities. It then deletes due quarantine keys and keys the 24-hour
lifecycle reached. A key is marked `deleting` before the store deletes it and
`deleted` after, so an interrupted pass is finished by the next. A key the
store reports as old but whose live record is younger by the service clock is
kept.

## Signals

| Question | Signal |
| --- | --- |
| Why has this upload stopped? | `gateway-request` with route template, status, code, reason, random candidate id, attempt and bytes; `stream-started`, `upload-failed` with its code, `upload-sealed`, `lease-expired` |
| Was a capability issued? | `capability-issued`, kind `new` or `renewed` |
| Is cleanup keeping up? | `sweep-completed` per kind with its count; `quarantine-delete-failed`; `Transfers.quarantine_usage` live, held, sealed bytes, deleting and cleanup lag in seconds |
| Did a store change bytes? | `quarantine-object-held` at error level |
| Can the host take another stream? | `StagingArea.usage` reserved bytes, streams and free bytes; `quota-refused` with its scope |

No event carries a capability, actor id, digest, key or header. Operators start
from [upload staging](../../runbooks/upload-staging.md) and
[quarantine cleanup](../../runbooks/quarantine-cleanup.md).

## Measured bounds

Measured on 2026-09-30 in the colima `fiat-s862a` x86_64 VM (qemu emulation,
kernel 6.8.0-117-generic, CPython 3.14.6) through the gateway, staging, local
quarantine store, read-back and seal, in 262,144-byte body messages. Memory is
the traced Python allocation peak above the level before the request, across
every thread, and the growth of the process's peak resident set. No
optimization was made.

| Declared bytes | Incremental Python bytes | Peak RSS growth | Staged peak seen | Staged after | Quarantine bytes | Seconds |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 4,194,304 | 2,205,653 | 2,304 KiB | 262,144 | 0 | 4,194,304 | 2.84 |
| 100,663,296 | 2,140,684 | 2,168 KiB | 96,731,136 | 0 | 100,663,296 | 13.17 |
| 4,194,304 | 2,138,568 | 308 KiB | 262,144 | 0 | 4,194,304 | 3.48 |
| 100,663,296 | 2,138,774 | 0 KiB | 96,731,136 | 0 | 100,663,296 | 13.30 |
| 1,073,741,824 | 2,150,919 | 352 KiB | 1,069,809,664 | 0 | 1,073,741,824 | 133.69 |

Incremental memory stayed near 2.1 MB at every size, below the 67,108,864-byte
ceiling. The two 1 MiB copy and read-back buffers account for most of it; this
is inferred, not profiled. Staged bytes never passed the declared size, which
is checked after every chunk in the suite, and were zero after every
request. Per stream the host holds at most the declared size in staging and
the store holds the declared size once. At most eight streams run, so staging
needs at most 8 GiB, and `capacity_bytes` can lower that. The check
`test_gateway_memory_per_stream_stays_bounded_and_does_not_grow_with_size`
repeats the 4 MiB and 96 MiB rows and keeps the ceiling. These numbers come
from an emulated VM and say nothing about production throughput.

## Alternatives

- Presigned or temporary provider credentials. Rejected by sections 4.2 and 9:
  they cannot enforce the exact size and digest, and the contributor would
  hold provider access.
- Multipart quarantine uploads. Rejected: the 1 GiB ceiling fits one
  conditional create, as section 12 says for authority objects, so no
  incomplete multipart upload exists to abort or sweep.
- Stream straight to the store and trust its checksum or ETag. Rejected by
  section 9.
- Hold the whole body in memory. Rejected by section 17.
- Require the endorsement to stay unexpired until the seal. Rejected: the
  endorsement lasts at most 300 seconds and a 1 GiB stream may take 30 minutes;
  every endorsement of one candidate binds the same bytes.
- A new attempt for every issue. Rejected: 16 attempts per candidate would
  run out on replays, and each would hold a stream.
- Store the idempotency key of `upload-attempts` with its capability.
  Rejected: the capability is never stored in the clear, so a replay could not
  return it anyway.
- Delete an object that failed its read-back. Rejected: its bytes are the
  evidence of a store that changed them.
- Build the gateway on FastAPI routes. Rejected: a plain ASGI callable sees
  every header as sent and bounds each body message itself.

## Consequences

A contributor endorses, gets a capability and uploads in one pass; a failed
stream costs one of 16 attempts and needs a new capability. A capability
lost in transit costs one issue request, not a stream. Stream and staging
reservations come back at the seal, at failure, or at lease expiry through the
next issue or sweep. A crash before the seal leaves the attempt open until its
lease ends. A crash after the seal leaves a sealed attempt that the same
capability replays. `Coordinator.begin_upload` still opens attempts with no
capability for persistence callers. Only capability attempts must seal beside a
read-back record, and no route reaches `begin_upload`. The gateway checks the
grant when the stream starts and again before the seal, not at the seal commit;
Step 6 checks run and key scope again before any intent. The idle and absolute
limits bound the body; the quarantine write and read-back after it are bounded
only by the store's own call timeouts, which the local store needs no more
than its disk does and the live adapter must set. The live R2 adapter,
its lifecycle rule and the tested proxy limit are Skills #863 evidence.
