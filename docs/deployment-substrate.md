# Deployment substrate: Cloudflare R2

Decided 2026-09-12 by the maintainer. This record names the substrate for the
checkpoint authority service. It authorises no spend, no account, no bucket and
no deployment; each of those is a separate act.

## Decision

Cloudflare R2 holds checkpoint authority. Two Cloudflare accounts.

| Bucket | Account | Lock | Purpose |
|---|---|---|---|
| `quarantine` | service | none; lifecycle expiry | candidate uploads, bounded and short-lived |
| `authority` | service | bucket lock, indefinite | accepted archives, acceptance statements, revocations, resolutions, key transitions, run anchors |
| `authority-replica` | recovery | bucket lock, retention no shorter than `authority` | second copy |

Keys are content-addressed: `sha256/<archive_sha256>`. There is no object
versioning in R2 and none is needed, because a locked key refuses a second
write rather than shadowing it.

Publication is a conditional `PUT` with `If-None-Match: *`. An occupied key is
a refusal, not an overwrite. A client resolving acceptance compares digests,
never a version string.

Grants are presigned URLs or temporary access credentials, scoped to one bucket
and prefix, bounded by content length and checksum, with a short expiry.
Contributors receive a `PUT` into `quarantine` only. Download is a presigned
`GET` against `authority`, and egress is free, so the grant's cost is not a
reason to ration it.

The replica is written by a job this service owns, because R2 has no native
cross-account replication. `awaiting_replica` clears on a verified read-back of
the replica object, not on the job reporting success.

The derived index is a query store, rebuildable from the immutable objects. A
database restore may speed recovery; it cannot decide what was accepted.

## What this gives up

Both copies sit at one provider. Losing the Cloudflare account, or a
provider-wide failure, reaches the primary and the replica together. Two
accounts reduce blast radius from credential compromise; they do not make the
copies independent.

R2 bucket locks have no compliance mode and no legal hold, and an administrator
holding a sufficiently scoped API token can remove a lock rule. Retention here
is a control against accident and against a compromised runtime role, not
against a determined administrator.

Both are accepted deliberately in exchange for zero egress, $0.015/GB-month
storage, and one identity surface instead of three.

## Open: the signer

R2 has no key-management service. The signing key is asymmetric, its private
half never leaves the service holding it, and that service is not Cloudflare.
Assumption pending confirmation: a KMS-class signer that holds no bytes,
costing a few pounds a year. The protocol pins the public verifier and key
identity; rotation is a typed signed transition so old statements stay
verifiable.

## Open: jurisdiction

R2 location hints are hints. A hard regional guarantee needs a jurisdictional
restriction set at bucket creation, and which jurisdiction applies has not been
decided.

## Runtime permissions

No runtime role receives object delete, lock-rule removal, retention
shortening, or bucket, policy, lock or token administration. Removing a lock
rule is break glass: two named approvers, one exact object, a bounded session,
a stated reason, and a durable after-action record.

## Repository hygiene

`wildcat-finance/fiat-checkpoints` is public. No archive, observation,
credential, environment value or deployment secret enters this tree.
