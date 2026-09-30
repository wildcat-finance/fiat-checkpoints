# Decision: Bind each upload to a numeric login, an operator-enrolled key and one signed endorsement

## Status

Accepted, 2026-09-30. Covers login, sessions, access tokens and CSRF, each
run's authorization projection, proof of possession, the exact-upload
endorsement and the historical-signer check. Upload transfer belongs to Step 5
and validation to Step 6.

## Context

Specification section 8 fixes the identity rules: a dedicated GitHub App
login, the immutable numeric user id from authenticated `GET /user`, Secure,
HttpOnly and SameSite cookies with CSRF protection, 15-minute CLI tokens, and
login state that lives five minutes, is used once and binds one browser.
Logout revokes sessions. Enrollment needs an authenticated identity, a
challenge, proof of possession and a signed operator approval. The upload
endorsement, signed by the enrolled key, binds actor, candidate, run, the
three checkpoint identities, carrier length, parent link, nonce and expiry.
Section 11 makes PostgreSQL coordination, never authority.

The released library already checks enrollment, grants, revocations and
endorsement signatures (`TrustPrefix`, `grant_at`, `signing_history`). The
test environment has no network, and this packet deploys no identity
provider (Skills #863).

## Decision

### Identity

`auth/identity.py` defines the provider seam: `authorization_url(state,
code_challenge)` and `user_document(code, code_verifier)`. The adapter
exchanges the code server-side, calls `GET /user`, discards the user token and
returns the response body. The service reads one field from it, the integer
`id`. A duplicate key, a string, boolean or float id, or a missing id refuses.
No login name, email or provider token is stored or accepted as a credential.
PKCE uses `S256`; its verifier is derived from the login state and browser
binding, so nothing extra is stored.

No live adapter ships. `create_intake_app` refuses production with the same
startup codes as the health app, including `scaffold-only`. The GitHub App
login adapter goes to a new fiat-checkpoints issue filed at integration;
Skills #863 keeps its live proof. A live adapter
names its client secret as `secret:<name>` and reads the value at exchange
time from `/run/secrets/fiat-checkpoints/<name>`: one link, a regular file, at
most 4,096 bytes, never logged or repeated in an error.

### Session custody

| Secret | Lifetime | Stored as | Carried as |
| --- | --- | --- | --- |
| Login state and browser binding | 5 minutes, spent on first presentation | SHA-256 | Query `state`; `__Host-fiat-login`, SameSite=Lax |
| Session | 8 hours, absolute | SHA-256 | `__Host-fiat-session`, Secure, HttpOnly, SameSite=Strict |
| CSRF token | The session's | Not stored; derived from the session secret | `X-CSRF-Token` on every unsafe browser request |
| Access token | At most 15 minutes, never past its session | SHA-256 | `Authorization: Bearer` only, bound to service and environment |

Every secret is 32 random bytes. A presented value of any other shape refuses
before a lookup, so a pasted personal token never reaches a query. Renewal
spends the presented token, and pairing or renewal needs a current grant in
some allowlisted run. Logout revokes the session and every token paired from
it. Ceilings: 10,000 live login states, 16 live sessions per actor (the oldest
is revoked), 8 live tokens per session. Expired or revoked rows never count.
The specification sets no browser session lifetime; eight hours covers a
working day, and a table check pins it.

### Run authorization

Each allowlisted run has external roots and a trust prefix of operator-signed
records, stored byte for byte in `trust_records`, at most 256 per run. Each
request reads the stored head. When the head differs from the cached
projection, the whole prefix is verified again from the roots through the
released `TrustPrefix`, and a stored row that fails refuses as
`authority_unavailable`. Ingestion verifies the new record at the end of the
verified prefix and writes it only if the head has not moved, holding the run
row. Announce needs `announce`, the endorsement's own grant `upload`, status
`read_status`, each checked by the released `grant_at` at the service clock.
A key revocation or an expired grant takes effect at the next request. A run
whose stored records no longer verify freezes that run only. The ingestion
method has no HTTP route yet: `POST /internal/v1/authority-records` goes to
the same new fiat-checkpoints issue, and Skills #863 keeps its live proof.

### Proof of possession

The contributor signs the protocol's proof message over the operator-signed
enrollment challenge. The service accepts the proof only from the
authenticated actor the challenge names, verifies it with the released
signature check and records it for the operator. Recording grants nothing. The
operator's key enrollment embeds the proof, and `TrustPrefix` verifies it
again. A key that signs its own enrollment or challenge refuses as
`issuer-untrusted`, and an endorsement from an unenrolled key refuses as
`signer_not_enrolled`. The API role pins OpenSSL alone, so it verifies
`spki-p256` keys only; Step 6 pins ssh-keygen and gpg in the validator role
(Laurence, 2026-09-30).

### Exact-upload endorsement

Announce binds a 64-hex nonce and the snapshot, manifest and parent digests
beside the candidate. The library authenticates the endorsement with the
enrolled key and checks enrollment and grant at its `issued_at`. The service
then compares actor, candidate, nonce, run, the three identities by role,
length and parent. It requires `issued_at` from announce's second up to now,
an unexpired endorsement and the named grant current now. The endorsement is
recorded once, only while the trust head is unchanged. An exact replay of the
recorded envelope returns the recorded result; any other envelope for that
candidate refuses.

| Refusal | Code |
| --- | --- |
| Actor, identity or length differs | 422 `identity_mismatch` |
| Candidate, nonce, run, parent, time or signature differs; grant not current | 422 `endorsement_invalid` |
| Signing key has no live enrollment for the actor | 422 `signer_not_enrolled` |
| Another actor's candidate, or no current grant | 404 `not_found` |
| Trust head moved before the commit, or database outage | 503 `policy_unavailable` |

A 422 carries the library's own `protocol_code` when the library produced it.
Any unexpected failure is 503 `authority_unavailable` with no text.

### Historical signers

`Projection.historical_signers` resolves each enrollment reference and signing
fingerprint through the released `signing_history` in this run's prefix and
requires that enrollment's key to have that fingerprint. A carried key,
another run's enrollment or a fabricated reference refuses as
`signer_not_enrolled`. A later revocation stays visible in the returned
history. Step 6 builds the native `ApprovedRun` rows from it.

## Signals

| Question | Event |
| --- | --- |
| Is authorization current? | `trust-projection-verified` with record count and duration; `trust-projection-refused` at error level; `authority-record-ingested` with record type and sequence; `authority-record-refused` |
| Why was a request refused? | `intake-request` with route template, status, fixed code, reason and any library code |
| Who holds sessions? | `session-opened` and `access-token-issued` with eviction counts; `session-revoked` |
| Was an endorsement bound? | `endorsement-verified` with the random candidate id and `recorded` or `replayed` |

No event carries an actor id, session id, digest, key, nonce or secret.

## Request bounds

The checks measure bounds and predict no latency. A control body is at most
65,536 bytes, and a streamed body is refused within one 16 KiB chunk of that.
With a current projection, one endorsement starts exactly one verifier
process. Rebuilding a four-record prefix with one enrollment starts five, and
ingesting a fifth record starts six. A run holds at most 256 trust records.

## Alternatives

- Trust the login name or email. Rejected: renames would move authority, and
  section 8 forbids it.
- Stateless signed session tokens. Rejected: logout could not revoke them, and
  the service would hold a signing key.
- A stored or double-submit CSRF token. Rejected: the derived token needs
  neither storage nor a key.
- Treat grant rows in SQL as authority. Rejected by section 11.
- A service-made enrollment challenge with its own proof format. Rejected: the
  protocol's challenge is operator-signed, and a second format would split
  proof checking.
- Verify the full prefix on every request. Rejected: one process start per
  record per request; the cache follows the head, whose tail digest commits to
  the whole prefix through each predecessor link.
- Let a later endorsement replace the first. Rejected: the nonce would stop
  being single-use and a replay would be ambiguous.
- A base64url nonce. Rejected after an observed failure: one nonce in about 32
  starts with `-` or `_`, which the released ID pattern refuses as
  `schema-pattern`.

## Consequences

Step 5 can issue a capability from the recorded endorsement after checking the
grant again, and Step 6 takes historical signers from the same projection.
Each head change costs one full prefix verification, bounded by 256 records.
Announce checks its grant when the request starts, so a revocation just before
it commits still leaves a candidate, but no endorsement for it can be recorded.
A stolen login state can burn a login but cannot open a session.
`scripts/serve.py` still serves health only; the intake app is built with
explicit services.

The released replay requires an acceptance to be issued inside its
endorsement's validity, at most five minutes. This step records one
endorsement per candidate, so issue #2 needs a way to endorse again before
acceptance.
