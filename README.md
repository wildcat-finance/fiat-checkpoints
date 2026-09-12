# fiat-checkpoints

The replaceable service behind Fiat's distributed checkpoint layer: contributor
authentication and run authorisation, bounded quarantine upload grants,
isolated validation against a pinned protocol release, immutable publication
and replication with signed statements, derived indexes, and the infrastructure
around them.

The portable protocol lives in [`wildcat-finance/skills`](https://github.com/wildcat-finance/skills)
and is pinned here by release or exact commit digest. This repository never
widens a schema locally to accept a failing upload.

Nothing is deployed. The current checkpoint transport remains the local store
under `<origin>/.hexaemeron/checkpoints/`, and no checkpoint operation uploads,
posts, commits or pushes.

## This repository is public

No archive, observation, credential, environment value or deployment secret
enters this tree. Ever.

## Contents

- [`docs/deployment-substrate.md`](docs/deployment-substrate.md) — the object
  store, its buckets, its locks, and what the choice gives up.
