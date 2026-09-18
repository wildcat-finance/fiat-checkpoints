# Fiat checkpoints

This repository currently runs a local health service with checkpoint admission
closed. It is Step 1 of [intake issue #1](https://github.com/wildcat-finance/fiat-checkpoints/issues/1).
Protocol work requires the release and source review named in
[Skills #1676](https://github.com/wildcat-finance/skills/issues/1676).

## Check and run locally

Use Python 3.12.13, uv 0.12.13 and Git. The wrapper installs only the versions
and hashes in `uv.lock`, refuses a stale lock, and runs from any working directory.

```bash
./scripts/check.sh --group scaffold --report .reports/scaffold.json
uv run --locked --python 3.12.13 python -I scripts/serve.py --config config/local.json
```

`GET /health/live` returns 200. `GET /health/ready` returns 503 with
`intake-closed`. Authentication, uploads, validation, acceptance and downloads
have no routes. Every production start refuses, including a configuration that
claims production trust or gVisor. A filename alone cannot establish a released
protocol or an isolated validator.

The public check prints JSON with its command, exit, case IDs, observed
counters and source/tool/report digests. `--report` writes the separate
`elenchus.unittest.v1` counter report. A missing group, zero tests, skip,
expected failure, error or assertion failure cannot pass. The whole check has
a 180-second process deadline. Future design reports require their exact
candidate, criterion and test group binding.

## Local container

The API image pins Python 3.12.13 for Linux amd64 and installs hashed wheels.
It runs as UID/GID 65532. It supplies local health only; it is not a validator
sandbox or a production deployment.

```bash
DOCKER_BUILDKIT=0 docker build --platform linux/amd64 -f containers/api.Dockerfile -t fiat-checkpoints:scaffold .
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 256m --cpus 1 -p 127.0.0.1:8000:8000 fiat-checkpoints:scaffold
```

The legacy builder flag supports the recorded host without a buildx plugin.
Container execution is checked separately from the Python suite; an unavailable
Docker engine must be reported as untested.

## Records and boundaries

The [adopted specification](docs/specification.md) is preserved byte for byte.
[Source bindings](docs/sources.json) identify its digest and the historical
sources. The [study](docs/study.md) records the selected design and its evidence
limits. The [runbook](docs/runbook.md) includes append-only amendments that
replace the initial research runner with the public runner.

The [configuration contract](config/README.md) describes the small scaffold
schema. [The architecture decision](docs/decisions/drafts/isolate-checkpoint-intake.md)
and [substrate amendment](docs/deployment-substrate.md) record the adopted
construction. [Dependency review](docs/dependencies.md) covers the exact graph;
[the reference host](docs/reference-host.json) records the local environment
without a performance claim.

Publication belongs to [issue #2](https://github.com/wildcat-finance/fiat-checkpoints/issues/2),
retrieval and the full-service demonstration to
[issue #3](https://github.com/wildcat-finance/fiat-checkpoints/issues/3), and live
deployment proof to [Skills #863](https://github.com/wildcat-finance/skills/issues/863).
Real archives, observations, credentials, deployment values and private
evidence stay outside this public tree.

The scaffold uses [Apache-2.0](LICENSE), following the Wildcat Labs Skills
licence. That is the recorded licensing assumption for maintainer review.
