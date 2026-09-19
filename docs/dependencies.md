# Dependency review

## Sources and graph

Reviewed on 2026-09-18 against the exact PyPI release metadata and `uv.lock`.
The direct packages point to the FastAPI, Kludex/Uvicorn, Psycopg and Encode
repositories through their published project links. The complete graph uses
PyPI and `files.pythonhosted.org`; no VCS dependency or private index is present.
No selected artifact was marked yanked in that observation.

FastAPI supplies ASGI routing and brings Starlette, Pydantic, annotation and
typing helpers. Uvicorn brings Click and h11. Psycopg's binary extra provides
its matching native driver wheel, avoiding an unpinned system-library install.
HTTPX is a development dependency for real HTTP and ASGI tests; it brings
HTTPcore, AnyIO, IDNA, certifi and h11. Windows-only tzdata stays in the portable
lock and is not installed on the Linux reference host.

## Release observations

The recent Psycopg 3.3.6 release is from the review date, IDNA 3.20 from the day
before, and Uvicorn 0.53.0 from four days before. Their youth remains a review
limit. Metadata and project links identify published provenance; they do not
prove package ownership, absence of malicious code or freedom from known
vulnerabilities. This pass inspected the graph and release metadata, not each
upstream source or an advisory database. There is no dependency-security claim.

| Package | Locked version | Upload date (UTC) |
| --- | --- | --- |
| `annotated-doc` | 0.0.5 | 2026-07-28 |
| `annotated-types` | 0.8.0 | 2026-07-23 |
| `anyio` | 4.15.1 | 2026-09-05 |
| `certifi` | 2026.7.22 | 2026-07-22 |
| `click` | 8.5.0 | 2026-08-26 |
| `fastapi` | 0.141.1 | 2026-07-29 |
| `h11` | 0.16.0 | 2025-04-24 |
| `httpcore` | 1.0.9 | 2025-04-24 |
| `httpx` | 0.28.1 | 2024-12-06 |
| `idna` | 3.20 | 2026-09-17 |
| `psycopg` | 3.3.6 | 2026-09-18 |
| `psycopg-binary` | 3.3.6 | 2026-09-18 |
| `pydantic` | 2.13.5 | 2026-08-28 |
| `pydantic-core` | 2.46.5 | 2026-08-28 |
| `starlette` | 1.6.0 | 2026-08-08 |
| `typing-extensions` | 4.16.0 | 2026-07-02 |
| `typing-inspection` | 0.4.4 | 2026-08-12 |
| `tzdata` | 2026.4 | 2026-09-12 |
| `uvicorn` | 0.53.0 | 2026-09-14 |

## Reproduction

`uv.lock` carries exact direct/transitive versions and artifact hashes.
`requirements.lock` and `requirements-dev.lock` are its hashed exports.
`requirements-tools.lock` separately pins uv 0.12.13 for CI bootstrap. The
wrapper requires that uv version and Python 3.12.13; the container installs
binary wheels with pip's hash checking enabled. Tests check installed versions,
lock freshness, export parity and a changed direct dependency's refusal.

Primary metadata is available from [PyPI FastAPI](https://pypi.org/project/fastapi/0.141.1/),
[PyPI Uvicorn](https://pypi.org/project/uvicorn/0.53.0/),
[PyPI Psycopg](https://pypi.org/project/psycopg/3.3.6/) and
[PyPI HTTPX](https://pypi.org/project/httpx/0.28.1/). Review the graph and release
changes again before any deployment, which this scaffold does not authorize.

## CI parser addition, 2026-09-19

[PyYAML 6.0.3](https://pypi.org/project/PyYAML/6.0.3/) parses the workflow in development tests. All 11 locked artifact hashes match its PyPI release metadata; none were yanked, and that metadata listed no vulnerabilities on 2026-09-19. This check did not review upstream source or an advisory database. The runtime lock and all prior package records are unchanged.
