"""Replay the released hostile fixture ids through the pinned inspect in the sandbox.

`scripts/reject-case.sh --case ID` replays one id and `--all` every id. Each
row reports the declared stage and refusal class, what the sandboxed inspect
observed and the specimen digest. A row passes only when the observed
protocol code and stage equal the declared ones; the run exits 1 otherwise.
"""

import argparse
import json
from pathlib import Path
import sys

from fiat_checkpoints.validation import fixture
from fiat_checkpoints.validation.outputs import InspectPassed
from fiat_checkpoints.validation.refusals import ValidationRefusal
from fiat_checkpoints.validation.sandbox import Sandbox
from fiat_checkpoints.validation.service import service_binds
from fiat_checkpoints.validation.specimens import Corpus


SCHEMA = "fiat-checkpoints-reject-cases/v1"


def replay(sandbox, release, corpus, fixture_id, *, binds=()):
    specimen = corpus.build(fixture_id)
    job_request = fixture.request(release, attempt="reject-case", outer_sha256=specimen.archive_sha256,
                                  carrier_length=len(specimen.archive))
    outcome, run = fixture.run(sandbox, release, specimen.archive, job_request, fixture.run_trust(release),
                               mode="inspect-case", case=fixture.case(specimen), binds=binds)
    if isinstance(outcome, InspectPassed):
        observed = {"outcome": "passed", "code": None, "stage": None, "protocol_code": None}
    else:
        observed = {"outcome": "refused", **outcome.record()}
        observed.pop("reason")
    passed = (observed["outcome"] == "refused" and observed["protocol_code"] == specimen.asserted_refusal
              and observed["stage"] == specimen.native_stage)
    return {"id": fixture_id, "expected_stage": specimen.native_stage,
            "expected_refusal": specimen.asserted_refusal, "observed": observed,
            "specimen_sha256": specimen.archive_sha256, "specimen_bytes": len(specimen.archive),
            "stderr_sha256": run.stderr_sha256, "wall_ms": run.resources["wall_ms"], "passed": passed}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Replay released hostile fixtures in the sandbox")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--case")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    from fiat_checkpoints.records.trees import REPOSITORY, load_release
    release = load_release()
    corpus = Corpus.released(release)
    ids = corpus.ids() if args.all else [args.case]
    if not args.all and args.case not in corpus.declared():
        print("reject-case-refused: case-unknown", file=sys.stderr)
        return 2
    sandbox = Sandbox()
    try:
        sandbox.check()
    except ValidationRefusal as refusal:
        print("reject-case-refused: " + refusal.reason, file=sys.stderr)
        return 2
    rows = [replay(sandbox, release, corpus, item, binds=service_binds(REPOSITORY)) for item in ids]
    report = {"schema": SCHEMA, "cases": rows, "declared": len(corpus.declared()), "run": len(rows),
              "passed": sum(row["passed"] for row in rows)}
    text = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["passed"] == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
