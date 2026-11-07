#!/bin/sh
# Demonstrate issue #1 intake to validation: real HTTP, PostgreSQL 16 and the gVisor validator.
#   scripts/demo.sh --scenario intake-validation --profile local [--out PATH]
# It starts gVisor, so it runs as the validator image's supervisor, with the
# PostgreSQL 16 test server up:
#   scripts/linux-env.sh db-start
#   scripts/sandbox-env.sh run scripts/demo.sh --scenario intake-validation --profile local
# It prints one JSON report and its SHA-256, and exits 0 only when every case
# behaved as declared. Every key, record and archive in it is synthetic.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
exec python3 -I -c 'import sys; sys.path[:0] = sys.argv[1:3]; from tests.test_demo_scenario import main; raise SystemExit(main(sys.argv[3:]))' "$ROOT" "$ROOT/src" "$@"
