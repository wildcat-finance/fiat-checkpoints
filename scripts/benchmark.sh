#!/bin/sh
# Measure the released valid fixture through the sandboxed native sequence.
#   scripts/benchmark.sh --profile local --corpus protocol.lock.json [--repetitions N] [--out PATH]
# Run it as the supervisor: scripts/sandbox-env.sh run scripts/benchmark.sh --profile local --corpus protocol.lock.json
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
exec python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from fiat_checkpoints.validation.benchmark import main; raise SystemExit(main(sys.argv[2:]))' "$ROOT/src" "$@"
