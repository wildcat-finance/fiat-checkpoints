#!/bin/sh
# Replay released hostile fixture ids through the sandboxed pinned inspect.
#   scripts/reject-case.sh --case ID [--out PATH]
#   scripts/reject-case.sh --all [--out PATH]
# Run it as the supervisor: scripts/sandbox-env.sh run scripts/reject-case.sh --all
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
exec python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from fiat_checkpoints.validation.reject import main; raise SystemExit(main(sys.argv[2:]))' "$ROOT/src" "$@"
