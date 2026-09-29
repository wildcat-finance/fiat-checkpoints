#!/bin/sh
# Run scripts/check.py under the pinned uv, interpreter and locked environment.
set -eu
CHECK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "$(uv --version 2>/dev/null || true)" in
  'uv 0.12.13'|'uv 0.12.13 ('*) ;;
  *) printf '%s\n' 'checks-refused: uv-version-mismatch' >&2; exit 2 ;;
esac
exec uv run --project "$CHECK_ROOT" --python 3.14.6 --locked --no-config --no-sources \
  python -I "$CHECK_ROOT/scripts/check.py" "$@"
