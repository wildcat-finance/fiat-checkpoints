#!/bin/sh
set -eu
CHECK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "$(uv --version)" in
  'uv 0.12.13'|'uv 0.12.13 ('*) ;;
  *) printf '%s\n' 'checks-refused: uv-version-mismatch' >&2; exit 2 ;;
esac
exec uv run --project "$CHECK_ROOT" --python 3.12.13 --locked --no-config --no-sources python -I "$CHECK_ROOT/scripts/check.py" "$@"
