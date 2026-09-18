#!/usr/bin/env python3
"""Start the local scaffold from its repository-owned source directory."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from fiat_checkpoints.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
