"""Resolvers for the selected design's pending conformance criteria.

`scripts/check.py design` looks a criterion up in `RESOLVERS` and refuses one
that has no entry. A resolver takes a `DesignContext` and returns the typed
value its criterion's unit names. The step that ships a criterion's evidence
registers its resolver here; the runner's own bytes stay fixed.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class DesignContext:
    root: Path
    candidate: str
    criterion: str
    # Runs named groups in this process and returns True only for a clean pass.
    run_groups: Callable[[tuple[str, ...]], bool]


RESOLVERS: dict[str, Callable[[DesignContext], object]] = {}
