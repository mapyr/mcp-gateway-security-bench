"""Discover and import the attack corpus so its ``@mcpsb.test`` callables register.

Attacks live as plain modules under ``attacks/`` (one ID per file). They are not
a normal import package from the runner's perspective — they are discovered by
path and executed, which registers them. Files whose name starts with ``_`` are
helpers, not attacks, and are skipped.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent


def import_attacks(root: Path = _REPO_ROOT) -> int:
    """Import every ``attacks/**/*.py`` (except ``_*``). Returns the count."""
    attacks_dir = root / "attacks"
    count = 0
    for path in sorted(attacks_dir.rglob("*.py")):
        if path.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(
            f"mcpsb_attack_{path.stem}_{count}", path
        )
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        count += 1
    return count
