"""Discover and import the positive-control corpus so its callables register.

Positive controls live under ``positive/`` (one file per family), decorated with
``@mcpsb.positive_control``. Like the attack corpus they are discovered by path
and executed; files whose name starts with ``_`` are helpers and are skipped.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent


def import_positive_controls(root: Path = _REPO_ROOT) -> int:
    """Import every ``positive/**/*.py`` (except ``_*``). Returns the count."""
    pc_dir = root / "positive"
    if not pc_dir.exists():
        return 0
    count = 0
    for path in sorted(pc_dir.rglob("*.py")):
        if path.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(
            f"mcpsb_positive_{path.stem}_{count}", path
        )
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        count += 1
    return count
