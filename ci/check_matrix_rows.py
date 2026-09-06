#!/usr/bin/env python3
"""CI gate: every target report covers exactly the registry's row set (WS-C).

The combined matrix is only honest if its columns are comparable — each target
must carry every registry sub-ID, no more and no less. This gate discovers the
per-target report JSON files and tries to build the combined matrix; the builder
refuses (RowSetMismatch) if any column's row set differs, and that refusal is the
gate. It also refuses if a report predates the current registry.

Discovers ``results/**/*.json`` report files (those with ``target`` + ``results``
keys). Pass explicit paths as arguments to check a specific set instead.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from mcpsb.report.combined import (  # noqa: E402
    RowSetMismatch,
    build_combined_matrix,
    canonical_sub_ids,
)


def _looks_like_report(data: object) -> bool:
    return isinstance(data, dict) and "target" in data and "results" in data


def _discover(paths: list[str]) -> list[Path]:
    if paths:
        return [Path(p) for p in paths]
    found: list[Path] = []
    for p in sorted((_REPO / "results").rglob("*.json")):
        try:
            if _looks_like_report(json.loads(p.read_text())):
                found.append(p)
        except (json.JSONDecodeError, OSError):
            continue
    return found


def main(argv: list[str]) -> int:
    files = _discover(argv)
    if not files:
        print("No target report JSON found under results/ — nothing to check.", file=sys.stderr)
        return 1

    reports = [json.loads(p.read_text()) for p in files]
    try:
        matrix = build_combined_matrix(reports)
    except RowSetMismatch as exc:
        print("Matrix row-set gate FAILED:", file=sys.stderr)
        print(f"  {exc}", file=sys.stderr)
        print(f"  registry row set has {len(canonical_sub_ids())} sub-IDs.", file=sys.stderr)
        return 1

    print(
        f"Matrix row-set gate OK: {len(matrix.targets)} target(s) "
        f"({', '.join(matrix.targets)}) each cover all "
        f"{len(matrix.sub_ids)} registry sub-IDs."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
