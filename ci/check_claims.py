#!/usr/bin/env python3
"""CI gate: the published report's claims are functions of its run data (WS-D3).

Two things are enforced:

1. **Hard invariants** over every discovered per-target report:
   * every target's ``version`` is non-empty (sourced from the artifact, not
     memory or docs);
   * every target that reports a PASS has at least one *verified* positive
     control — otherwise a "block" is indistinguishable from "blocks everything"
     and must not be published as a PASS.

2. **No hand-editing of the summary.** The committed reference combined matrix
   (``results/reference/combined-matrix.md``) is regenerated from the reference
   report JSONs and must match byte-for-byte. Because the summary sentences (the
   observation-plane headline, the live-target count, the positive-control claim,
   the version list) are *derived* from the data, a stale or hand-edited report
   fails here — the only way to change the prose is to change the run.

Column order is standardized (sorted by target) so the report is reproducible.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from mcpsb.report.claims import claim_violations, render_summary  # noqa: E402
from mcpsb.report.combined import (  # noqa: E402
    RowSetMismatch,
    build_combined_matrix,
    render_combined_markdown,
)
from mcpsb.report.regions import extract_region  # noqa: E402

_REFERENCE_DIR = _REPO / "results" / "reference"
_REFERENCE_MATRIX = _REFERENCE_DIR / "combined-matrix.md"
_NARRATIVE_REPORT = _REPO / "REPORT.md"


def _looks_like_report(data: object) -> bool:
    return isinstance(data, dict) and "target" in data and "results" in data


def _discover_reports(root: Path) -> list[dict]:
    out: list[dict] = []
    for p in sorted(root.rglob("*.json")):
        try:
            data = json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if _looks_like_report(data):
            out.append(data)
    return out


def main() -> int:
    all_reports = _discover_reports(_REPO / "results")
    if not all_reports:
        print("No target report JSON found under results/ — nothing to check.", file=sys.stderr)
        return 1

    problems = claim_violations(all_reports)

    # Staleness / hand-edit guard for the published reference matrix.
    if _REFERENCE_MATRIX.exists():
        ref_reports = sorted(_discover_reports(_REFERENCE_DIR), key=lambda r: r["target"])
        try:
            matrix = build_combined_matrix(ref_reports)
        except RowSetMismatch as exc:
            problems.append(f"reference reports do not form a matrix: {exc}")
        else:
            regenerated = render_combined_markdown(matrix)
            committed = _REFERENCE_MATRIX.read_text()
            if regenerated.rstrip("\n") != committed.rstrip("\n"):
                problems.append(
                    f"{_REFERENCE_MATRIX.relative_to(_REPO)} is stale or hand-edited; "
                    f"regenerate it from the run data:\n"
                    f"    python -m mcpsb.cli matrix "
                    f"{' '.join(f'results/reference/{r['target']}.json' for r in ref_reports)} "
                    f"--out {_REFERENCE_MATRIX.relative_to(_REPO)}"
                )

        # The same byte-match pattern applied to the narrative report: its
        # generated summary region must equal a fresh render, so REPORT.md's prose
        # cannot be edited to say more than the run supports either.
        if _NARRATIVE_REPORT.exists():
            embedded = extract_region(_NARRATIVE_REPORT.read_text(), "reference-summary")
            expected = render_summary(ref_reports).strip()
            if embedded is None:
                problems.append(
                    f"{_NARRATIVE_REPORT.relative_to(_REPO)}: generated region "
                    f"'reference-summary' is missing its markers"
                )
            elif embedded != expected:
                problems.append(
                    f"{_NARRATIVE_REPORT.relative_to(_REPO)}: the 'reference-summary' "
                    f"region is stale or hand-edited; refresh it from run data:\n"
                    f"    python -m mcpsb.cli report --out REPORT.md"
                )

    if problems:
        print("Claim-consistency gate FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    print(
        f"Claim-consistency gate OK: {len(all_reports)} report(s) — versions present, "
        f"every PASS backed by a verified positive control, summary matches run data."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
