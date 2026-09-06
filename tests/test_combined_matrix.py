"""WS-C: the combined matrix and its row-set consistency gate."""

from __future__ import annotations

import copy

import pytest

from mcpsb.report.combined import (
    RowSetMismatch,
    build_combined_matrix,
    canonical_sub_ids,
    render_combined_markdown,
)
from mcpsb.testkit import FAMILIES


def _report(target: str, verdict: str = "INCONCLUSIVE") -> dict:
    subs = canonical_sub_ids()
    return {
        "target": target,
        "spec_version": "0.1",
        "generated_at": "2026-09-04T00:00:00+00:00",
        "results": [
            {
                "sub_id": s,
                "test_id": s.rsplit(".", 1)[0],
                "surface": s.rsplit(".", 1)[1],
                "severity": "HIGH",
                "verdict": verdict,
                "reason": f"reason for {s}",
                "evidence_source": None,
                "evidence": {},
            }
            for s in subs
        ],
        "positive_controls": [
            {
                "family": f,
                "verdict": "PASS",
                "reason": "legitimate request accepted",
                "evidence_source": "client_response",
                "verified": True,
            }
            for f in sorted(FAMILIES)
        ],
    }


def test_canonical_row_set_is_stable_and_nonempty():
    rows = canonical_sub_ids()
    assert rows == sorted(set(rows), key=rows.index)  # no duplicates, order preserved
    assert len(rows) == 35


def test_builds_matrix_with_all_rows_and_columns():
    m = build_combined_matrix([_report("secure", "PASS"), _report("vulnerable", "FAIL")])
    assert m.targets == ["secure", "vulnerable"]
    assert len(m.sub_ids) == 35
    # Every cell is populated — no blanks.
    for sub in m.sub_ids:
        for t in m.targets:
            assert (sub, t) in m.verdict
    assert m.verdict[(m.sub_ids[0], "secure")] == "PASS"
    assert m.verdict[(m.sub_ids[0], "vulnerable")] == "FAIL"
    # Positive-control rows present for every family/target.
    for fam in FAMILIES:
        assert (fam, "secure") in m.positive


def test_missing_row_is_refused():
    bad = _report("holey")
    bad["results"].pop()  # drop one sub-ID
    with pytest.raises(RowSetMismatch, match="missing="):
        build_combined_matrix([_report("secure"), bad])


def test_extra_row_is_refused():
    bad = _report("bloated")
    extra = copy.deepcopy(bad["results"][0])
    extra["sub_id"] = "MADEUP-999.z"
    bad["results"].append(extra)
    with pytest.raises(RowSetMismatch, match="extra="):
        build_combined_matrix([bad])


def test_duplicate_sub_id_is_refused():
    bad = _report("dup")
    bad["results"].append(copy.deepcopy(bad["results"][0]))
    # set-equality holds, but the length check catches the duplicate row.
    with pytest.raises(RowSetMismatch, match="duplicate sub-ID"):
        build_combined_matrix([bad])


def test_duplicate_target_column_is_refused():
    with pytest.raises(RowSetMismatch, match="duplicate target"):
        build_combined_matrix([_report("secure"), _report("secure")])


def test_markdown_has_no_blank_cells_and_footnotes():
    m = build_combined_matrix([_report("secure", "PASS"), _report("vulnerable", "FAIL")])
    md = render_combined_markdown(m)
    # A blank cell would render as "|  |" or "| |"; assert none in the verdict table.
    for line in md.splitlines():
        if line.startswith("| `") and line.rstrip().endswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            assert all(cells), f"blank cell in row: {line}"
    assert "## Cell reasons" in md
    assert "[^1]:" in md
