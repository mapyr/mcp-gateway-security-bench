"""Report rendering: per-severity counts with an explicit N/A column, no
aggregate score (SPEC §4)."""

from mcpsb.report.claims import Claims, claim_violations, derive_claims, render_summary
from mcpsb.report.combined import (
    CombinedMatrix,
    RowSetMismatch,
    build_combined_matrix,
    canonical_sub_ids,
    load_reports,
    render_combined_markdown,
)
from mcpsb.report.json_report import render_json
from mcpsb.report.markdown_report import render_markdown
from mcpsb.report.model import Report

__all__ = [
    "Report",
    "render_json",
    "render_markdown",
    "CombinedMatrix",
    "RowSetMismatch",
    "build_combined_matrix",
    "canonical_sub_ids",
    "load_reports",
    "render_combined_markdown",
    "Claims",
    "derive_claims",
    "claim_violations",
    "render_summary",
]
