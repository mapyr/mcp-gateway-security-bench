"""Markdown report rendering (WS-1).

A per-severity summary matrix plus a per-sub-ID detail table. No aggregate
score, and the N/A verdicts (UNSUPPORTED, DECLARED-OUT-OF-SCOPE) sit in their
own columns so they are never mistaken for PASS or FAIL.
"""

from __future__ import annotations

from mcpsb.report.model import SEVERITY_ORDER, VERDICT_COLUMNS, Report

_HEADER = {
    "PASS": "PASS",
    "FAIL": "FAIL",
    "UNSUPPORTED": "UNSUP",
    "DECLARED-OUT-OF-SCOPE": "OOS",
    "INCONCLUSIVE": "INCONC",
    "ERROR": "ERROR",
}


def render_markdown(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"# MCPSB report — `{report.target}`")
    lines.append("")
    meta = f"Spec {report.spec_version}"
    if report.generated_at:
        meta += f" · generated {report.generated_at}"
    lines.append(meta)
    lines.append("")
    lines.append(
        "> No aggregate score by design (SPEC §4). `UNSUP`/`OOS` are the N/A "
        "bucket — the target was not meaningfully asked, not that it failed."
    )
    lines.append("")

    # Summary matrix.
    cols = [_HEADER[v.value] for v in VERDICT_COLUMNS]
    lines.append("## Summary by severity")
    lines.append("")
    lines.append("| Severity | " + " | ".join(cols) + " |")
    lines.append("| --- | " + " | ".join("---:" for _ in cols) + " |")
    matrix = report.matrix()
    for sev in SEVERITY_ORDER:
        row = matrix[sev]
        cells = [str(row[v]) for v in VERDICT_COLUMNS]
        lines.append(f"| {sev.value} | " + " | ".join(cells) + " |")
    totals = report.totals()
    total_cells = [str(totals[v]) for v in VERDICT_COLUMNS]
    lines.append("| **Total** | " + " | ".join(f"**{c}**" for c in total_cells) + " |")
    lines.append("")

    # Detail.
    lines.append("## Detail")
    lines.append("")
    lines.append("| Sub-ID | Severity | Verdict | Reason |")
    lines.append("| --- | --- | --- | --- |")
    for r in report.results:
        reason = r.reason.replace("|", "\\|") if r.reason else ""
        lines.append(
            f"| `{r.sub_id}` | {r.severity.value} | {r.verdict.value} | {reason} |"
        )
    lines.append("")
    return "\n".join(lines)
