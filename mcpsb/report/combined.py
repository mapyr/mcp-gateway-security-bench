"""The combined matrix (WS-C): one table, sub-IDs down, targets across.

The v0.1 report was several per-target tables, which let a target quietly omit
rows and made "mostly INCONCLUSIVE" look like an accident rather than the honest
result it is. This renders *one* matrix whose row set is fixed by the registry,
so every target column carries every row — a cell is drawn explicitly as
INCONCLUSIVE / UNSUPPORTED, never left blank. Per-cell reasons are collected as
footnotes below the table.

The row set is authoritative: :func:`build_combined_matrix` refuses to build if
any target's report does not cover exactly the registry's sub-IDs. That refusal
is the CI gate (``ci/check_matrix_rows.py``): a report that gained or dropped a
row cannot be rendered into a matrix that pretends the columns are comparable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from mcpsb.registry import REGISTRY, active_tests
from mcpsb.report.claims import render_summary
from mcpsb.testkit import FAMILIES, family_of


def canonical_sub_ids(registry: tuple = REGISTRY) -> list[str]:
    """Every sub-ID the registry declares, in registry order — the row set."""
    return [f"{spec.id}.{letter}" for spec in active_tests(registry) for letter in spec.surfaces]


class RowSetMismatch(ValueError):
    """A target report's sub-ID set is not exactly the registry's row set."""


@dataclass
class CombinedMatrix:
    targets: list[str]
    sub_ids: list[str]
    #: (sub_id, target) -> verdict string
    verdict: dict[tuple[str, str], str] = field(default_factory=dict)
    #: (sub_id, target) -> reason string (may be empty)
    reason: dict[tuple[str, str], str] = field(default_factory=dict)
    #: (sub_id, target) -> evidence_source string or None
    evidence: dict[tuple[str, str], "str | None"] = field(default_factory=dict)
    #: (family, target) -> (verdict, reason) for the positive-control rows
    positive: dict[tuple[str, str], tuple[str, str]] = field(default_factory=dict)
    #: target -> spec_version / generated_at / version for provenance
    meta: dict[str, dict[str, str]] = field(default_factory=dict)
    #: the raw per-target report dicts, so the renderer can derive the summary
    reports: list[dict] = field(default_factory=list)


def _report_sub_ids(report: dict) -> list[str]:
    return [r["sub_id"] for r in report.get("results", [])]


def build_combined_matrix(reports: list[dict], registry: tuple = REGISTRY) -> CombinedMatrix:
    """Merge per-target report dicts into one matrix, or raise RowSetMismatch.

    Every report must cover exactly the registry's sub-ID set (no missing, no
    extra rows) — this is what makes the columns comparable and is enforced, not
    assumed.
    """
    rows = canonical_sub_ids(registry)
    row_set = set(rows)
    targets: list[str] = []
    m = CombinedMatrix(targets=targets, sub_ids=rows, reports=list(reports))
    for report in reports:
        target = report["target"]
        if target in targets:
            raise RowSetMismatch(f"duplicate target column {target!r}")
        got = _report_sub_ids(report)
        got_set = set(got)
        if got_set != row_set:
            missing = sorted(row_set - got_set)
            extra = sorted(got_set - row_set)
            raise RowSetMismatch(
                f"target {target!r} row set differs from the registry: "
                f"missing={missing} extra={extra}"
            )
        if len(got) != len(got_set):
            raise RowSetMismatch(f"target {target!r} has duplicate sub-ID rows")
        targets.append(target)
        m.meta[target] = {
            "spec_version": report.get("spec_version", ""),
            "generated_at": report.get("generated_at", ""),
            "version": report.get("version", "") or "",
        }
        for r in report["results"]:
            key = (r["sub_id"], target)
            m.verdict[key] = r["verdict"]
            m.reason[key] = r.get("reason", "") or ""
            m.evidence[key] = r.get("evidence_source")
        for p in report.get("positive_controls", []):
            m.positive[(p["family"], target)] = (p["verdict"], p.get("reason", "") or "")
    return m


def load_reports(paths: list[Path]) -> list[dict]:
    """Load per-target report JSON files, ordered as given."""
    out: list[dict] = []
    for p in paths:
        out.append(json.loads(Path(p).read_text()))
    return out


# --------------------------------------------------------------------------- #
# Markdown rendering.
# --------------------------------------------------------------------------- #

_ABBR = {
    "PASS": "PASS",
    "FAIL": "FAIL",
    "UNSUPPORTED": "UNSUP",
    "DECLARED-OUT-OF-SCOPE": "OOS",
    "INCONCLUSIVE": "INCON",
    "ERROR": "ERR",
}


def _cell(verdict: str) -> str:
    return _ABBR.get(verdict, verdict)


def render_combined_markdown(m: CombinedMatrix) -> str:
    lines: list[str] = []
    lines.append("# MCPSB combined matrix")
    lines.append("")
    lines.append(
        "> One matrix, every registry sub-ID as a row and every target as a "
        "column. No cell is blank: where a target was not meaningfully asked the "
        "cell reads `UNSUP`, and where preconditions were never established it "
        "reads `INCON`. There is no aggregate score (SPEC §4). Most cells read "
        "`INCON` because that is the honest result — a live intermediary rarely "
        "lets the bench establish every precondition end-to-end."
    )
    lines.append("")

    # Provenance line per target.
    for t in m.targets:
        meta = m.meta.get(t, {})
        gen = meta.get("generated_at") or "—"
        ver = meta.get("version") or "—"
        lines.append(f"- `{t}` — {ver}, spec {meta.get('spec_version', '?')}, generated {gen}")
    lines.append("")

    # Derived summary (WS-D3): every sentence here is a function of the run data.
    if m.reports:
        lines.append(render_summary(m.reports))

    header = "| Sub-ID | " + " | ".join(f"`{t}`" for t in m.targets) + " |"
    sep = "| --- | " + " | ".join(":---:" for _ in m.targets) + " |"
    lines.append("## Positive controls (per family)")
    lines.append("")
    lines.append("| Family | " + " | ".join(f"`{t}`" for t in m.targets) + " |")
    lines.append(sep)
    footnotes: list[str] = []
    fn_index: dict[str, int] = {}

    def _mark(reason: str) -> str:
        if not reason:
            return ""
        if reason not in fn_index:
            fn_index[reason] = len(footnotes) + 1
            footnotes.append(reason)
        return f" [^{fn_index[reason]}]"

    for fam in sorted(FAMILIES):
        cells = []
        for t in m.targets:
            v, reason = m.positive.get((fam, t), ("—", ""))
            cells.append(f"{_cell(v)}{_mark(reason)}" if v != "—" else "—")
        lines.append(f"| {fam} | " + " | ".join(cells) + " |")
    lines.append("")

    lines.append("## Verdicts (per sub-ID)")
    lines.append("")
    lines.append(header)
    lines.append(sep)
    for sub_id in m.sub_ids:
        cells = []
        for t in m.targets:
            v = m.verdict.get((sub_id, t), "—")
            cells.append(f"{_cell(v)}{_mark(m.reason.get((sub_id, t), ''))}")
        lines.append(f"| `{sub_id}` | " + " | ".join(cells) + " |")
    lines.append("")

    if footnotes:
        lines.append("## Cell reasons")
        lines.append("")
        for reason in footnotes:
            i = fn_index[reason]
            lines.append(f"[^{i}]: {reason}")
        lines.append("")
    return "\n".join(lines)
