"""The report model (WS-1).

A report is the target name, the run's results, and counts derived from them.
The counts are per-severity and per-verdict; there is deliberately **no
aggregate score** (SPEC §4). The "not applicable" verdicts get their own column
so a target that simply does not offer a policy is never confused with one that
failed it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mcpsb.registry import Severity
from mcpsb.verdict import PositiveControlResult, Result, Verdict

#: Column order for reports: conclusive first, then N/A, then non-results.
VERDICT_COLUMNS: tuple[Verdict, ...] = (
    Verdict.PASS,
    Verdict.FAIL,
    Verdict.UNSUPPORTED,
    Verdict.DECLARED_OUT_OF_SCOPE,
    Verdict.INCONCLUSIVE,
    Verdict.ERROR,
)

SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)


@dataclass
class Report:
    target: str
    results: list[Result] = field(default_factory=list)
    #: Injected by the caller (CLI passes wall-clock; tests pass a fixed value)
    #: so the report model itself stays deterministic.
    generated_at: str = ""
    spec_version: str = "0.1"
    #: The target software's own version, sourced from the artifact under test
    #: (a running image / installed wheel / CLI), never from memory or docs. The
    #: WS-D3 claim gate refuses to publish a report whose target version is empty.
    version: str = ""
    #: Per-family positive-control outcomes (WS-D2). Each family's own row in the
    #: matrix; a family that is not verified is why its PASSes read INCONCLUSIVE.
    positive_controls: list[PositiveControlResult] = field(default_factory=list)

    def verified_families(self) -> frozenset[str]:
        return frozenset(p.family for p in self.positive_controls if p.verified)

    def matrix(self) -> dict[Severity, dict[Verdict, int]]:
        """severity -> verdict -> count, zero-filled over all combinations."""
        m: dict[Severity, dict[Verdict, int]] = {
            sev: {v: 0 for v in VERDICT_COLUMNS} for sev in SEVERITY_ORDER
        }
        for r in self.results:
            m[r.severity][r.verdict] += 1
        return m

    def totals(self) -> dict[Verdict, int]:
        t = {v: 0 for v in VERDICT_COLUMNS}
        for r in self.results:
            t[r.verdict] += 1
        return t

    def to_json(self) -> dict:
        return {
            "target": self.target,
            "version": self.version,
            "spec_version": self.spec_version,
            "generated_at": self.generated_at,
            "note": "No aggregate score by design (SPEC §4).",
            "totals": {v.value: c for v, c in self.totals().items()},
            "by_severity": {
                sev.value: {v.value: c for v, c in row.items()}
                for sev, row in self.matrix().items()
            },
            "positive_controls": [p.to_json() for p in self.positive_controls],
            "results": [r.to_json() for r in self.results],
        }
