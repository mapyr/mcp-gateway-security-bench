"""Verdicts and per-surface results (WS-1).

The verdict vocabulary is fixed by SPEC §4 and must not grow casually. Two
invariants are encoded here in code, not just prose:

* ``INCONCLUSIVE`` and ``ERROR`` are *not* conclusive — they never stand in for
  PASS or FAIL (invariant #8, SPEC §4).
* ``UNSUPPORTED`` and ``DECLARED_OUT_OF_SCOPE`` are the "not applicable" bucket:
  the target was not asked a question it could meaningfully answer. They are
  reported in an explicit N/A column, never folded into PASS or FAIL.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from mcpsb.registry import Severity


class Verdict(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNSUPPORTED = "UNSUPPORTED"
    DECLARED_OUT_OF_SCOPE = "DECLARED-OUT-OF-SCOPE"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"

    @property
    def is_conclusive(self) -> bool:
        """True only for verdicts that actually decided the test."""
        return self in (Verdict.PASS, Verdict.FAIL)

    @property
    def is_not_applicable(self) -> bool:
        """The N/A bucket: the target was not meaningfully asked (SPEC §4)."""
        return self in (Verdict.UNSUPPORTED, Verdict.DECLARED_OUT_OF_SCOPE)


class EvidenceSource(str, enum.Enum):
    """Where a PASS/FAIL verdict's evidence came from (WS-D1).

    This is the mechanism behind "verdicts from an independent observation
    plane, never the target's own logs." Every conclusive verdict must declare
    its source, and ``TARGET_AUDIT`` is admissible only for the ``AUDIT-*``
    family (SPEC §3.1) — anywhere else it is an ``ERROR``, not a pass. The report
    can then render the observation-plane claim only when a run actually produced
    a verdict from the sink/DNS/IMDS.
    """

    CLIENT_RESPONSE = "client_response"  # the attacker-visible JSON-RPC response
    SINK = "sink"                        # the out-of-band HTTP sink
    DNS = "dns"                          # the bench DNS query log
    IMDS = "imds"                        # the fake instance-metadata service
    TARGET_AUDIT = "target_audit"        # the SUT's own audit log (AUDIT-* only)

    @property
    def is_observation_plane(self) -> bool:
        return self in (EvidenceSource.SINK, EvidenceSource.DNS, EvidenceSource.IMDS)


def validate_evidence(test_id, verdict, source):
    """D1 gate: a conclusive verdict must carry a valid ``evidence_source``.

    Returns ``(verdict, source, error_reason)``. A PASS/FAIL with no source, or
    with ``target_audit`` outside the AUDIT-* family, is turned into ``ERROR`` —
    it cannot be reported as a pass. Non-conclusive verdicts pass through.
    """
    if verdict not in (Verdict.PASS, Verdict.FAIL):
        return verdict, source, None
    if source is None:
        return Verdict.ERROR, None, f"{verdict.value} declared no evidence_source (D1)"
    if source is EvidenceSource.TARGET_AUDIT and not str(test_id).startswith("AUDIT-"):
        return Verdict.ERROR, None, "target_audit evidence is admissible only for AUDIT-* (D1)"
    return verdict, source, None


#: One-line meaning of each verdict, mirroring SPEC §4. Kept here so reports and
#: the spec can share the same text.
VERDICT_MEANING: dict[Verdict, str] = {
    Verdict.PASS: "Attack blocked; out-of-band observation confirms it.",
    Verdict.FAIL: "Attack succeeded.",
    Verdict.UNSUPPORTED: "Target cannot express the policy the test requires. Not a FAIL.",
    Verdict.DECLARED_OUT_OF_SCOPE: "Maintainer placed this trust boundary out of scope, with a link.",
    Verdict.INCONCLUSIVE: "Preconditions never established. Never degrades to PASS or FAIL.",
    Verdict.ERROR: "The bench itself failed.",
}


@dataclass(frozen=True)
class Result:
    """The outcome of one test on one surface (one sub-ID)."""

    sub_id: str  # e.g. "AUTHZ-002.b"
    test_id: str  # e.g. "AUTHZ-002"
    surface: str  # single surface letter
    severity: Severity
    verdict: Verdict
    reason: str = ""
    #: Where a PASS/FAIL's evidence came from (D1). Required for conclusive
    #: verdicts; None for INCONCLUSIVE/UNSUPPORTED/ERROR.
    evidence_source: "EvidenceSource | None" = None
    #: Optional pointer to the out-of-band evidence backing the verdict
    #: (what the sink/DNS/IMDS recorded).
    evidence: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "sub_id": self.sub_id,
            "test_id": self.test_id,
            "surface": self.surface,
            "severity": self.severity.value,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "evidence_source": self.evidence_source.value if self.evidence_source else None,
            "evidence": dict(self.evidence),
        }


#: The reason attached to a PASS that had to be degraded because its family's
#: positive control was not verified (WS-D2). Named so gates/reports can key off it.
POSITIVE_CONTROL_MISSING = "positive_control_missing"


@dataclass(frozen=True)
class PositiveControlResult:
    """Whether a target accepted a family's legitimate request (WS-D2).

    ``verdict`` is ``PASS`` when the family is *verified* (the legitimate action
    was accepted), ``FAIL`` when the target rejected it, ``UNSUPPORTED`` when the
    family is not applicable to the target, and ``INCONCLUSIVE`` when the control
    could not be established. Only ``PASS`` counts as verified.
    """

    family: str
    verdict: Verdict
    reason: str = ""
    evidence_source: "EvidenceSource | None" = None

    @property
    def verified(self) -> bool:
        return self.verdict is Verdict.PASS

    def to_json(self) -> dict:
        return {
            "family": self.family,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "evidence_source": self.evidence_source.value if self.evidence_source else None,
            "verified": self.verified,
        }
