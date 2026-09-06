"""Claims derived from run data (WS-D3).

Every summary sentence a report makes about itself is a *function of the run*,
computed here from the per-target report dicts — never written by hand. The
renderer emits only the claims the data supports (e.g. the observation-plane
headline appears only when a live verdict actually came from the sink/DNS/IMDS),
and ``ci/check_claims.py`` re-derives the same claims to gate the published
report against its data.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_OBSERVATION_PLANE = {"sink", "dns", "imds"}


@dataclass
class Claims:
    #: target -> its software version (empty string if the run did not source one)
    versions: dict[str, str] = field(default_factory=dict)
    #: targets whose version is empty — the gate refuses to publish these
    missing_versions: list[str] = field(default_factory=list)
    #: targets with >=1 non-INCONCLUSIVE result (i.e. actually exercised live)
    live_targets: list[str] = field(default_factory=list)
    #: targets with >=1 PASS
    targets_with_pass: list[str] = field(default_factory=list)
    #: of targets_with_pass, those lacking any verified positive control (a
    #: contradiction the gate rejects: a PASS with no verified control is not one)
    pass_without_positive_control: list[str] = field(default_factory=list)
    #: targets that produced >=1 conclusive verdict from the observation plane
    observation_plane_targets: list[str] = field(default_factory=list)

    @property
    def observation_plane(self) -> bool:
        return bool(self.observation_plane_targets)


def _conclusive(r: dict) -> bool:
    return r.get("verdict") in ("PASS", "FAIL")


def derive_claims(reports: list[dict]) -> Claims:
    c = Claims()
    for report in reports:
        t = report["target"]
        c.versions[t] = report.get("version", "") or ""
        if not c.versions[t]:
            c.missing_versions.append(t)
        results = report.get("results", [])
        if any(r.get("verdict") != "INCONCLUSIVE" for r in results):
            c.live_targets.append(t)
        has_pass = any(r.get("verdict") == "PASS" for r in results)
        if has_pass:
            c.targets_with_pass.append(t)
            verified = {p["family"] for p in report.get("positive_controls", []) if p.get("verified")}
            if not verified:
                c.pass_without_positive_control.append(t)
        if any(_conclusive(r) and r.get("evidence_source") in _OBSERVATION_PLANE for r in results):
            c.observation_plane_targets.append(t)
    return c


def claim_violations(reports: list[dict]) -> list[str]:
    """Hard invariants a publishable report must satisfy (WS-D3). Empty == OK."""
    c = derive_claims(reports)
    problems: list[str] = []
    for t in c.missing_versions:
        problems.append(f"target {t!r} has an empty version; source it from the artifact before publishing")
    for t in c.pass_without_positive_control:
        problems.append(
            f"target {t!r} reports a PASS but has no verified positive control — "
            f"a block that is indistinguishable from blocking everything cannot be published as a PASS"
        )
    return problems


def render_summary(reports: list[dict]) -> str:
    """The report's self-description, derived entirely from the run (WS-D3)."""
    c = derive_claims(reports)
    lines: list[str] = ["## Summary", ""]

    n_live = len(c.live_targets)
    total = len(reports)
    if n_live:
        lines.append(
            f"- **{n_live} of {total} target(s) were exercised live** "
            f"({', '.join(f'`{t}`' for t in c.live_targets)}): each produced at "
            f"least one non-INCONCLUSIVE verdict."
        )
    else:
        lines.append(
            f"- **No target was exercised live** (all {total} report only "
            f"INCONCLUSIVE/UNSUPPORTED): the harness is complete but no target let "
            f"it establish a conclusive verdict."
        )

    # The observation-plane headline is conditional on the data (WS-D3): it is
    # only true if a live verdict actually came from the sink/DNS/IMDS.
    if c.observation_plane:
        lines.append(
            f"- **Verdicts were confirmed by the out-of-band observation plane** "
            f"for {', '.join(f'`{t}`' for t in c.observation_plane_targets)} "
            f"(evidence from the sink/DNS/IMDS, not the target's own response)."
        )
    else:
        lines.append(
            "- The observation plane recorded no conclusive verdict in this run, "
            "so no observation-plane claim is made (it is not a differentiator here)."
        )

    if c.targets_with_pass:
        lines.append(
            f"- **Every target with a PASS has a verified positive control** "
            f"({', '.join(f'`{t}`' for t in c.targets_with_pass)}): a legitimate "
            f"request was accepted before a blocked one was scored."
        )

    lines.append("")
    lines.append("Target versions (sourced from the artifact under test):")
    for t, v in c.versions.items():
        lines.append(f"- `{t}` — {v or '_(version not sourced)_'}")
    lines.append("")
    return "\n".join(lines)
