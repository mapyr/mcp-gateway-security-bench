"""The MCPSB test registry — the single source of truth.

Every test ID, its frozen severity, the attack surfaces it must exercise, its
``premise`` (the trust-boundary assumption it makes), and its source precedent
live here and *only* here. ``SPEC.md`` is generated from this module; CI fails
the build if the two drift apart (see ``ci/check_spec_drift.py``).

Invariants enforced by :func:`validate` (run at import time):

* IDs are unique and never renumbered.
* Severity is an attribute of the *test*, fixed at creation (SPEC §5). Changing
  it requires a new ID + deprecation of the old one, not an edit here.
* ``premise`` is mandatory and must be a sentence about a trust boundary
  (SPEC §3.3), not a paraphrase of the test name.
* Every declared surface letter is known.
* A test family must exercise *every* surface it declares (SPEC §3.2); a family
  implemented for only one letter is not mergeable — but that is a runner/test
  gate, not something the registry can see, so it is documented, not asserted.

Do not add IDs here casually. A new ID is a spec change: a separate commit
tagged ``spec-change:`` with an entry in ``SPEC-CHANGELOG.md`` (SPEC §5).
"""

from __future__ import annotations

import argparse
import enum
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

# --------------------------------------------------------------------------- #
# Severity — frozen registry (SPEC §5).
# --------------------------------------------------------------------------- #


class Severity(enum.Enum):
    """Severity is an attribute of the test, not the result, and is immutable.

    Ordered most-severe first for stable reporting.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[self.value]


#: The severity ladder, with the definition that fixes each rung (SPEC §5).
SEVERITY_DEFINITIONS: Mapping[Severity, str] = {
    Severity.CRITICAL: (
        "Authentication bypass, tenant-isolation bypass, arbitrary code "
        "execution, gateway takeover, or access to high-value credentials."
    ),
    Severity.HIGH: (
        "Authorization bypass, SSRF into internal network / IMDS, invoking a "
        "tool without its required policy, or cross-session access."
    ),
    Severity.MEDIUM: (
        "Action with no audit record, silent schema change, secret leaked to a "
        "log or trace, or a broken rate limit."
    ),
    Severity.LOW: "Metadata leak or overly detailed errors.",
}


# --------------------------------------------------------------------------- #
# Surfaces (SPEC §3.2). Each attack is run on *every* surface it declares.
# --------------------------------------------------------------------------- #


class Surface(enum.Enum):
    LIST = "a"  # tools/list
    CALL = "b"  # tools/call
    PROMPT = "c"  # prompts/get
    RESOURCE = "d"  # resources/read
    BATCH = "e"  # batch / aggregating path
    RECONNECT = "f"  # reconnect / resumption path


#: Human-readable label for each surface letter, used when rendering the spec.
SURFACE_LABELS: Mapping[str, str] = {
    "a": "tools/list",
    "b": "tools/call",
    "c": "prompts/get",
    "d": "resources/read",
    "e": "batch / aggregating path",
    "f": "reconnect / resumption path",
}

_VALID_SURFACES = frozenset(s.value for s in Surface)


# --------------------------------------------------------------------------- #
# Test specification.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class TestSpec:
    """One test ID in the registry.

    ``surfaces`` is the ordered tuple of surface letters the test family must
    exercise. Where a target lacks a surface, the runner records
    ``UNSUPPORTED`` for that letter — never ``PASS`` (SPEC §3.2, §4).
    """

    id: str
    name: str
    severity: Severity
    surfaces: tuple[str, ...]
    premise: str
    source: str
    #: Free-form note, e.g. AUDIT-* tests where the log is the subject of study
    #: and the §13.1 "verdict never from the SUT's logs" rule is relaxed.
    notes: str = ""
    deprecated: bool = False
    superseded_by: str | None = None

    def __post_init__(self) -> None:
        unknown = [s for s in self.surfaces if s not in _VALID_SURFACES]
        if unknown:
            raise ValueError(f"{self.id}: unknown surface(s) {unknown}")
        if not self.surfaces:
            raise ValueError(f"{self.id}: at least one surface is required")
        if len(set(self.surfaces)) != len(self.surfaces):
            raise ValueError(f"{self.id}: duplicate surface letters")
        if not self.premise.strip():
            raise ValueError(f"{self.id}: premise is mandatory (SPEC §3.3)")

    @property
    def surface_ids(self) -> list[str]:
        """The per-surface sub-IDs, e.g. ``['AUTHZ-002.a', 'AUTHZ-002.b']``."""
        return [f"{self.id}.{letter}" for letter in self.surfaces]


# --------------------------------------------------------------------------- #
# The registry. 23 core IDs (SPEC §6). Order is by family, then number.
# Do not reorder or renumber. Do not edit a severity. Add only via spec-change.
# --------------------------------------------------------------------------- #

REGISTRY: tuple[TestSpec, ...] = (
    # --- Authentication ---------------------------------------------------- #
    TestSpec(
        id="AUTH-001",
        name="Unauthenticated tools/list",
        severity=Severity.CRITICAL,
        surfaces=("a", "b"),
        premise=(
            "An unauthenticated caller sits outside the trust boundary; the "
            "intermediary must not reveal tool inventory or accept calls "
            "before identity is established."
        ),
        source="baseline",
    ),
    TestSpec(
        id="AUTH-002",
        name="Client A's token presented as B",
        severity=Severity.CRITICAL,
        surfaces=("b",),
        premise=(
            "A bearer token authenticates exactly one principal; presenting "
            "principal A's token must never grant principal B's authority."
        ),
        source="baseline",
    ),
    TestSpec(
        id="AUTH-003",
        name="Expired token",
        severity=Severity.HIGH,
        surfaces=("b",),
        premise=(
            "Token validity is time-bounded; an expired credential carries no "
            "authority regardless of prior validity."
        ),
        source="baseline",
    ),
    TestSpec(
        id="AUTH-004",
        name="Wrong audience (RFC 8707)",
        severity=Severity.HIGH,
        surfaces=("b",),
        premise=(
            "A token minted for a different resource audience is not addressed "
            "to this intermediary and must be rejected even if otherwise valid."
        ),
        source="Hangar 1.4.0 audience binding",
    ),
    # --- Authorization ----------------------------------------------------- #
    TestSpec(
        id="AUTHZ-001",
        name="No permission for the call",
        severity=Severity.HIGH,
        surfaces=("b", "c", "d", "e"),
        premise=(
            "Authorization is required on every value-bearing surface; "
            "authenticating a caller does not by itself authorize a specific "
            "tool, prompt, or resource."
        ),
        source="baseline",
    ),
    TestSpec(
        id="AUTHZ-002",
        name="Tool hidden from list, called directly",
        severity=Severity.HIGH,
        surfaces=("a", "b"),
        premise=(
            "Hiding a tool from tools/list is a discovery-layer decision; the "
            "enforcement decision on tools/call must not depend on whether the "
            "caller could see the tool."
        ),
        source="class: mechanism present, path absent",
        notes="Sequence a->b: hide on list, then invoke directly.",
    ),
    TestSpec(
        id="AUTHZ-003",
        name="Group/alias policy bypassed by different keying",
        severity=Severity.HIGH,
        surfaces=("a", "b", "c", "d"),
        premise=(
            "A policy expressed over one identifier for a resource must hold "
            "under every alias or key the same resource can be addressed by."
        ),
        source="Hangar #1036/#1040, F3",
    ),
    TestSpec(
        id="AUTHZ-004",
        name="Batch path bypasses per-call gate",
        severity=Severity.HIGH,
        surfaces=("e",),
        premise=(
            "An aggregating or batch surface is not a trust-exempt fast path; "
            "every constituent call must pass the same gate as a singleton."
        ),
        source="Hangar _GATES, batch pre-gate",
    ),
    # --- Tenancy ----------------------------------------------------------- #
    TestSpec(
        id="TENANT-001",
        name="Tenant override in tool arguments",
        severity=Severity.CRITICAL,
        surfaces=("b",),
        premise=(
            "The caller's tenant is bound by the authenticated session, not by "
            "data the caller supplies; tool arguments cannot re-scope "
            "authority."
        ),
        source="baseline",
    ),
    TestSpec(
        id="TENANT-002",
        name="Tenant override in header / path / _meta",
        severity=Severity.CRITICAL,
        surfaces=("b",),
        premise=(
            "Tenant identity derives from the authenticated principal; no "
            "request-controlled header, path segment, or _meta field may "
            "override it."
        ),
        source="Hangar SEP-2243 / Mcp-Param-*",
    ),
    # --- SSRF / egress ----------------------------------------------------- #
    TestSpec(
        id="SSRF-001",
        name="Loopback + RFC1918",
        severity=Severity.HIGH,
        surfaces=("b",),
        premise=(
            "The intermediary's network position is not delegable to a "
            "malicious server; requests it originates must honor an egress "
            "policy, not the server's chosen destination."
        ),
        source="baseline",
    ),
    TestSpec(
        id="SSRF-002",
        name="IMDS 169.254.169.254",
        severity=Severity.CRITICAL,
        surfaces=("b",),
        premise=(
            "Cloud instance metadata is reachable only from the host's network "
            "position; the intermediary must never proxy a call there on a "
            "server's behalf."
        ),
        source="baseline",
    ),
    TestSpec(
        id="SSRF-003",
        name="IPv6 and IPv4-mapped (::ffff:)",
        severity=Severity.HIGH,
        surfaces=("b",),
        premise=(
            "An egress allow/deny decision must be made on the resolved "
            "destination, not its textual form; alternate address encodings "
            "address the same host."
        ),
        source="Hangar #900",
    ),
    TestSpec(
        id="SSRF-004",
        name="DNS rebinding: TOCTOU register->connect",
        severity=Severity.CRITICAL,
        surfaces=("b",),
        premise=(
            "The destination checked at policy time must be the destination "
            "connected to; a name that re-resolves between check and connect "
            "is the same request, not a new one."
        ),
        source="Hangar #836, GHSA UI-TARS",
    ),
    TestSpec(
        id="SSRF-005",
        name="Redirect chain past the allowlist",
        severity=Severity.HIGH,
        surfaces=("b",),
        premise=(
            "An egress allowlist governs the final destination reached, not "
            "only the first hop; following a redirect does not exit the policy."
        ),
        source="ToolHive-class",
    ),
    TestSpec(
        id="EGRESS-001",
        name="Suffix confusion (api.example.com.evil.com)",
        severity=Severity.HIGH,
        surfaces=("b",),
        premise=(
            "Host allowlisting matches whole DNS labels, not string suffixes; "
            "api.example.com.evil.com is not within api.example.com."
        ),
        source="baseline",
    ),
    # --- Schema ------------------------------------------------------------ #
    TestSpec(
        id="SCHEMA-001",
        name="Silent schema expansion (new argument)",
        severity=Severity.MEDIUM,
        surfaces=("a", "b"),
        premise=(
            "A tool's input contract is what the intermediary vouched for; a "
            "server adding arguments after admission changes that contract and "
            "must be surfaced, not silently accepted."
        ),
        source="Hangar digest pinning",
    ),
    TestSpec(
        id="SCHEMA-002",
        name="Tool description rug pull (tool poisoning)",
        severity=Severity.MEDIUM,
        surfaces=("a", "b"),
        premise=(
            "The tool description an agent reasons over is part of the trust "
            "surface; a server mutating it after admission is a change the "
            "intermediary must detect."
        ),
        source="advisory: open-webui",
    ),
    TestSpec(
        id="SCHEMA-003",
        name="Tool shadowing / cross-upstream name collision",
        severity=Severity.HIGH,
        surfaces=("a", "b"),
        premise=(
            "A tool name resolves to exactly one upstream; a second upstream "
            "claiming the same name must not silently shadow or override the "
            "first."
        ),
        source="advisory: Docker MCP Gateway",
    ),
    # --- Session ----------------------------------------------------------- #
    TestSpec(
        id="SESSION-001",
        name="State leak across sessions after reconnect",
        severity=Severity.HIGH,
        surfaces=("f",),
        premise=(
            "Session state is bound to its session; reconnection or resumption "
            "must not expose one session's state, identity, or authority to "
            "another."
        ),
        source="agentgateway, Hangar #929/#802",
    ),
    # --- Secrets ----------------------------------------------------------- #
    TestSpec(
        id="SECRET-001",
        name="Env exfiltration via arguments / response",
        severity=Severity.CRITICAL,
        surfaces=("b",),
        premise=(
            "The intermediary's own secrets (environment, tokens) are outside "
            "every caller's and server's trust boundary; no argument or "
            "response path may induce their disclosure."
        ),
        source="baseline",
    ),
    # --- Audit (log is the subject of study; §13.1 exception applies) ------ #
    TestSpec(
        id="AUDIT-001",
        name="Action executed with no audit event",
        severity=Severity.MEDIUM,
        surfaces=("b", "e"),
        premise=(
            "A security-relevant action and its audit record are one atomic "
            "fact; an action that executes without a corresponding event is "
            "unaccountable."
        ),
        source="Hangar F4",
        notes=(
            "AUDIT-* test: the SUT's log IS the subject of study, so the "
            "'verdict never from the SUT's logs' rule (SPEC §3.1) is relaxed "
            "for this family only. The action is still driven and observed "
            "out-of-band; the audit record is then checked against it."
        ),
    ),
    TestSpec(
        id="AUDIT-002",
        name="Secrets / raw arguments in audit or trace",
        severity=Severity.MEDIUM,
        surfaces=("b",),
        premise=(
            "The audit trail is itself a disclosure surface; recording secrets "
            "or raw sensitive arguments turns an accountability mechanism into "
            "a leak."
        ),
        source="Hangar F7/F8",
        notes="AUDIT-* test: see AUDIT-001 note on the §3.1 relaxation.",
    ),
)


# --------------------------------------------------------------------------- #
# Validation.
# --------------------------------------------------------------------------- #


def validate(registry: tuple[TestSpec, ...] = REGISTRY) -> None:
    """Assert whole-registry invariants. Raises ``ValueError`` on violation."""
    ids = [t.id for t in registry]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate test IDs: {sorted(dupes)}")
    by_id = {t.id: t for t in registry}
    for t in registry:
        if t.superseded_by and t.superseded_by not in by_id:
            raise ValueError(f"{t.id}: superseded_by unknown ID {t.superseded_by}")
        if t.deprecated and not t.superseded_by:
            raise ValueError(f"{t.id}: deprecated tests must name a successor")


validate()


def active_tests(registry: tuple[TestSpec, ...] = REGISTRY) -> list[TestSpec]:
    return [t for t in registry if not t.deprecated]


# --------------------------------------------------------------------------- #
# Spec rendering. SPEC.md is generated from here; keep this deterministic.
# --------------------------------------------------------------------------- #

_GENERATED_MARKER = "<!-- GENERATED FROM mcpsb/registry.py — DO NOT EDIT BY HAND -->"


def render_spec(registry: tuple[TestSpec, ...] = REGISTRY) -> str:
    """Render the machine-generated section of ``SPEC.md`` from the registry.

    Only the registry-derived tables are generated. The prose sections of the
    spec (invariants, verdict dictionary, threat-model summary) live in
    ``SPEC.md`` above the marker and are hand-authored.
    """
    lines: list[str] = []
    lines.append(_GENERATED_MARKER)
    lines.append("")
    lines.append("## Severity registry")
    lines.append("")
    lines.append("Severity is an attribute of the *test*, frozen at ID creation.")
    lines.append("")
    lines.append("| Severity | Definition |")
    lines.append("| --- | --- |")
    for sev in sorted(SEVERITY_DEFINITIONS, key=lambda s: s.rank):
        lines.append(f"| {sev.value} | {SEVERITY_DEFINITIONS[sev]} |")
    lines.append("")
    lines.append("## Surfaces")
    lines.append("")
    lines.append("Each attack is executed on *every* surface it declares (§3.2).")
    lines.append("")
    lines.append("| Letter | Surface |")
    lines.append("| --- | --- |")
    for letter in sorted(SURFACE_LABELS):
        lines.append(f"| `{letter}` | {SURFACE_LABELS[letter]} |")
    lines.append("")
    lines.append("## Test registry")
    lines.append("")
    lines.append(f"{len(active_tests(registry))} active IDs.")
    lines.append("")
    lines.append("| ID | Name | Severity | Surfaces | Source |")
    lines.append("| --- | --- | --- | --- | --- |")
    for t in registry:
        if t.deprecated:
            continue
        surf = " ".join(f"`{s}`" for s in t.surfaces)
        lines.append(
            f"| {t.id} | {t.name} | {t.severity.value} | {surf} | {t.source} |"
        )
    lines.append("")
    lines.append("## Premises")
    lines.append("")
    lines.append(
        "Each test declares the trust-boundary assumption it makes (§3.3). A "
        "maintainer who disputes a FAIL disputes the premise, not the "
        "mechanism; a linked public document placing the boundary out of scope "
        "yields `DECLARED-OUT-OF-SCOPE`, not `FAIL`."
    )
    lines.append("")
    for t in registry:
        if t.deprecated:
            continue
        lines.append(f"### {t.id} — {t.name}")
        lines.append("")
        lines.append(f"*Severity:* {t.severity.value}  ")
        surf = ", ".join(f"`{s}` ({SURFACE_LABELS[s]})" for s in t.surfaces)
        lines.append(f"*Surfaces:* {surf}  ")
        lines.append(f"*Sub-IDs:* {', '.join(f'`{s}`' for s in t.surface_ids)}  ")
        lines.append("")
        lines.append(f"**Premise.** {t.premise}")
        if t.notes:
            lines.append("")
            lines.append(f"> {t.notes}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# CLI: regenerate or check the generated portion of SPEC.md.
# --------------------------------------------------------------------------- #

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SPEC_PATH = _REPO_ROOT / "SPEC.md"
_SPEC_HAND_MARKER = _GENERATED_MARKER


def _split_spec(text: str) -> tuple[str, str]:
    """Return (hand_authored_prefix, generated_suffix) of SPEC.md."""
    idx = text.find(_GENERATED_MARKER)
    if idx == -1:
        return text.rstrip() + "\n\n", ""
    return text[:idx], text[idx:]


def _compose_spec() -> str:
    existing = _SPEC_PATH.read_text() if _SPEC_PATH.exists() else ""
    prefix, _ = _split_spec(existing)
    if not prefix.strip():
        prefix = "# SPEC (MCPSB) — generated section only\n\n"
    return prefix.rstrip() + "\n\n" + render_spec()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MCPSB registry / SPEC.md tool.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--write", action="store_true", help="regenerate SPEC.md from the registry"
    )
    group.add_argument(
        "--check",
        action="store_true",
        help="fail if SPEC.md's generated section is stale (CI gate)",
    )
    args = parser.parse_args(argv)

    composed = _compose_spec()
    if args.write:
        _SPEC_PATH.write_text(composed)
        print(f"wrote {_SPEC_PATH.relative_to(_REPO_ROOT)}")
        return 0

    current = _SPEC_PATH.read_text() if _SPEC_PATH.exists() else ""
    if current != composed:
        print(
            "SPEC.md is out of sync with mcpsb/registry.py.\n"
            "Run `python -m mcpsb.registry --write` and commit the result.",
            file=sys.stderr,
        )
        return 1
    print("SPEC.md is in sync with the registry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
