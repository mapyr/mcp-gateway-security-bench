"""Attack registration and execution context (WS-1 skeleton for WS-4).

Attacks are Python callables registered against a registry test ID with the
``@mcpsb.test`` decorator. The runner looks an attack up by test ID and invokes
it once per declared surface. In WS-1 nothing is registered yet, which is
exactly why a run reports ``INCONCLUSIVE`` for every sub-ID — the harness is
complete but has no attack to establish the test.

The decorator does *not* let an attack invent an ID or a severity: the ``id``
must already exist in ``mcpsb.registry`` and the surfaces must be a subset of
what the registry declares for it (invariants #4, #5). This is where a
mismatch between an attack and the spec is caught at import time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from mcpsb.adapter import Endpoint, PolicyBundle
from mcpsb.registry import REGISTRY
from mcpsb.verdict import Verdict

_REGISTRY_BY_ID = {t.id: t for t in REGISTRY}

#: A family is the ID prefix before the ``-NNN`` (AUTH-001 -> AUTH). Positive
#: controls are keyed by family, not by ID (WS-D2).
FAMILIES = frozenset(t.id.rsplit("-", 1)[0] for t in REGISTRY)


def family_of(test_id: str) -> str:
    """The family a test ID belongs to: ``AUTH-001`` -> ``AUTH``."""
    return test_id.rsplit("-", 1)[0]


@dataclass
class AttackContext:
    """Everything an attack needs to run one sub-ID.

    The observation-plane clients (sink, DNS, IMDS, redirector) are attached in
    WS-2; until then the field is a placeholder. An attack returns a
    :class:`~mcpsb.verdict.Verdict` derived from what those clients recorded —
    never from ``endpoint`` responses (invariant #1), except the ``AUDIT-*``
    family.
    """

    sub_id: str
    test_id: str
    surface: str
    endpoint: Endpoint
    bundle: PolicyBundle
    observation: object | None = None  # WS-2: observation-plane client bundle
    scenario: object | None = None  # mcpsb.scenario.Scenario: abstract-role handles
    #: Adapter-provided factory (base_url, token) -> MCP client, so attacks stay
    #: transport-neutral. None means use the baseline JSON-RPC-over-HTTP client.
    client_factory: object | None = None
    #: Set by the attack to explain its verdict and point at out-of-band proof.
    reason: str = ""
    #: Where the verdict's evidence came from (mcpsb.verdict.EvidenceSource).
    #: Mandatory for a PASS/FAIL (D1): the runner turns a conclusive verdict with
    #: no source — or target_audit outside AUDIT-* — into ERROR.
    evidence_source: object | None = None
    evidence: dict[str, str] = field(default_factory=dict)
    scratch: dict[str, str] = field(default_factory=dict)


#: An attack: given a context, return a verdict. Raising maps to ERROR.
AttackFn = Callable[[AttackContext], Verdict]


@dataclass(frozen=True)
class RegisteredAttack:
    test_id: str
    surfaces: tuple[str, ...]
    fn: AttackFn
    #: The evidence source a conclusive verdict from this attack carries (D1).
    #: The runner stamps it onto the context before the attack runs.
    evidence_source: "object | None" = None


_ATTACKS: dict[str, RegisteredAttack] = {}


def test(*, id: str, surfaces: str, evidence: str) -> Callable[[AttackFn], AttackFn]:
    """Register an attack for a registry test ID.

    ``surfaces`` is a string of surface letters the attack implements, e.g.
    ``"ab"``. It must be a subset of the surfaces the registry declares for the
    ID; a family must ultimately cover *all* of them (invariant #5), which the
    runner verifies against the registry at run time.

    ``evidence`` names where this attack's conclusive verdicts come from
    (``mcpsb.verdict.EvidenceSource`` value): ``client_response``, ``sink``,
    ``dns``, ``imds``, or ``target_audit`` (the last only for the AUDIT-* family).
    The runner stamps it onto the context before the attack runs and validates it
    (D1) — a PASS/FAIL with no source, or target_audit outside AUDIT-*, ERRORs.
    """
    from mcpsb.verdict import EvidenceSource  # local import avoids a cycle

    try:
        source = EvidenceSource(evidence)
    except ValueError:
        raise ValueError(
            f"@mcpsb.test({id}): unknown evidence {evidence!r}; expected one of "
            f"{[e.value for e in EvidenceSource]}"
        )

    def decorate(fn: AttackFn) -> AttackFn:
        spec = _REGISTRY_BY_ID.get(id)
        if spec is None:
            raise ValueError(
                f"@mcpsb.test: unknown ID {id!r}. New IDs are a spec-change to "
                f"mcpsb/registry.py (invariant #4), not a decorator argument."
            )
        letters = tuple(surfaces)
        unknown = set(letters) - set(spec.surfaces)
        if unknown:
            raise ValueError(
                f"@mcpsb.test({id}): surfaces {sorted(unknown)} are not declared "
                f"for this ID (declared: {list(spec.surfaces)})."
            )
        if id in _ATTACKS:
            raise ValueError(f"@mcpsb.test: duplicate registration for {id!r}")
        _ATTACKS[id] = RegisteredAttack(
            test_id=id, surfaces=letters, fn=fn, evidence_source=source
        )
        return fn

    return decorate


@dataclass(frozen=True)
class PositiveControl:
    """A legitimate action a target must accept, one per family (WS-D2).

    Its whole purpose is discrimination: a PASS in a family only means something
    if the target also *accepts* that family's legitimate request. If the family
    has no verified positive control on a target, every PASS in the family
    degrades to INCONCLUSIVE (``positive_control_missing``) — a target that
    blocks everything must not be scored as if it blocked selectively.
    """

    family: str
    evidence_source: "object"
    fn: AttackFn


_POSITIVE: dict[str, PositiveControl] = {}


def positive_control(*, family: str, evidence: str) -> Callable[[AttackFn], AttackFn]:
    """Register the positive control for a family (WS-D2).

    The control returns ``Verdict.PASS`` when the target accepted the family's
    legitimate request (family verified), and anything else when it did not.
    ``evidence`` follows the same D1 vocabulary as ``@test``.
    """
    from mcpsb.verdict import EvidenceSource  # local import avoids a cycle

    if family not in FAMILIES:
        raise ValueError(
            f"@positive_control: unknown family {family!r}; known: {sorted(FAMILIES)}"
        )
    try:
        source = EvidenceSource(evidence)
    except ValueError:
        raise ValueError(
            f"@positive_control({family}): unknown evidence {evidence!r}; expected "
            f"one of {[e.value for e in EvidenceSource]}"
        )

    def decorate(fn: AttackFn) -> AttackFn:
        if family in _POSITIVE:
            raise ValueError(f"@positive_control: duplicate control for {family!r}")
        _POSITIVE[family] = PositiveControl(family=family, evidence_source=source, fn=fn)
        return fn

    return decorate


def get_positive_control(family: str) -> PositiveControl | None:
    return _POSITIVE.get(family)


def all_positive_controls() -> list[PositiveControl]:
    return [_POSITIVE[k] for k in sorted(_POSITIVE)]


def get_attack(test_id: str) -> RegisteredAttack | None:
    return _ATTACKS.get(test_id)


def registered_ids() -> set[str]:
    return set(_ATTACKS)


def all_attacks() -> list[RegisteredAttack]:
    """Every registered attack, ordered by test ID for deterministic runs."""
    return [_ATTACKS[k] for k in sorted(_ATTACKS)]


def _reset_registry_for_tests() -> None:
    """Test-only: clear registered attacks between unit tests."""
    _ATTACKS.clear()
    _POSITIVE.clear()
