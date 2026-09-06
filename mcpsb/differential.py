"""The differential gate (GOVERNANCE §3).

Every attack must be FAIL on a deliberately vulnerable intermediary and PASS on a
deliberately secure one. A test that is not both does not exist: if it does not
fail the vulnerable control it proves nothing, and if it does not pass the secure
control it is mis-written (or the secure control is wrong). This module runs each
registered attack against two adapters and reports every deviation.

It is target-agnostic on purpose: it takes a "must-fail" and a "must-pass"
adapter factory. ``ci/check_differential.py`` supplies the reference controls.
The gate makes no assumption that the two adapters are *the* controls — only that
one must fail every attack and the other must pass every attack.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from mcpsb.adapter import Adapter, PolicyBundle
from mcpsb.testkit import AttackContext, RegisteredAttack
from mcpsb.verdict import Verdict, validate_evidence

AdapterFactory = Callable[[], Adapter]


@dataclass
class DifferentialViolation:
    sub_id: str
    on_must_fail: Verdict
    on_must_pass: Verdict
    message: str


def _run_attack(factory: AdapterFactory, attack: RegisteredAttack, observation) -> dict[str, Verdict]:
    adapter = factory()
    if observation is not None and hasattr(observation, "reset"):
        observation.reset()
    endpoint = adapter.provision(PolicyBundle.empty())
    if observation is not None and hasattr(adapter, "wire_observation"):
        adapter.wire_observation(observation)
    scenario = adapter.scenario() if hasattr(adapter, "scenario") else None
    client_factory = adapter.client_factory() if hasattr(adapter, "client_factory") else None
    verdicts: dict[str, Verdict] = {}
    try:
        for letter in attack.surfaces:
            sub_id = f"{attack.test_id}.{letter}"
            ctx = AttackContext(
                sub_id=sub_id,
                test_id=attack.test_id,
                surface=letter,
                endpoint=endpoint,
                bundle=PolicyBundle.empty(),
                observation=observation,
                scenario=scenario,
                client_factory=client_factory,
            )
            ctx.evidence_source = attack.evidence_source  # D1: declared at registration
            try:
                verdict = attack.fn(ctx)
            except Exception:  # noqa: BLE001 — a crashing attack is a violation, surfaced as ERROR
                verdict = Verdict.ERROR
            if not isinstance(verdict, Verdict):
                verdict = Verdict.ERROR
            # D1 applies here too: an attack that doesn't declare a valid
            # evidence_source ERRORs, so the differential gate catches it.
            verdict, _src, _err = validate_evidence(attack.test_id, verdict, ctx.evidence_source)
            verdicts[sub_id] = verdict
    finally:
        adapter.teardown()
    return verdicts


def differential(
    attacks: Iterable[RegisteredAttack],
    must_fail: AdapterFactory,
    must_pass: AdapterFactory,
    observation=None,
) -> list[DifferentialViolation]:
    """Return every attack sub-ID that is not FAIL-on-``must_fail`` and
    PASS-on-``must_pass``. An empty list means the gate is satisfied."""
    violations: list[DifferentialViolation] = []
    for attack in attacks:
        failed = _run_attack(must_fail, attack, observation)
        passed = _run_attack(must_pass, attack, observation)
        for sub_id in failed:
            fv = failed[sub_id]
            pv = passed.get(sub_id, Verdict.ERROR)
            if fv is not Verdict.FAIL or pv is not Verdict.PASS:
                violations.append(
                    DifferentialViolation(
                        sub_id=sub_id,
                        on_must_fail=fv,
                        on_must_pass=pv,
                        message=(
                            f"expected FAIL on must-fail control and PASS on "
                            f"must-pass control; got {fv.value} / {pv.value}"
                        ),
                    )
                )
    return violations
