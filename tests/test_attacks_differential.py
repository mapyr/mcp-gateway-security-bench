"""Run the differential gate over the real attack corpus (WS-4).

This is the same check ``ci/check_differential.py`` performs, surfaced in the
test suite: every registered attack must be FAIL on the vulnerable control and
PASS on the secure one. It also asserts each attack covers all the surface
letters the registry declares for its ID (invariant #5).
"""

from __future__ import annotations

from mcpsb import testkit
from mcpsb.attackloader import import_attacks
from mcpsb.differential import differential
from mcpsb.observation import ObservationPlane
from mcpsb.registry import REGISTRY
from mcpsb.testkit import all_attacks
from controls.secure.adapter import Adapter as SecureAdapter
from controls.vulnerable.adapter import Adapter as VulnerableAdapter

_REGISTRY_BY_ID = {t.id: t for t in REGISTRY}


def _load() -> list:
    testkit._reset_registry_for_tests()
    import_attacks()
    return all_attacks()


def test_all_registered_attacks_pass_the_differential_gate():
    attacks = _load()
    assert attacks, "no attacks registered"
    obs = ObservationPlane().start()
    try:
        violations = differential(
            attacks, lambda: VulnerableAdapter(), lambda: SecureAdapter(), observation=obs
        )
    finally:
        obs.stop()
        testkit._reset_registry_for_tests()
    assert violations == [], "\n".join(f"{v.sub_id}: {v.message}" for v in violations)


def test_each_attack_covers_all_declared_surfaces():
    attacks = _load()
    try:
        for attack in attacks:
            declared = set(_REGISTRY_BY_ID[attack.test_id].surfaces)
            covered = set(attack.surfaces)
            assert covered == declared, (
                f"{attack.test_id} covers {sorted(covered)}, "
                f"registry declares {sorted(declared)} (invariant #5)"
            )
    finally:
        testkit._reset_registry_for_tests()
