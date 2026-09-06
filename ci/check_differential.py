#!/usr/bin/env python3
"""CI gate: every attack is FAIL on `vulnerable` and PASS on `secure`.

Discovers and imports every attack module under ``attacks/`` (registering them
via ``@mcpsb.test``), then runs the differential against the two reference
controls with a live observation plane. Any attack that is not FAIL-on-vulnerable
and PASS-on-secure fails the build (GOVERNANCE §3).

With no attacks yet (before WS-4) the gate passes and says so — it never
silently claims coverage it does not have.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from mcpsb.attackloader import import_attacks as _import_attacks  # noqa: E402
from mcpsb.differential import differential  # noqa: E402
from mcpsb.observation import ObservationPlane  # noqa: E402
from mcpsb.testkit import all_attacks  # noqa: E402


def _vulnerable_factory():
    from mcpsb.runner import load_adapter

    return load_adapter("vulnerable")


def _secure_factory():
    from mcpsb.runner import load_adapter

    return load_adapter("secure")


def main() -> int:
    modules = _import_attacks()
    attacks = all_attacks()
    if not attacks:
        print(
            f"Differential gate: no attacks registered "
            f"({modules} attack module(s) scanned). Nothing to gate yet."
        )
        return 0

    obs = ObservationPlane().start()
    try:
        violations = differential(attacks, _vulnerable_factory, _secure_factory, observation=obs)
    finally:
        obs.stop()

    if violations:
        print(
            f"Differential gate FAILED: {len(violations)} attack sub-ID(s) are "
            f"not FAIL-on-vulnerable/PASS-on-secure:",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  {v.sub_id}: {v.message}", file=sys.stderr)
        return 1

    print(
        f"Differential gate OK: {len(attacks)} attack(s) are FAIL-on-vulnerable "
        f"and PASS-on-secure."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
