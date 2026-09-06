#!/usr/bin/env python3
"""CI gate: the reference controls behave as their names promise.

Runs the full bench (23 attacks over 35 sub-IDs, observation plane, real HTTP)
against both controls and asserts the end-to-end invariant that underpins the
whole project:

* ``vulnerable`` — every implemented sub-ID is FAIL (nothing is protected);
* ``secure``     — every implemented sub-ID is PASS (everything is protected).

This is stronger than the differential gate (which compares per attack): it
asserts the *aggregate* report over a live run, catching any regression where a
control drifts from all-FAIL / all-PASS.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from mcpsb.attackloader import import_attacks  # noqa: E402
from mcpsb.observation import ObservationPlane  # noqa: E402
from mcpsb.positiveloader import import_positive_controls  # noqa: E402
from mcpsb.runner import load_adapter, run  # noqa: E402
from mcpsb.verdict import Verdict  # noqa: E402


def _run(target: str, obs) -> list:
    return run(load_adapter(target), observation=obs).results


def main() -> int:
    import_attacks()
    import_positive_controls()
    obs = ObservationPlane().start()
    try:
        vuln = _run("vulnerable", obs)
        obs.reset()
        secure = _run("secure", obs)
    finally:
        obs.stop()

    problems: list[str] = []
    for r in vuln:
        if r.verdict is not Verdict.FAIL:
            problems.append(f"vulnerable/{r.sub_id}: expected FAIL, got {r.verdict.value}")
    for r in secure:
        if r.verdict is not Verdict.PASS:
            problems.append(f"secure/{r.sub_id}: expected PASS, got {r.verdict.value}")

    if problems:
        print("Controls invariant FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    print(
        f"Controls invariant OK: vulnerable all-FAIL ({len(vuln)}), "
        f"secure all-PASS ({len(secure)})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
