"""Registry invariant tests (WS-0).

These lock the properties that the rest of the project relies on: unique frozen
IDs, mandatory premises, known surfaces, and — critically — that SPEC.md is a
faithful render of the registry. If SPEC.md drifts, this fails, the same gate as
`ci/check_spec_drift.py` but visible in the normal test run.
"""

from __future__ import annotations

import re

from mcpsb import registry
from mcpsb.registry import REGISTRY, Severity, Surface


def test_ids_are_unique():
    ids = [t.id for t in REGISTRY]
    assert len(ids) == len(set(ids))


def test_registry_has_expected_size():
    # 23 core IDs (SPEC §6). A change here is a spec change, not a test edit.
    assert len(registry.active_tests()) == 23


def test_every_test_has_a_premise():
    for t in REGISTRY:
        assert t.premise.strip(), f"{t.id} has no premise"


def test_premise_is_not_a_paraphrase_of_the_name():
    # Weak but useful guard: the premise must not be merely the name echoed back.
    for t in REGISTRY:
        assert t.premise.strip().lower() != t.name.strip().lower(), t.id
        assert len(t.premise) > len(t.name), t.id


def test_surfaces_are_known_and_nonempty():
    valid = {s.value for s in Surface}
    for t in REGISTRY:
        assert t.surfaces, f"{t.id} declares no surface"
        assert set(t.surfaces) <= valid, f"{t.id} has unknown surface"
        assert len(set(t.surfaces)) == len(t.surfaces), f"{t.id} duplicate surface"


def test_surface_sub_ids_are_well_formed():
    for t in REGISTRY:
        for sub in t.surface_ids:
            assert re.fullmatch(rf"{re.escape(t.id)}\.[a-f]", sub), sub


def test_severity_is_frozen_enum():
    for t in REGISTRY:
        assert isinstance(t.severity, Severity)


def test_audit_family_documents_the_log_exception():
    # AUDIT-* tests relax the "verdict never from the SUT log" rule (SPEC §3.1);
    # each must say so in its notes, so the exception is never silent.
    for t in REGISTRY:
        if t.id.startswith("AUDIT-"):
            assert t.notes.strip(), f"{t.id} must document the §3.1 relaxation"


def test_validate_passes():
    registry.validate()


def test_spec_md_matches_registry():
    # The same check ci/check_spec_drift.py runs, surfaced in the test suite.
    from mcpsb.registry import _SPEC_PATH, _compose_spec  # noqa: PLC0415

    assert _SPEC_PATH.exists(), "SPEC.md missing; run `python -m mcpsb.registry --write`"
    assert _SPEC_PATH.read_text() == _compose_spec(), (
        "SPEC.md is stale; run `python -m mcpsb.registry --write` and commit."
    )
