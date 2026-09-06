"""WS-D3: claims derived from run data + the consistency gate's invariants."""

from __future__ import annotations

from mcpsb.report.claims import claim_violations, derive_claims, render_summary


def _report(target, *, version="v1", results=None, positive=None):
    return {
        "target": target,
        "version": version,
        "results": results or [],
        "positive_controls": positive or [],
    }


def _res(verdict, source=None):
    return {"sub_id": "X-001.a", "verdict": verdict, "evidence_source": source}


def _pc(family, verified):
    return {"family": family, "verdict": "PASS" if verified else "FAIL", "verified": verified}


def test_derive_live_targets_and_pass():
    reports = [
        _report("a", results=[_res("INCONCLUSIVE")]),
        _report("b", results=[_res("PASS", "client_response")], positive=[_pc("AUTH", True)]),
    ]
    c = derive_claims(reports)
    assert c.live_targets == ["b"]  # only b has a non-INCONCLUSIVE verdict
    assert c.targets_with_pass == ["b"]
    assert c.pass_without_positive_control == []


def test_observation_plane_only_when_sourced_from_plane():
    # A PASS sourced from the client response does not support the obs-plane claim.
    reports = [_report("a", results=[_res("PASS", "client_response")], positive=[_pc("AUTH", True)])]
    assert derive_claims(reports).observation_plane is False
    # A FAIL sourced from the sink does.
    reports = [_report("b", results=[_res("FAIL", "sink")])]
    c = derive_claims(reports)
    assert c.observation_plane is True and c.observation_plane_targets == ["b"]


def test_missing_version_is_a_violation():
    reports = [_report("a", version="", results=[_res("INCONCLUSIVE")])]
    problems = claim_violations(reports)
    assert any("empty version" in p for p in problems)


def test_pass_without_positive_control_is_a_violation():
    reports = [_report("a", results=[_res("PASS", "client_response")], positive=[_pc("AUTH", False)])]
    problems = claim_violations(reports)
    assert any("no verified positive control" in p for p in problems)


def test_clean_reports_have_no_violations():
    reports = [_report("a", results=[_res("PASS", "sink")], positive=[_pc("SSRF", True)])]
    assert claim_violations(reports) == []


def test_summary_omits_observation_claim_when_unsupported():
    reports = [_report("a", results=[_res("PASS", "client_response")], positive=[_pc("AUTH", True)])]
    summary = render_summary(reports)
    assert "no observation-plane claim is made" in summary
    assert "confirmed by the out-of-band observation plane" not in summary


def test_summary_makes_observation_claim_when_supported():
    reports = [_report("a", results=[_res("FAIL", "sink")])]
    summary = render_summary(reports)
    assert "confirmed by the out-of-band observation plane" in summary


def test_summary_reports_no_live_target_when_all_inconclusive():
    # A target is "live" once it is provisioned enough to answer at all — the
    # runner only emits UNSUPPORTED after the endpoint is available, so only an
    # all-INCONCLUSIVE report means the target was never exercised.
    reports = [_report("a", results=[_res("INCONCLUSIVE")]), _report("b", results=[_res("INCONCLUSIVE")])]
    summary = render_summary(reports)
    assert "No target was exercised live" in summary


def test_unsupported_counts_as_live_because_it_required_provisioning():
    reports = [_report("a", results=[_res("UNSUPPORTED")])]
    assert derive_claims(reports).live_targets == ["a"]
