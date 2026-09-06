"""Runner and report tests (WS-1).

Covers the verdict logic that does not depend on a specific attack: the
all-INCONCLUSIVE noop smoke run (the WS-1 DoD), plus the UNSUPPORTED / PASS /
FAIL / ERROR paths a real target will exercise, driven by a fake in-process
adapter and a temporarily registered attack.
"""

from __future__ import annotations

import json

import pytest

from mcpsb import runner, testkit
from mcpsb.adapter import Capability, Endpoint, PolicyBundle, UnsupportedPolicy
from mcpsb.registry import active_tests
from mcpsb.report import render_json, render_markdown
from mcpsb.verdict import EvidenceSource, Verdict, validate_evidence


@pytest.fixture(autouse=True)
def _clean_attacks():
    testkit._reset_registry_for_tests()
    yield
    testkit._reset_registry_for_tests()


# --- adapters used by the tests ------------------------------------------- #


class _NoopLike:
    name = "noop-like"

    def provision(self, bundle: PolicyBundle) -> Endpoint:
        return Endpoint(available=False, reason="no intermediary")

    def capabilities(self):
        return set()

    def teardown(self):
        return None


class _AvailableAdapter:
    """Available, exposes only surfaces a and b."""

    name = "fake"

    def __init__(self):
        self.torn_down = False

    def provision(self, bundle: PolicyBundle) -> Endpoint:
        return Endpoint(base_url="http://fake", available=True)

    def capabilities(self):
        # Exposes surfaces a and b, and can express per-principal authorization
        # (the family the registered-attack tests use); lacks the c/d/e surfaces.
        return {
            Capability.SURFACE_LIST,
            Capability.SURFACE_CALL,
            Capability.AUTHORIZATION,
            Capability.PRINCIPAL_BINDING,
        }

    def teardown(self):
        self.torn_down = True


def _expected_sub_id_count() -> int:
    return sum(len(t.surfaces) for t in active_tests())


# --- the DoD --------------------------------------------------------------- #


def test_noop_via_loader_is_all_inconclusive():
    adapter = runner.load_adapter("noop")
    report = runner.run(adapter, generated_at="2026-01-01T00:00:00+00:00")
    assert len(report.results) == _expected_sub_id_count()
    assert all(r.verdict is Verdict.INCONCLUSIVE for r in report.results)
    totals = report.totals()
    assert totals[Verdict.INCONCLUSIVE] == len(report.results)
    assert totals[Verdict.PASS] == 0 and totals[Verdict.FAIL] == 0


def test_teardown_is_always_called():
    adapter = _AvailableAdapter()
    runner.run(adapter)
    assert adapter.torn_down is True


# --- verdict paths against an available target ----------------------------- #


def test_unsupported_surface_is_reported_not_failed():
    # AUTHZ-001 declares surfaces b,c,d,e; the fake exposes only a,b. c/d/e must
    # be UNSUPPORTED — never FAIL (SPEC §4).
    report = runner.run(_AvailableAdapter())
    by_sub = {r.sub_id: r for r in report.results}
    assert by_sub["AUTHZ-001.b"].verdict is Verdict.INCONCLUSIVE  # supported, no attack
    for missing in ("AUTHZ-001.c", "AUTHZ-001.d", "AUTHZ-001.e"):
        assert by_sub[missing].verdict is Verdict.UNSUPPORTED


def test_missing_policy_capability_is_unsupported_not_failed():
    # TENANT-001 requires the TENANCY capability, which the fake adapter does not
    # declare. It must be UNSUPPORTED (SPEC §4), never FAIL.
    report = runner.run(_AvailableAdapter())
    by_sub = {r.sub_id: r for r in report.results}
    assert by_sub["TENANT-001.b"].verdict is Verdict.UNSUPPORTED
    assert "policy" in by_sub["TENANT-001.b"].reason


def _verify_family(family: str) -> None:
    """Register a positive control that verifies ``family`` so its PASSes stand
    (WS-D2). Without one, every PASS in the family degrades to INCONCLUSIVE."""

    @testkit.positive_control(family=family, evidence="client_response")
    def _pc(ctx):
        return Verdict.PASS


def test_registered_attack_pass_and_reason_flow_through():
    _verify_family("AUTHZ")

    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
    def _attack(ctx):
        ctx.reason = f"blocked on {ctx.surface}"
        ctx.evidence = {"sink": "no-hit"}
        return Verdict.PASS

    report = runner.run(_AvailableAdapter())
    by_sub = {r.sub_id: r for r in report.results}
    assert by_sub["AUTHZ-002.a"].verdict is Verdict.PASS
    assert by_sub["AUTHZ-002.a"].reason == "blocked on a"
    assert by_sub["AUTHZ-002.a"].evidence == {"sink": "no-hit"}


def test_attack_exception_is_error_not_fail():
    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
    def _attack(ctx):
        raise RuntimeError("boom")

    report = runner.run(_AvailableAdapter())
    by_sub = {r.sub_id: r for r in report.results}
    assert by_sub["AUTHZ-002.a"].verdict is Verdict.ERROR
    assert "RuntimeError" in by_sub["AUTHZ-002.a"].reason


def test_unsupported_policy_exception_maps_to_unsupported():
    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
    def _attack(ctx):
        raise UnsupportedPolicy("no tenant concept")

    report = runner.run(_AvailableAdapter())
    by_sub = {r.sub_id: r for r in report.results}
    assert by_sub["AUTHZ-002.a"].verdict is Verdict.UNSUPPORTED


def test_non_verdict_return_is_error():
    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
    def _attack(ctx):
        return "not a verdict"

    report = runner.run(_AvailableAdapter())
    by_sub = {r.sub_id: r for r in report.results}
    assert by_sub["AUTHZ-002.a"].verdict is Verdict.ERROR


# --- registration guards --------------------------------------------------- #


def test_cannot_register_unknown_id():
    with pytest.raises(ValueError, match="unknown ID"):

        @testkit.test(id="NOPE-999", surfaces="b", evidence="client_response")
        def _a(ctx):
            return Verdict.PASS


def test_cannot_register_undeclared_surface():
    # AUTH-002 declares only surface b; registering surface a must fail.
    with pytest.raises(ValueError, match="not declared"):

        @testkit.test(id="AUTH-002", surfaces="a", evidence="client_response")
        def _a(ctx):
            return Verdict.PASS


# --- D1: evidence_source gate ---------------------------------------------- #


def test_pass_carries_declared_evidence_source():
    _verify_family("AUTHZ")

    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
    def _attack(ctx):
        return Verdict.PASS

    report = runner.run(_AvailableAdapter())
    by_sub = {r.sub_id: r for r in report.results}
    r = by_sub["AUTHZ-002.a"]
    assert r.verdict is Verdict.PASS
    assert r.evidence_source is EvidenceSource.CLIENT_RESPONSE
    assert json.loads(render_json(report))["results"]
    # to_json surfaces it for the report / CI gates to key off.
    assert r.to_json()["evidence_source"] == "client_response"


def test_conclusive_without_evidence_source_becomes_error():
    # An attack that clears the stamped source cannot report a PASS (D1).
    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
    def _attack(ctx):
        ctx.evidence_source = None
        return Verdict.PASS

    report = runner.run(_AvailableAdapter())
    r = {x.sub_id: x for x in report.results}["AUTHZ-002.a"]
    assert r.verdict is Verdict.ERROR
    assert "evidence_source" in r.reason and r.evidence_source is None


def test_target_audit_outside_audit_family_is_error():
    # target_audit is admissible only for AUDIT-*; on any other ID a PASS/FAIL
    # sourced from the target's own log ERRORs rather than counting.
    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="target_audit")
    def _attack(ctx):
        return Verdict.PASS

    report = runner.run(_AvailableAdapter())
    r = {x.sub_id: x for x in report.results}["AUTHZ-002.a"]
    assert r.verdict is Verdict.ERROR
    assert "target_audit" in r.reason


def test_inconclusive_needs_no_evidence_source():
    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
    def _attack(ctx):
        ctx.evidence_source = None
        return Verdict.INCONCLUSIVE

    report = runner.run(_AvailableAdapter())
    r = {x.sub_id: x for x in report.results}["AUTHZ-002.a"]
    assert r.verdict is Verdict.INCONCLUSIVE


def test_decorator_rejects_unknown_evidence():
    with pytest.raises(ValueError, match="unknown evidence"):

        @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="hearsay")
        def _a(ctx):
            return Verdict.PASS


def test_validate_evidence_pure_function():
    # AUDIT-* may cite the target's own audit log; nothing else may.
    v, s, err = validate_evidence("AUDIT-001", Verdict.PASS, EvidenceSource.TARGET_AUDIT)
    assert v is Verdict.PASS and s is EvidenceSource.TARGET_AUDIT and err is None
    v, s, err = validate_evidence("SSRF-001", Verdict.PASS, EvidenceSource.TARGET_AUDIT)
    assert v is Verdict.ERROR and err
    v, s, err = validate_evidence("SSRF-001", Verdict.FAIL, None)
    assert v is Verdict.ERROR and err
    # Non-conclusive verdicts pass through untouched.
    v, s, err = validate_evidence("SSRF-001", Verdict.INCONCLUSIVE, None)
    assert v is Verdict.INCONCLUSIVE and err is None


# --- D2: positive-control gate --------------------------------------------- #


def test_pass_degrades_without_verified_positive_control():
    # No positive control for AUTHZ -> a PASS is indistinguishable from "blocks
    # everything", so it degrades to INCONCLUSIVE (never to PASS).
    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
    def _attack(ctx):
        return Verdict.PASS

    report = runner.run(_AvailableAdapter())
    r = {x.sub_id: x for x in report.results}["AUTHZ-002.a"]
    assert r.verdict is Verdict.INCONCLUSIVE
    assert "positive_control_missing" in r.reason


def test_pass_stands_with_verified_positive_control():
    _verify_family("AUTHZ")

    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
    def _attack(ctx):
        return Verdict.PASS

    report = runner.run(_AvailableAdapter())
    r = {x.sub_id: x for x in report.results}["AUTHZ-002.a"]
    assert r.verdict is Verdict.PASS
    assert report.verified_families() == frozenset({"AUTHZ"})


def test_failing_positive_control_does_not_verify_family():
    @testkit.positive_control(family="AUTHZ", evidence="client_response")
    def _pc(ctx):
        return Verdict.FAIL  # target rejected the legitimate request

    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
    def _attack(ctx):
        return Verdict.PASS

    report = runner.run(_AvailableAdapter())
    r = {x.sub_id: x for x in report.results}["AUTHZ-002.a"]
    assert r.verdict is Verdict.INCONCLUSIVE
    assert report.verified_families() == frozenset()
    pc = {p.family: p for p in report.positive_controls}["AUTHZ"]
    assert pc.verdict is Verdict.FAIL and not pc.verified


def test_fail_is_not_degraded_by_missing_positive_control():
    # An observed breach is real regardless of the positive control; only PASS
    # is gated.
    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
    def _attack(ctx):
        return Verdict.FAIL

    report = runner.run(_AvailableAdapter())
    r = {x.sub_id: x for x in report.results}["AUTHZ-002.a"]
    assert r.verdict is Verdict.FAIL


def test_pass_on_untested_version_is_withheld_as_error():
    # A target running an untested build must not yield a PASS/FAIL — the bench
    # withholds the verdict (ERROR), never a "correct but out of date" one.
    _verify_family("AUTHZ")

    class _OldBuild(_AvailableAdapter):
        def version(self):
            return "target/1.0.0"

        def tested_versions(self):
            return ">= 2.0.0"

        def supports_version(self, version):
            from mcpsb.versioning import version_supported

            return version_supported(version, minimum="2.0.0")

    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
    def _attack(ctx):
        return Verdict.PASS

    report = runner.run(_OldBuild())
    r = {x.sub_id: x for x in report.results}["AUTHZ-002.a"]
    assert r.verdict is Verdict.ERROR
    assert "outside the tested range" in r.reason and "1.0.0" in r.reason


def test_pass_on_tested_version_stands():
    _verify_family("AUTHZ")

    class _CurrentBuild(_AvailableAdapter):
        def version(self):
            return "target/2.5.0"

        def supports_version(self, version):
            from mcpsb.versioning import version_supported

            return version_supported(version, minimum="2.0.0")

    @testkit.test(id="AUTHZ-002", surfaces="ab", evidence="client_response")
    def _attack(ctx):
        return Verdict.PASS

    report = runner.run(_CurrentBuild())
    assert {x.sub_id: x for x in report.results}["AUTHZ-002.a"].verdict is Verdict.PASS


def test_adapter_version_is_threaded_into_report():
    class _Versioned(_AvailableAdapter):
        def version(self):
            return "fake/9.9.9"

    report = runner.run(_Versioned())
    assert report.version == "fake/9.9.9"
    assert json.loads(render_json(report))["version"] == "fake/9.9.9"


def test_missing_version_defaults_empty():
    # _AvailableAdapter has no version() -> empty, which the claim gate rejects.
    report = runner.run(_AvailableAdapter())
    assert report.version == ""


def test_positive_control_row_recorded_in_report_json():
    _verify_family("AUTHZ")
    report = runner.run(_AvailableAdapter())
    data = json.loads(render_json(report))
    fams = {p["family"]: p for p in data["positive_controls"]}
    assert fams["AUTHZ"]["verified"] is True
    assert fams["AUTHZ"]["verdict"] == "PASS"


# --- report rendering ------------------------------------------------------ #


def test_json_report_round_trips_and_has_no_aggregate_score():
    report = runner.run(_NoopLike(), generated_at="2026-01-01T00:00:00+00:00")
    data = json.loads(render_json(report))
    assert data["target"] == "noop-like"
    assert "score" not in data and "grade" not in data
    assert data["totals"]["INCONCLUSIVE"] == len(report.results)


def test_markdown_report_renders_matrix():
    report = runner.run(_NoopLike())
    md = render_markdown(report)
    assert "No aggregate score" in md
    assert "| Severity |" in md and "INCONC" in md
