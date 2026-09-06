"""Differential gate tests (WS-3 DoD).

Proves the gate mechanism end-to-end against the real controls:

* a well-formed attack (FAIL on vulnerable, PASS on secure) yields no violations;
* a mis-written attack (PASS on both) is caught;
* the verdict can be read from the observation plane (the egress attack), which
  is how real SSRF/egress attacks will work in WS-4.

The synthetic attacks drive the control over its real HTTP interface — the same
way WS-4 attacks will — so this exercises the controls, the harness, and the
observation integration together.
"""

from __future__ import annotations

import json
import urllib.request

import pytest

from mcpsb import testkit
from mcpsb.differential import differential
from mcpsb.observation import ObservationPlane
from mcpsb.testkit import all_attacks
from mcpsb.verdict import Verdict
from controls.secure.adapter import Adapter as SecureAdapter
from controls.vulnerable.adapter import Adapter as VulnerableAdapter


@pytest.fixture(autouse=True)
def _clean():
    testkit._reset_registry_for_tests()
    yield
    testkit._reset_registry_for_tests()


def _rpc(ctx, body: dict, token: str | None = None, path: str = "") -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = ctx.endpoint.base_url + path
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=3) as resp:  # noqa: S310 — localhost only
        return json.loads(resp.read())


def _factories():
    return (lambda: VulnerableAdapter(), lambda: SecureAdapter())


def test_wellformed_authz_attack_has_no_violations():
    # Reaching a hidden/restricted tool means the attack succeeded -> FAIL.
    @testkit.test(id="AUTHZ-002", surfaces="b", evidence="client_response")
    def attack(ctx):
        resp = _rpc(
            ctx,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "admin_ping"}},
            token="tok-alice-acme",
        )
        return Verdict.FAIL if "result" in resp else Verdict.PASS

    must_fail, must_pass = _factories()
    violations = differential(all_attacks(), must_fail, must_pass)
    assert violations == []


def test_miswritten_attack_is_caught():
    # Always-PASS never fails the vulnerable control, so the gate must reject it.
    @testkit.test(id="AUTH-002", surfaces="b", evidence="client_response")
    def attack(ctx):
        return Verdict.PASS

    must_fail, must_pass = _factories()
    violations = differential(all_attacks(), must_fail, must_pass)
    assert len(violations) == 1
    assert violations[0].sub_id == "AUTH-002.b"
    assert violations[0].on_must_fail is Verdict.PASS


def test_egress_attack_reads_verdict_from_observation_plane():
    # SSRF: fetch a host that resolves to loopback (the sink stands in for the
    # internal resource). Verdict comes from the sink, never the SUT response.
    @testkit.test(id="SSRF-001", surfaces="b", evidence="sink")
    def attack(ctx):
        sink = ctx.observation.sink
        sink.recorder.clear()
        _rpc(
            ctx,
            {"static": {"internal.svc": "127.0.0.1"}, "allowlist": ["api.example.com"]},
            path="/__egress__",
        )
        try:
            _rpc(
                ctx,
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": "fetch", "arguments": {"url": f"http://internal.svc:{sink.port}/steal"}}},
                token="tok-alice-acme",
            )
        except Exception:
            pass  # a blocked egress may surface as an error; the sink is the truth
        return Verdict.FAIL if sink.recorder.received(path="/steal") else Verdict.PASS

    obs = ObservationPlane().start()
    try:
        must_fail, must_pass = _factories()
        violations = differential(all_attacks(), must_fail, must_pass, observation=obs)
    finally:
        obs.stop()
    assert violations == []


def test_gate_with_no_attacks_is_vacuously_satisfied():
    must_fail, must_pass = _factories()
    assert differential(all_attacks(), must_fail, must_pass) == []
