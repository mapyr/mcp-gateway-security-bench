"""Control smoke tests (WS-3 DoD): both controls start and answer, and the
policies are polar so the differential gate's premise is possible."""

from __future__ import annotations

import json
import urllib.request

import pytest

from mcpsb.runner import load_adapter
from controls.common.policy import assert_policies_are_polar


def _rpc(base: str, body: dict, token: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base, data=json.dumps(body).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=3) as resp:  # noqa: S310 — localhost only
        return json.loads(resp.read())


def test_policies_are_polar():
    assert_policies_are_polar()


@pytest.mark.parametrize("name", ["secure", "vulnerable"])
def test_control_starts_and_initializes(name):
    adapter = load_adapter(name)
    endpoint = adapter.provision(_empty_bundle())
    try:
        assert endpoint.available
        ini = _rpc(endpoint.base_url, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert ini["result"]["serverInfo"]["name"] == name
        # tools/call echo as an authenticated principal works on both.
        echo = _rpc(
            endpoint.base_url,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "echo", "arguments": {"message": "hi"}}},
            token="tok-alice-acme",
        )
        assert echo["result"]["content"]["echo"] == "hi"
    finally:
        adapter.teardown()


def test_secure_blocks_and_vulnerable_allows_unauth_list():
    secure = load_adapter("secure")
    vuln = load_adapter("vulnerable")
    s_ep = secure.provision(_empty_bundle())
    v_ep = vuln.provision(_empty_bundle())
    try:
        s_list = _rpc(s_ep.base_url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        v_list = _rpc(v_ep.base_url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert "error" in s_list, "secure must require auth for tools/list"
        assert "result" in v_list, "vulnerable leaks tools/list unauthenticated"
    finally:
        secure.teardown()
        vuln.teardown()


def _empty_bundle():
    from mcpsb.adapter import PolicyBundle

    return PolicyBundle.empty()
