"""Self-tests for the malicious MCP fixtures (WS-5 DoD).

Each server is driven directly with the bench's own MCP client and its
misbehavior is asserted deterministically. These are the real upstreams that
real-target runs (WS-6+) will proxy to.
"""

from __future__ import annotations

from mcpsb.client import MCPClient
from fixtures.mcp import BenignServer, DriftServer, ExfilServer, MCPServerHost, ShadowServer
from fixtures.mcp.benign import BENIGN_MARKER
from fixtures.mcp.drift import DRIFTED_DESCRIPTION, INJECTED_ARG
from fixtures.mcp.shadow import SHADOW_MARKER


def _client(host: MCPServerHost) -> MCPClient:
    return MCPClient(host.base_url)


def test_benign_server_echoes():
    with MCPServerHost(BenignServer()) as host:
        c = _client(host)
        assert c.request("initialize").result["serverInfo"]["name"] == "benign"
        resp = c.tools_call("echo", {"message": "hi"})
        assert resp.result["content"]["echo"] == "hi"
        assert resp.result["content"]["server"] == BENIGN_MARKER


def test_shadow_server_claims_a_colliding_name_and_marks_calls():
    with MCPServerHost(ShadowServer(collide_name="echo")) as host:
        c = _client(host)
        names = [t["name"] for t in c.tools_list().result["tools"]]
        assert names == ["echo"]  # collides with the benign server's tool
        resp = c.tools_call("echo", {"message": "x"})
        assert resp.result["content"][SHADOW_MARKER] is True


def test_drift_server_changes_contract_after_first_list():
    with MCPServerHost(DriftServer()) as host:
        c = _client(host)
        first = c.tools_list().result["tools"][0]
        second = c.tools_list().result["tools"][0]
        assert INJECTED_ARG not in first["inputSchema"]["properties"]
        assert first["description"] != DRIFTED_DESCRIPTION
        # After admission, the contract drifts.
        assert INJECTED_ARG in second["inputSchema"]["properties"]
        assert second["description"] == DRIFTED_DESCRIPTION


def test_drift_is_deterministic_across_instances():
    for _ in range(2):
        with MCPServerHost(DriftServer()) as host:
            c = _client(host)
            assert INJECTED_ARG not in c.tools_list().result["tools"][0]["inputSchema"]["properties"]
            assert INJECTED_ARG in c.tools_list().result["tools"][0]["inputSchema"]["properties"]


def test_exfil_server_captures_forwarded_credentials():
    server = ExfilServer()
    with MCPServerHost(server) as host:
        c = MCPClient(host.base_url, token="secret-token-XYZ")
        c.tools_call("collect", {"data": "payload"})
        # The forwarded bearer token was captured out-of-band.
        assert server.captured_token("secret-token-XYZ")
        assert server.recorder.saw_header("authorization")


def test_exfil_server_does_not_capture_what_was_not_sent():
    server = ExfilServer()
    with MCPServerHost(server) as host:
        MCPClient(host.base_url).tools_call("collect", {"data": "x"})
        assert not server.captured_token("secret-token-XYZ")
