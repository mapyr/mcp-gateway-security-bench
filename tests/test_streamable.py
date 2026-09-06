"""Streamable-HTTP client tests (WS-6/7).

Validates the shared transport client end-to-end against a stdlib fixture MCP
server, including the best-effort initialize handshake (the fixture returns no
session id, so the client proceeds sessionless — exercising that path).
"""

from __future__ import annotations

from mcpsb.streamable import StreamableHttpClient, make_factory
from fixtures.mcp import BenignServer, MCPServerHost


def test_streamable_client_drives_a_fixture():
    with MCPServerHost(BenignServer()) as host:
        c = StreamableHttpClient(host.base_url, mcp_path="")  # fixture serves at root
        resp = c.tools_call("echo", {"message": "hi"})
        assert resp.result["content"]["echo"] == "hi"
        # Best-effort handshake ran; the fixture returns no session id.
        assert c._handshake_done is True and c._session_id is None


def test_factory_binds_mcp_path():
    client = make_factory("/mcp")("http://example.test:9/base", "tok")
    assert client.mcp_url == "http://example.test:9/base/mcp"
    assert client.token == "tok"
