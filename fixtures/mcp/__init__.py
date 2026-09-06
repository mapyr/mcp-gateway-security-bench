"""Malicious (and one benign) MCP servers — the attacker-controlled upstreams
from the threat model (WS-5).

Each is a small, deterministic MCP server (JSON-RPC over HTTP) that misbehaves in
exactly one way: shadowing another server's tool name, drifting its schema after
admission, capturing everything the intermediary forwards to it (exfil), or
serving as the internal target of a rebinding upstream. A target under test
(WS-6+) is configured to proxy to these; the bench can also drive them directly,
which is how the self-tests validate them.

The control intermediary simulates these behaviors internally (via /__drift__,
/__shadow__, /__egress__) so the attack corpus can be validated without a real
target. These fixtures are the real thing the same attacks exercise once a real
target proxies to them.
"""

from fixtures.mcp.base import BaseMCPServer, MCPServerHost, Received
from fixtures.mcp.benign import BenignServer
from fixtures.mcp.drift import DriftServer
from fixtures.mcp.exfil import ExfilServer
from fixtures.mcp.shadow import ShadowServer

__all__ = [
    "BaseMCPServer",
    "MCPServerHost",
    "Received",
    "BenignServer",
    "DriftServer",
    "ExfilServer",
    "ShadowServer",
]
