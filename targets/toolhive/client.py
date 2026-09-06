"""ToolHive transport client (WS-6).

ToolHive's proxy speaks Streamable HTTP (default since CLI v0.6.0) at ``/mcp``.
The transport itself is generic, so this just binds the shared Streamable-HTTP
client to ToolHive's endpoint path; attacks are unchanged.

Source: https://github.com/stacklok/toolhive/issues/2920 (/mcp = streamable-http).
"""

from __future__ import annotations

from mcpsb.streamable import StreamableHttpClient, make_factory

ToolHiveClient = StreamableHttpClient
factory = make_factory("/mcp")
