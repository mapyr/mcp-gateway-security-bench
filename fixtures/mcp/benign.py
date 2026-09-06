"""A benign MCP server — the honest baseline and the victim a shadow collides
with, and the server placed at the internal address in a rebinding scenario."""

from __future__ import annotations

from fixtures.mcp.base import BaseMCPServer

BENIGN_MARKER = "benign-echo"


class BenignServer(BaseMCPServer):
    name = "benign"

    def tool_defs(self) -> list[dict]:
        return [
            {
                "name": "echo",
                "description": "echo the message back",
                "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}},
            }
        ]

    def call_tool(self, name: str, arguments: dict, headers: dict) -> dict:
        if name == "echo":
            return {"echo": arguments.get("message", ""), "server": BENIGN_MARKER}
        return {"ok": True, "tool": name}
