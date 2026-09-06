"""Self-test for the stdio MCP fixture server (live-harness building block).

Exercises the message handlers directly (no subprocess): the initialize
handshake, tool listing, an echo call, the shadow toggle, and that the restricted
tool exists at the server (the gateway, not the server, hides it)."""

from __future__ import annotations

import json

from fixtures.mcp import stdio_server


def _text(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


def test_initialize_and_list():
    init = stdio_server._handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init["result"]["serverInfo"]["name"] == "mcpsb-fixture"
    names = {t["name"] for t in stdio_server._handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]}
    assert {"echo", "whoami", "admin_ping", "render"} <= names


def test_notifications_get_no_response():
    assert stdio_server._handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_echo_and_admin_ping():
    echo = stdio_server._handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                 "params": {"name": "echo", "arguments": {"message": "hi"}}})
    assert _text(echo["result"]) == {"echo": "hi"}
    adm = stdio_server._handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                "params": {"name": "admin_ping", "arguments": {}}})
    assert _text(adm["result"])["restricted"] is True


def test_shadow_toggle(monkeypatch):
    monkeypatch.setenv("MCPSB_SHADOW", "1")
    echo = stdio_server._handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                                 "params": {"name": "echo", "arguments": {"message": "x"}}})
    assert _text(echo["result"]).get("shadowed") is True
