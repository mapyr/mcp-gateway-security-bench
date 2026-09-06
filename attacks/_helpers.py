"""Shared attack helpers (not an attack itself; the gate importer skips ``_*``).

Nothing here knows any target: it is thin sugar over the neutral MCP client and
the verdict vocabulary.
"""

from __future__ import annotations

from mcpsb.client import MCPClient
from mcpsb.testkit import AttackContext
from mcpsb.verdict import Verdict


def client(ctx: AttackContext, token: str | None = None) -> MCPClient:
    """The MCP client for the target under test. Transport-neutral: a target
    whose transport differs from the baseline provides a ``client_factory`` via
    its adapter; otherwise the baseline JSON-RPC-over-HTTP client is used."""
    if ctx.client_factory is not None:
        return ctx.client_factory(ctx.endpoint.base_url, token)
    return MCPClient(ctx.endpoint.base_url, token=token)


def served_or_blocked(ctx: AttackContext, response) -> Verdict:
    """Verdict from what the attacking client received — a legitimate observation
    surface (SPEC §3.1). The attack SUCCEEDED (FAIL) only if it got a usable
    result with a 2xx status; anything else — a JSON-RPC error, or an HTTP 4xx/5xx
    such as a 401 from a real gateway — means it was blocked (PASS). The evidence
    source (client_response) is declared on the attack's @mcpsb.test decorator."""
    served = response.result is not None and response.status < 400
    if served:
        ctx.reason = f"{ctx.surface}: attack succeeded (served a result)"
        return Verdict.FAIL
    detail = _err(response) if response.is_error else f"HTTP {response.status}"
    ctx.reason = f"{ctx.surface}: blocked ({detail})"
    return Verdict.PASS


def _err(response) -> str:
    if isinstance(response.body, dict):
        err = response.body.get("error", "error")
        if isinstance(err, dict):
            return str(err.get("message", "error"))
        return str(err)
    return "error"


def batch_entry(response, rpc_id: int):
    """Return the batch sub-response with the given id, or None."""
    if isinstance(response.body, list):
        for item in response.body:
            if isinstance(item, dict) and item.get("id") == rpc_id:
                return item
    return None


def _tools(response) -> list:
    return (response.result or {}).get("tools", []) if response.result else []


def tool_names(response) -> list:
    return [t.get("name") for t in _tools(response) if isinstance(t, dict)]


def tool_def(response, name: str):
    for t in _tools(response):
        if isinstance(t, dict) and t.get("name") == name:
            return t
    return None


def schema_props(response, name: str) -> set:
    definition = tool_def(response, name) or {}
    return set((definition.get("inputSchema", {}) or {}).get("properties", {}))


def description(response, name: str):
    definition = tool_def(response, name) or {}
    return definition.get("description")

