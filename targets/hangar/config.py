"""Translate the bench's policy into MCP Hangar configuration (config.yaml).

Hangar is configured by a YAML file: an ``auth:`` block (OIDC / API key, RBAC
role assignments, per-tenant audiences) and an ``mcp_servers:`` map whose ``tools:``
dict form is an *enforced* allow/deny policy. Pure functions, unit-testable
without Hangar present.

Reference: the mcp-hangar repo README and ``auth/config.py`` schema.
"""

from __future__ import annotations


def generate_auth_block(
    *,
    issuer: str,
    audience: str,
    resource_uri: str,
    require_tenant: bool = True,
    strict_tenant_audience: bool = True,
    tenant_audiences: dict[str, str] | None = None,
    role_assignments: list[dict] | None = None,
) -> dict:
    """The secure ``auth:`` block: OIDC on, anonymous off, audience bound."""
    return {
        "enabled": True,
        "allow_anonymous": False,
        "oidc": {
            "enabled": True,
            "issuer": issuer,
            "audience": audience,
            "resource_uri": resource_uri,  # RFC 8707 binding
            "require_tenant": require_tenant,
            "strict_tenant_audience": strict_tenant_audience,
            "tenant_audiences": dict(tenant_audiences or {}),
        },
        "role_assignments": list(role_assignments or []),
    }


def generate_server_entry(
    *,
    name: str,
    mode: str,
    command: list[str] | None = None,
    url: str | None = None,
    allow_tools: list[str] | None = None,
    deny_tools: list[str] | None = None,
) -> dict:
    """An ``mcp_servers`` entry with an enforced tool allow/deny policy."""
    entry: dict = {"mode": mode}
    if command is not None:
        entry["command"] = list(command)
    if url is not None:
        entry["url"] = url
    if allow_tools is not None or deny_tools is not None:
        entry["tools"] = {}
        if allow_tools is not None:
            entry["tools"]["allow"] = list(allow_tools)
        if deny_tools is not None:
            entry["tools"]["deny"] = list(deny_tools)
    return entry


def generate_config(auth_block: dict, servers: dict[str, dict]) -> dict:
    return {"auth": auth_block, "mcp_servers": servers}
