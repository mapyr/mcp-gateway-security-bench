"""Translate the bench's policy into Docker MCP Gateway configuration.

Unlike ToolHive's Cedar policy file, the Docker gateway is configured mostly by
**CLI flags** plus per-server **catalog metadata**. The secure posture the bench
provisions:

* a static **tool allowlist** (``--tools``) — blocks calls to non-exposed tools;
* **egress control** (``--block-network`` globally, plus per-server
  ``allowHosts``/``disableNetwork`` in the catalog entry);
* **secret scanning** (``--block-secrets``, default on);
* **image provenance** (``--verify-signatures``, default on);
* **call logging** (``--log-calls``, default on);
* a stable **bearer token** for the HTTP transport (``MCP_GATEWAY_AUTH_TOKEN``).

Pure functions, unit-testable without Docker present.

Sources: https://github.com/docker/mcp-gateway/blob/main/docs/mcp-gateway.md ,
https://github.com/docker/mcp-gateway/blob/main/docs/security.md
"""

from __future__ import annotations


def generate_gateway_flags(
    *,
    port: int,
    allowed_tools: list[str],
    block_network: bool = True,
    verify_signatures: bool = True,
    block_secrets: bool = True,
    log_calls: bool = True,
    transport: str = "streaming",
) -> list[str]:
    """The ``docker mcp gateway run`` flags for the secure posture."""
    flags = ["--transport", transport, "--port", str(port)]
    if allowed_tools:
        flags += ["--tools", ",".join(allowed_tools)]
    for name, on in (
        ("--verify-signatures", verify_signatures),
        ("--block-secrets", block_secrets),
        ("--block-network", block_network),
        ("--log-calls", log_calls),
    ):
        flags.append(f"{name}={'true' if on else 'false'}")
    return flags


def generate_catalog_entry(server_name: str, image: str, allow_hosts: list[str]) -> dict:
    """A catalog entry pinning a server's image and its egress allowlist."""
    return {
        "name": server_name,
        "image": image,
        "disableNetwork": not allow_hosts,
        "allowHosts": list(allow_hosts),
    }
