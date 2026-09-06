"""Translate the bench's target-agnostic policy into ToolHive configuration.

Two artifacts, both documented and sourced in the README:

* a **Cedar authorization policy** (``thv run --authz-config``) — default-deny,
  permitting each principal only its granted tools/prompts/resources, so the
  restricted ``admin_ping`` and cross-principal calls are denied;
* a **permission profile** (``thv run --permission-profile``) — egress
  allowlist, so the proxied server may reach only the allowed host.

These are pure functions so they are unit-testable without ToolHive present. The
adapter writes them to disk and passes them to ``thv run``.

Cedar reference: https://docs.stacklok.com/toolhive/reference/authz-policy-reference
Permissions reference: https://docs.stacklok.com/toolhive/guides-cli/custom-permissions
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Grant:
    """Which tools/prompts/resources a principal (OIDC ``sub``) may use."""

    sub: str
    tools: tuple[str, ...] = ()
    prompts: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()


def generate_cedar_authz(grants: list[Grant]) -> dict:
    """A default-deny Cedar policy permitting each principal only its grants.

    ToolHive's Cedar engine is default-deny (SPEC alignment: authorization is
    required on every value-bearing surface), so we only emit ``permit`` rules;
    anything not permitted — including the restricted tool — is denied.
    """
    policies: list[str] = []
    for g in grants:
        for tool in g.tools:
            policies.append(
                f'permit(principal == Client::"{g.sub}", '
                f'action == Action::"call_tool", resource == Tool::"{tool}");'
            )
        for prompt in g.prompts:
            policies.append(
                f'permit(principal == Client::"{g.sub}", '
                f'action == Action::"get_prompt", resource == Prompt::"{prompt}");'
            )
        for resource in g.resources:
            policies.append(
                f'permit(principal == Client::"{g.sub}", '
                f'action == Action::"read_resource", resource == Resource::"{resource}");'
            )
    return {
        "version": "1.0",
        "type": "cedarv1",
        "cedar": {"policies": policies, "entities_json": "[]"},
    }


def generate_permission_profile(allow_hosts: list[str], allow_ports: list[int] | None = None) -> dict:
    """An egress permission profile allowing only ``allow_hosts``.

    Everything else is blocked (``insecure_allow_all: false``), which is the
    default-on network isolation ToolHive applies (v0.30.1+).
    """
    return {
        "network": {
            "outbound": {
                "insecure_allow_all": False,
                "allow_host": list(allow_hosts),
                "allow_port": list(allow_ports or [80, 443]),
            }
        }
    }


def write_json(path: str, obj: dict) -> None:
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2)
