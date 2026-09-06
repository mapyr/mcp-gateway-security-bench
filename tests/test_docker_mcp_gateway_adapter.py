"""Docker MCP Gateway adapter tests (WS-7).

Validates the capability map and its UNSUPPORTED profile without a live gateway.
The profile is deliberately different from ToolHive's — the point of the bench is
to surface that two real intermediaries offer different boundaries.
"""

from __future__ import annotations

from mcpsb.adapter import SURFACE_CAPABILITY, Capability, PolicyBundle
from mcpsb.capabilities import is_policy_supported
from mcpsb.registry import active_tests
from mcpsb.runner import load_adapter
from targets.docker_mcp_gateway.config import generate_catalog_entry, generate_gateway_flags


def _unsupported_sub_ids(capabilities: set) -> set[str]:
    out = set()
    for spec in active_tests():
        policy_missing = not is_policy_supported(spec.id, capabilities)
        for letter in spec.surfaces:
            if SURFACE_CAPABILITY[letter] not in capabilities or policy_missing:
                out.add(f"{spec.id}.{letter}")
    return out


def test_capabilities_reflect_shared_token_and_collision_control():
    caps = load_adapter("docker_mcp_gateway").capabilities()
    # A shared bearer token can require auth but not distinguish principals.
    assert Capability.AUTHENTICATION in caps
    assert Capability.PRINCIPAL_BINDING not in caps
    assert Capability.TOKEN_EXPIRY not in caps
    assert Capability.TOKEN_AUDIENCE not in caps
    assert Capability.AUTHORIZATION not in caps
    # But it defends against tool-name shadowing, logs calls, scans secrets,
    # controls egress, and allowlists tools.
    assert Capability.NAME_COLLISION_CONTROL in caps
    assert Capability.AUDIT_LOG in caps
    assert Capability.SECRET_ISOLATION in caps
    assert Capability.EGRESS_POLICY in caps
    assert Capability.TOOL_ALLOWLIST in caps


def test_unsupported_profile_matches_sourced_analysis():
    caps = load_adapter("docker_mcp_gateway").capabilities()
    expected = {
        # shared token: no per-principal identity, no expiry/audience
        "AUTH-002.b", "AUTH-003.b", "AUTH-004.b",
        # no per-caller authorization policy
        "AUTHZ-001.b", "AUTHZ-001.c", "AUTHZ-001.d", "AUTHZ-001.e",
        "AUTHZ-003.a", "AUTHZ-003.b", "AUTHZ-003.c", "AUTHZ-003.d",
        "AUTHZ-004.e",
        # no tenancy
        "TENANT-001.b", "TENANT-002.b",
        # no schema-drift pinning
        "SCHEMA-001.a", "SCHEMA-001.b", "SCHEMA-002.a", "SCHEMA-002.b",
        # no documented session isolation
        "SESSION-001.f",
        # the batch surface is not claimed (AUDIT-001 also declares surface e)
        "AUDIT-001.e",
    }
    assert _unsupported_sub_ids(caps) == expected


def test_collision_and_audit_and_egress_families_run():
    caps = load_adapter("docker_mcp_gateway").capabilities()
    unsupported = _unsupported_sub_ids(caps)
    # These are within the gateway's model, so NOT unsupported (they run live).
    for sub in ("AUTH-001.a", "AUTHZ-002.b", "SCHEMA-003.a", "SCHEMA-003.b",
                "SSRF-002.b", "EGRESS-001.b", "SECRET-001.b", "AUDIT-001.b"):
        assert sub not in unsupported


def test_gateway_flags_secure_posture():
    flags = generate_gateway_flags(port=8080, allowed_tools=["echo", "whoami"])
    assert "--tools" in flags and "echo,whoami" in flags
    assert "--block-network=true" in flags
    assert "--block-secrets=true" in flags
    assert "--verify-signatures=true" in flags
    assert "--log-calls=true" in flags


def test_catalog_entry_pins_egress():
    entry = generate_catalog_entry("fetcher", "mcp/fetcher@sha256:abc", ["api.example.com"])
    assert entry["allowHosts"] == ["api.example.com"]
    assert entry["disableNetwork"] is False
    assert generate_catalog_entry("iso", "img", [])["disableNetwork"] is True


def test_provision_is_honest_when_gateway_absent(monkeypatch):
    monkeypatch.delenv("MCPSB_DMG_AUTH_TOKEN", raising=False)
    adapter = load_adapter("docker_mcp_gateway")
    endpoint = adapter.provision(PolicyBundle.empty())
    assert endpoint.available is False and endpoint.reason
