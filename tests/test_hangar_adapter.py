"""Hangar adapter tests (WS-8).

Hangar is the author's own target (GOVERNANCE §1); the capability map was derived
from its source with the same enforcement-must-be-in-code standard as the
third-party targets, and these tests validate the resulting UNSUPPORTED profile
without a live Hangar.
"""

from __future__ import annotations

from mcpsb.adapter import SURFACE_CAPABILITY, Capability, PolicyBundle
from mcpsb.capabilities import is_policy_supported
from mcpsb.registry import active_tests
from mcpsb.runner import load_adapter
from targets.hangar.config import generate_auth_block, generate_server_entry


def _unsupported_sub_ids(capabilities: set) -> set[str]:
    out = set()
    for spec in active_tests():
        policy_missing = not is_policy_supported(spec.id, capabilities)
        for letter in spec.surfaces:
            if SURFACE_CAPABILITY[letter] not in capabilities or policy_missing:
                out.add(f"{spec.id}.{letter}")
    return out


def test_capabilities_declared_only_where_enforced():
    caps = load_adapter("hangar").capabilities()
    # Enforced in code -> declared:
    for c in (Capability.AUTHENTICATION, Capability.PRINCIPAL_BINDING,
              Capability.TOKEN_EXPIRY, Capability.TOKEN_AUDIENCE,
              Capability.AUTHORIZATION, Capability.TENANCY,
              Capability.NAME_COLLISION_CONTROL, Capability.AUDIT_LOG,
              Capability.SCHEMA_PINNING, Capability.SURFACE_BATCH):
        assert c in caps
    # Offered but enforced incompletely -> still declared, so the tests RUN and
    # reveal the gap as FAIL (not hidden behind UNSUPPORTED).
    assert Capability.EGRESS_POLICY in caps
    # No evidence of enforcement -> not declared -> UNSUPPORTED:
    assert Capability.SESSION_ISOLATION not in caps
    assert Capability.SECRET_ISOLATION not in caps
    assert Capability.SURFACE_PROMPT not in caps
    assert Capability.SURFACE_RESOURCE not in caps


def test_unsupported_profile():
    caps = load_adapter("hangar").capabilities()
    expected = {
        # prompts/resources surfaces not declared (no evidence Hangar proxies them)
        "AUTHZ-001.c", "AUTHZ-001.d", "AUTHZ-003.c", "AUTHZ-003.d",
        # no documented session isolation
        "SESSION-001.f",
        # no gateway-layer secret-isolation boundary the test can probe
        "SECRET-001.b",
    }
    assert _unsupported_sub_ids(caps) == expected


def test_egress_and_audit_and_schema_families_run_not_hidden():
    # These MUST run (not UNSUPPORTED) so a live run reveals the enforcement
    # gaps as FAIL — the COI-neutral behavior (GOVERNANCE §1).
    caps = load_adapter("hangar").capabilities()
    unsupported = _unsupported_sub_ids(caps)
    for sub in ("SSRF-002.b", "SSRF-004.b", "EGRESS-001.b",
                "AUDIT-002.b", "SCHEMA-001.a", "SCHEMA-003.a", "TENANT-001.b"):
        assert sub not in unsupported


def test_secure_auth_block():
    block = generate_auth_block(
        issuer="https://issuer", audience="mcp-hangar",
        resource_uri="https://hangar.example.com",
        tenant_audiences={"team-a": "https://hangar.example.com/team-a"},
    )
    assert block["enabled"] is True and block["allow_anonymous"] is False
    assert block["oidc"]["audience"] == "mcp-hangar"
    assert block["oidc"]["strict_tenant_audience"] is True


def test_server_entry_enforced_tool_policy():
    entry = generate_server_entry(
        name="fx", mode="subprocess", command=["python", "-m", "fixtures.mcp", "benign"],
        allow_tools=["echo"], deny_tools=["admin_ping"],
    )
    assert entry["tools"]["allow"] == ["echo"]
    assert entry["tools"]["deny"] == ["admin_ping"]


def test_provision_is_honest_when_hangar_absent(monkeypatch):
    for k in ("MCPSB_HANGAR_OIDC_ISSUER", "MCPSB_HANGAR_OIDC_AUDIENCE",
              "MCPSB_HANGAR_TOKEN_A", "MCPSB_HANGAR_TOKEN_B"):
        monkeypatch.delenv(k, raising=False)
    endpoint = load_adapter("hangar").provision(PolicyBundle.empty())
    assert endpoint.available is False and endpoint.reason
