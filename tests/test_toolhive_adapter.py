"""ToolHive adapter tests (WS-6) — validate the capability map and config
translation without needing a live ToolHive.

The capability declaration is the substance of the adapter: it determines which
tests are UNSUPPORTED. This computes, from the declared capabilities plus each
test's requirements, exactly which sub-IDs ToolHive cannot answer, and asserts it
matches the sourced analysis in the README.
"""

from __future__ import annotations

from mcpsb.adapter import SURFACE_CAPABILITY, Capability, PolicyBundle
from mcpsb.capabilities import is_policy_supported
from mcpsb.registry import active_tests
from mcpsb.runner import load_adapter
from targets.toolhive.config import Grant, generate_cedar_authz, generate_permission_profile


def _unsupported_sub_ids(capabilities: set) -> set[str]:
    """Sub-IDs the target cannot answer, by the same rule the runner applies."""
    out = set()
    for spec in active_tests():
        policy_missing = not is_policy_supported(spec.id, capabilities)
        for letter in spec.surfaces:
            surface_missing = SURFACE_CAPABILITY[letter] not in capabilities
            if surface_missing or policy_missing:
                out.add(f"{spec.id}.{letter}")
    return out


def test_capabilities_declared():
    adapter = load_adapter("toolhive")
    caps = adapter.capabilities()
    # Present (documented, sourced):
    assert Capability.AUTHENTICATION in caps
    assert Capability.TOKEN_AUDIENCE in caps
    assert Capability.AUTHORIZATION in caps
    assert Capability.EGRESS_POLICY in caps
    # Absent (no documented support) -> drive UNSUPPORTED:
    assert Capability.TENANCY not in caps
    assert Capability.SCHEMA_PINNING not in caps
    assert Capability.SESSION_ISOLATION not in caps
    assert Capability.AUDIT_LOG not in caps
    assert Capability.SECRET_ISOLATION not in caps
    assert Capability.SURFACE_BATCH not in caps


def test_unsupported_profile_matches_sourced_analysis():
    caps = load_adapter("toolhive").capabilities()
    unsupported = _unsupported_sub_ids(caps)
    expected = {
        # no multi-tenancy
        "TENANT-001.b", "TENANT-002.b",
        # no post-admission schema pinning
        "SCHEMA-001.a", "SCHEMA-001.b", "SCHEMA-002.a", "SCHEMA-002.b",
        "SCHEMA-003.a", "SCHEMA-003.b",
        # no session isolation
        "SESSION-001.f",
        # no boundary protecting its own injected secrets from the proxied server
        "SECRET-001.b",
        # CLI proxy has no audit log (vMCP-only)
        "AUDIT-001.b", "AUDIT-001.e", "AUDIT-002.b",
        # batch surface not claimed
        "AUTHZ-001.e", "AUTHZ-004.e",
    }
    assert unsupported == expected


def test_runnable_families_are_not_unsupported():
    caps = load_adapter("toolhive").capabilities()
    unsupported = _unsupported_sub_ids(caps)
    # Auth, the non-batch authz surfaces, SSRF, and egress are within ToolHive's
    # model, so they must NOT be UNSUPPORTED (they run against a live target).
    for sub in ("AUTH-001.a", "AUTH-004.b", "AUTHZ-001.b", "AUTHZ-002.b",
                "AUTHZ-003.c", "SSRF-002.b", "SSRF-004.b", "EGRESS-001.b"):
        assert sub not in unsupported


def test_cedar_authz_is_default_deny_permits_only():
    policy = generate_cedar_authz([
        Grant(sub="alice", tools=("echo",), prompts=("greeting",), resources=("notes",)),
        Grant(sub="bob", tools=("echo",)),
    ])
    assert policy["type"] == "cedarv1"
    joined = " ".join(policy["cedar"]["policies"])
    assert 'permit(principal == Client::"alice", action == Action::"call_tool", resource == Tool::"echo");' in policy["cedar"]["policies"]
    assert "forbid" not in joined  # default-deny; no explicit forbids needed
    # The restricted tool is simply never permitted.
    assert "admin_ping" not in joined


def test_permission_profile_blocks_all_but_allowlist():
    profile = generate_permission_profile(["api.example.com"], [443])
    outbound = profile["network"]["outbound"]
    assert outbound["insecure_allow_all"] is False
    assert outbound["allow_host"] == ["api.example.com"]
    assert outbound["allow_port"] == [443]


def test_provision_is_honest_when_toolhive_absent():
    # Without thv / the harness env, provision must be unavailable (INCONCLUSIVE),
    # never a fabricated or insecure-config run.
    adapter = load_adapter("toolhive")
    endpoint = adapter.provision(PolicyBundle.empty())
    assert endpoint.available is False
    assert endpoint.reason
