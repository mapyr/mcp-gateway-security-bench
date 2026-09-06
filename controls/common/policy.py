"""Policy toggles for the reference intermediary.

Each flag is a single enforcement decision, and each maps to one or more test
families in the registry. ``SECURE_POLICY`` sets every flag to its protective
value; ``VULNERABLE_POLICY`` sets every flag to its unsafe value. Because the two
differ on every dimension, every attack should be FAIL on vulnerable and PASS on
secure — which is exactly what the differential gate checks.

The flags are intentionally boolean and independent so a reader can see, one
line at a time, precisely what "secure" means here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Policy:
    name: str

    # --- Authentication (AUTH-*) ----------------------------------------- #
    require_auth_for_list: bool  # AUTH-001 (surface a)
    require_auth_for_call: bool  # AUTH-001 (surface b)
    bind_token_to_principal: bool  # AUTH-002
    check_token_expiry: bool  # AUTH-003
    check_token_audience: bool  # AUTH-004

    # --- Authorization (AUTHZ-*) ----------------------------------------- #
    authorize_calls: bool  # AUTHZ-001
    gate_hidden_tools: bool  # AUTHZ-002 (enforce even when hidden from list)
    canonicalize_keys: bool  # AUTHZ-003 (policy holds under every alias/key)
    gate_batch_per_call: bool  # AUTHZ-004

    # --- Tenancy (TENANT-*) ---------------------------------------------- #
    tenant_from_session_only: bool  # TENANT-001/002 (ignore args/header/_meta)

    # --- Egress / SSRF (SSRF-*, EGRESS-*) -------------------------------- #
    enforce_egress_allowlist: bool  # SSRF-001/002/003, EGRESS-001
    recheck_after_resolve: bool  # SSRF-004 (rebinding), SSRF-005 (redirects)

    # --- Schema (SCHEMA-*) ----------------------------------------------- #
    pin_schema: bool  # SCHEMA-001/002 (detect post-admission mutation)
    unique_tool_names: bool  # SCHEMA-003 (reject cross-upstream shadowing)

    # --- Session (SESSION-*) --------------------------------------------- #
    isolate_sessions: bool  # SESSION-001

    # --- Secrets (SECRET-*) ---------------------------------------------- #
    protect_secrets: bool  # SECRET-001

    # --- Audit (AUDIT-*) ------------------------------------------------- #
    audit_actions: bool  # AUDIT-001
    redact_audit: bool  # AUDIT-002


_ALL_FLAGS = tuple(
    f for f in Policy.__dataclass_fields__ if Policy.__dataclass_fields__[f].type == "bool"
)


SECURE_POLICY = Policy(
    name="secure",
    require_auth_for_list=True,
    require_auth_for_call=True,
    bind_token_to_principal=True,
    check_token_expiry=True,
    check_token_audience=True,
    authorize_calls=True,
    gate_hidden_tools=True,
    canonicalize_keys=True,
    gate_batch_per_call=True,
    tenant_from_session_only=True,
    enforce_egress_allowlist=True,
    recheck_after_resolve=True,
    pin_schema=True,
    unique_tool_names=True,
    isolate_sessions=True,
    protect_secrets=True,
    audit_actions=True,
    redact_audit=True,
)


VULNERABLE_POLICY = Policy(
    name="vulnerable",
    require_auth_for_list=False,
    require_auth_for_call=False,
    bind_token_to_principal=False,
    check_token_expiry=False,
    check_token_audience=False,
    authorize_calls=False,
    gate_hidden_tools=False,
    canonicalize_keys=False,
    gate_batch_per_call=False,
    tenant_from_session_only=False,
    enforce_egress_allowlist=False,
    recheck_after_resolve=False,
    pin_schema=False,
    unique_tool_names=False,
    isolate_sessions=False,
    protect_secrets=False,
    audit_actions=False,
    redact_audit=False,
)


def assert_policies_are_polar() -> None:
    """Sanity check: secure protects on every flag, vulnerable on none.

    This guarantees the differential gate's premise — that every attack can be
    FAIL on vulnerable and PASS on secure — is at least *possible* by
    construction. Called from the control smoke tests.
    """
    for flag in _ALL_FLAGS:
        assert getattr(SECURE_POLICY, flag) is True, f"secure must protect: {flag}"
        assert getattr(VULNERABLE_POLICY, flag) is False, f"vulnerable must not: {flag}"
