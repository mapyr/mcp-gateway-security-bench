"""The scenario contract (WS-4, part of the policy-bundle idea in §8).

Attacks must not name a target or hard-code its identities (invariant #3). So an
attack never writes ``tok-alice-acme`` or ``admin_ping`` — those are the control
intermediary's concrete choices. Instead the adapter provides a :class:`Scenario`
that maps the bench's *abstract roles* (principal A, a hidden tool, the egress
tool, …) onto whatever the target actually calls them. The attack reasons in
roles; the adapter supplies handles.

For ``AUDIT-*`` tests — where the SUT's own record is the subject of study
(SPEC §3.1) — the scenario also carries target-agnostic readers for the audit
log and trace, so the attack inspects them without knowing the target's log API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Scenario:
    # Credentials for distinct principals in distinct tenants.
    principal_a_token: str
    principal_b_token: str
    expired_token: str
    wrong_audience_token: str

    # A tool principal A is authorized to call.
    authorized_tool: str

    # A tool that exists but is hidden from tools/list and that principal A is
    # NOT authorized to call (AUTHZ-001/002).
    hidden_tool: str

    # The egress tool and the argument naming its destination URL (SSRF/EGRESS).
    egress_tool: str
    egress_url_arg: str

    # A tool that can be induced to interpolate an environment secret, the
    # template argument, the probe string, and the secret to look for (SECRET).
    secret_tool: str
    secret_template_arg: str
    secret_probe: str
    secret_marker: str

    # A tool returning tenant-scoped data, and the markers each tenant should see
    # (TENANT-*). principal A is tenant A; a cross-tenant read leaks B's marker.
    # ``other_tenant_id`` and ``tenant_override_arg`` are the untrusted handle and
    # argument name an attacker would use to try to re-scope the tenant.
    tenant_tool: str
    tenant_a_marker: str
    tenant_b_marker: str
    other_tenant_id: str
    tenant_override_arg: str

    # A prompt and a resource principal A is authorized for (AUTHZ-001 surfaces).
    authorized_prompt: str
    authorized_resource: str

    # AUTH-002: the untrusted way to claim to be another principal, and B's
    # identity as it would appear if the claim were honored.
    impersonation_header: str = "X-Principal"
    principal_b_identity: str = ""

    # TENANT-002: the untrusted header an attacker uses to re-scope the tenant.
    tenant_override_header: str = "X-Tenant"

    # SSRF/EGRESS: a host that is on the egress allowlist (EGRESS-001 builds a
    # confusable child of it) and an allowlisted host the attacker controls and
    # can rebind (SSRF-004).
    allowlisted_host: str = ""
    rebindable_host: str = ""

    # AUTHZ-003: restricted items and a non-canonical alias for each, that a
    # policy keyed on the canonical name must still cover.
    hidden_tool_alias: str = ""
    hidden_prompt: str = ""
    hidden_prompt_alias: str = ""
    hidden_resource: str = ""
    hidden_resource_alias: str = ""

    # SESSION-001: a write/read tool pair and the session header.
    session_write_tool: str = ""
    session_read_tool: str = ""
    session_value_arg: str = "value"
    session_header: str = "Mcp-Session-Id"

    # SCHEMA-*: trigger post-admission drift / a shadowing upstream, and the tool
    # whose definition is affected.
    schema_tool: str = ""
    shadow_marker: str = ""  # a string appearing in a call served by the shadow
    trigger_drift: Callable[[], None] = field(default=lambda: None)
    trigger_shadow: Callable[[], None] = field(default=lambda: None)

    # AUDIT-* readers (SPEC §3.1 exception). Return the entries as dicts.
    read_audit: Callable[[], list] = field(default=lambda: [])
    read_trace: Callable[[], list] = field(default=lambda: [])

    # Reset target-side state (audit/trace/session) between runs, if supported.
    reset_state: Callable[[], None] = field(default=lambda: None)
