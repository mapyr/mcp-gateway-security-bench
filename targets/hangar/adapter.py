"""MCP Hangar adapter (WS-8).

Hangar is maintained by this bench's author. Per GOVERNANCE §1 it is implemented
LAST, runs through the *same* pipeline as every other target, and its results do
not appear in Hangar's own marketing until an external maintainer has published a
run (§1.4). The capability map below was derived from Hangar's source with the
same skeptical, enforcement-must-be-in-code standard applied to third-party
targets — a capability is declared only where the code actually enforces it.

A consequence of that standard, applied honestly: capabilities Hangar *offers* but
does not fully enforce are still **declared**, so the corresponding tests RUN
rather than being hidden behind UNSUPPORTED. Hiding them would be the
conflict-of-interest failure this project exists to prevent. Conversely, the
specifics of any *unfixed* own-target finding are NOT written here or in the
published results: consistent with DISCLOSURE.md, they are handled privately and
fixed before publication, so this repo never ships an attack roadmap for the
author's own product (which would be the opposite failure — harming its security).

Provisioning is honest (invariant #8): without the live harness (Hangar running
with auth enabled, an OIDC issuer, and a comprehensive fixture MCP server behind
it) ``provision`` returns unavailable and every test is INCONCLUSIVE.
"""

from __future__ import annotations

import os

from mcpsb.adapter import Capability, Endpoint, PolicyBundle
from mcpsb.provisioning import preflight
from mcpsb.scenario import Scenario
from mcpsb.streamable import make_factory

#: Declared only where enforcement is in code (see README for the citations and
#: the enforcement caveats). Not declared — and thus UNSUPPORTED — are the
#: prompts/resources surfaces (no evidence Hangar proxies them), session
#: isolation, and gateway-layer secret isolation.
_CAPABILITIES = {
    Capability.SURFACE_LIST,
    Capability.SURFACE_CALL,
    Capability.SURFACE_BATCH,          # hangar_call fan-out, per-call gated
    Capability.SURFACE_RECONNECT,
    Capability.AUTHENTICATION,         # JWT/OIDC + API key (opt-in)
    Capability.PRINCIPAL_BINDING,      # sub -> PrincipalId
    Capability.TOKEN_EXPIRY,           # verify_exp + max-lifetime gate
    Capability.TOKEN_AUDIENCE,         # verify_aud + RFC 8707 resource binding
    Capability.AUTHORIZATION,          # dual fail-closed deny engines, call-time
    Capability.TOOL_ALLOWLIST,         # per-tenant tools allow/deny policy
    Capability.TENANCY,                # tenant from verified token, anti-spoof
    Capability.EGRESS_POLICY,          # offered (guard exists) — see caveat
    Capability.SCHEMA_PINNING,         # digest re-verify on call (operator pin)
    Capability.NAME_COLLISION_CONTROL, # colliding names dropped fail-safe
    Capability.AUDIT_LOG,              # events emitted on the call path
}

_REQUIRED_ENV = ("MCPSB_HANGAR_OIDC_ISSUER", "MCPSB_HANGAR_OIDC_AUDIENCE",
                 "MCPSB_HANGAR_TOKEN_A", "MCPSB_HANGAR_TOKEN_B")


class Adapter:
    name = "hangar"

    def __init__(self) -> None:
        self._proc = None

    def capabilities(self) -> set[Capability]:
        return set(_CAPABILITIES)

    def version(self) -> str:
        """Sourced from the installed artifact, never a literal (WS-E). A pin in
        the task text is not evidence — the version is whatever wheel is actually
        installed. Empty when Hangar is not installed here, which the claim gate
        (WS-D3) then refuses to publish rather than letting a remembered number
        stand in for the artifact."""
        import importlib.metadata as _md

        # Only the real distribution names — never a bare "hangar", which is an
        # unrelated PyPI package; a false version is worse than an empty one.
        for dist in ("mcp-hangar", "mcp_hangar"):
            try:
                return f"mcp-hangar/{_md.version(dist)}"
            except _md.PackageNotFoundError:
                continue
        return ""

    #: The capability map below reflects the v2 authorization model (per-caller
    #: authz, tool allow/deny, tenancy) — features Hangar gained in the v2 line.
    #: Running the adapter against a pre-v2 build (e.g. 1.4.0, which predates that
    #: model) would produce AUTHZ FAILs that are technically correct and years out
    #: of date. The floor pins the map to the version it was reviewed against.
    _TESTED_MIN = "2.17.1"

    def tested_versions(self) -> str:
        return f">= {self._TESTED_MIN}"

    def supports_version(self, version: str) -> bool:
        from mcpsb.versioning import version_supported

        return version_supported(version, minimum=self._TESTED_MIN)

    def client_factory(self):
        return make_factory("/mcp")

    def provision(self, bundle: PolicyBundle) -> Endpoint:
        unavailable = preflight(
            binary="mcp-hangar", required_env=_REQUIRED_ENV, docs="targets/hangar/README.md"
        )
        if unavailable is not None:
            return unavailable
        # A configured environment would start Hangar with auth enabled, the
        # generated config.yaml, and a fixture MCP server behind it, then return
        # a live Endpoint (Streamable HTTP at /mcp). That live bring-up is the
        # remaining integration step (README) and is intentionally not faked.
        return Endpoint(
            available=False,
            reason="live provisioning not yet implemented; harness env is present",
        )

    def scenario(self) -> Scenario:
        return Scenario(
            principal_a_token=os.environ.get("MCPSB_HANGAR_TOKEN_A", ""),
            principal_b_token=os.environ.get("MCPSB_HANGAR_TOKEN_B", ""),
            expired_token=os.environ.get("MCPSB_HANGAR_TOKEN_EXPIRED", ""),
            wrong_audience_token=os.environ.get("MCPSB_HANGAR_TOKEN_WRONGAUD", ""),
            authorized_tool="echo",
            hidden_tool="admin_ping",
            egress_tool="fetch",
            egress_url_arg="url",
            secret_tool="render",
            secret_template_arg="template",
            secret_probe="${MCPSB_SECRET}",
            secret_marker=os.environ.get("MCPSB_HANGAR_SECRET_MARKER", ""),
            tenant_tool="read_doc",
            tenant_a_marker=os.environ.get("MCPSB_HANGAR_TENANT_A_MARKER", ""),
            tenant_b_marker=os.environ.get("MCPSB_HANGAR_TENANT_B_MARKER", ""),
            other_tenant_id=os.environ.get("MCPSB_HANGAR_OTHER_TENANT", ""),
            tenant_override_arg="tenant",
            authorized_prompt="greeting",
            authorized_resource="notes",
            schema_tool="echo",
            shadow_marker="shadowed",
        )

    def teardown(self) -> None:
        self._proc = None
