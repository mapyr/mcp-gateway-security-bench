"""Docker MCP Gateway adapter (WS-7).

Capability declaration is grounded in the gateway's documented model, pinned to
a recent version (≥ v0.43.1; see README for the sourced map and the version
caveats). Its profile differs markedly from ToolHive's: incoming auth is a single
*shared* bearer token (no per-principal identity, no expiry/audience), so the
per-principal AUTH/AUTHZ tests are ``UNSUPPORTED``; but it *does* reject
cross-server tool-name collisions (SCHEMA-003), log calls (AUDIT), scan for
secrets (SECRET), and control egress (SSRF/EGRESS) — so those run.

Provisioning is honest (invariant #8): a faithful run needs the gateway plus the
fixtures wired through its catalog and a stable auth token; absent that harness,
``provision`` returns unavailable and every test is ``INCONCLUSIVE``. It never
brings the gateway up in a partial/insecure config and reports the fallout.
"""

from __future__ import annotations

import os

from mcpsb.adapter import Capability, Endpoint, PolicyBundle
from mcpsb.provisioning import preflight
from mcpsb.scenario import Scenario
from mcpsb.streamable import make_factory

#: What Docker MCP Gateway can express (sourced map in README). Absent — and thus
#: UNSUPPORTED — are per-principal identity (shared token), token expiry/audience,
#: per-caller authorization, tenancy, schema-drift pinning, session isolation,
#: and the batch surface.
_CAPABILITIES = {
    Capability.SURFACE_LIST,
    Capability.SURFACE_CALL,
    Capability.SURFACE_PROMPT,
    Capability.SURFACE_RESOURCE,
    Capability.SURFACE_RECONNECT,
    Capability.AUTHENTICATION,          # shared bearer token on HTTP transports
    Capability.TOOL_ALLOWLIST,          # --tools blocks non-exposed tools
    Capability.EGRESS_POLICY,           # --block-network / allowHosts / SSRF hardening
    Capability.NAME_COLLISION_CONTROL,  # rejects colliding tool names (v0.43.1+)
    Capability.AUDIT_LOG,               # --log-calls (default on)
    Capability.SECRET_ISOLATION,        # --block-secrets scans args/responses
}

_REQUIRED_ENV = ("MCPSB_DMG_AUTH_TOKEN",)


class Adapter:
    name = "docker_mcp_gateway"

    def __init__(self) -> None:
        self._proc = None

    def capabilities(self) -> set[Capability]:
        return set(_CAPABILITIES)

    def version(self) -> str:
        """Sourced live from the Docker MCP plugin (WS-E), never a literal."""
        import re
        import subprocess

        try:
            out = subprocess.run(
                ["docker", "mcp", "version"], capture_output=True, text=True, timeout=10
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return ""
        m = re.search(r"v?\d+\.\d+\.\d+", out)
        return f"docker-mcp-gateway/{m.group(0)}" if m else ""

    #: The capability map and the earlier live observations were made against
    #: v2.0.x. Other builds are out of the tested range until re-reviewed.
    _TESTED_MIN, _TESTED_MAX = "2.0.0", "2.0.999"

    def tested_versions(self) -> str:
        return "2.0.x"

    def supports_version(self, version: str) -> bool:
        from mcpsb.versioning import version_supported

        return version_supported(version, minimum=self._TESTED_MIN, maximum=self._TESTED_MAX)

    def client_factory(self):
        return make_factory("/mcp")

    def provision(self, bundle: PolicyBundle) -> Endpoint:
        unavailable = preflight(
            binary="docker",
            required_env=_REQUIRED_ENV,
            docs="targets/docker_mcp_gateway/README.md",
        )
        if unavailable is not None:
            return unavailable
        # Attach-to-running-gateway mode: an operator has started the gateway
        # (docker/mcp-gateway, --transport streaming, MCP_GATEWAY_AUTH_TOKEN set)
        # and points the adapter at it. This is a real, honest provision — the
        # gateway was brought up with its own secure config, not faked here.
        endpoint = os.environ.get("MCPSB_DMG_ENDPOINT")
        if endpoint:
            return Endpoint(base_url=endpoint, available=True)
        return Endpoint(
            available=False,
            reason=(
                "auth token present but MCPSB_DMG_ENDPOINT not set; start the "
                "gateway and export its URL (see targets/docker_mcp_gateway/README.md)"
            ),
        )

    def scenario(self) -> Scenario:
        # A shared bearer token authenticates the caller but does not distinguish
        # principals, so the two "principal" tokens are the same token; the
        # per-principal tests are UNSUPPORTED and never reach this anyway.
        token = os.environ.get("MCPSB_DMG_AUTH_TOKEN", "")
        return Scenario(
            principal_a_token=token,
            principal_b_token=token,
            expired_token="",
            wrong_audience_token="",
            authorized_tool="echo",
            hidden_tool="admin_ping",
            egress_tool="fetch",
            egress_url_arg="url",
            secret_tool="render",
            secret_template_arg="template",
            secret_probe="${MCPSB_SECRET}",
            secret_marker=os.environ.get("MCPSB_DMG_SECRET_MARKER", ""),
            tenant_tool="read_doc",
            tenant_a_marker="",
            tenant_b_marker="",
            other_tenant_id="",
            tenant_override_arg="tenant",
            authorized_prompt="greeting",
            authorized_resource="notes",
            schema_tool="echo",
            shadow_marker="shadowed",
        )

    def teardown(self) -> None:
        self._proc = None
