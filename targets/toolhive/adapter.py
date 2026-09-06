"""ToolHive adapter (WS-6) — the first real target.

Capability declaration is grounded in ToolHive's documented model (see
``README.md`` for the sourced map). It determines which tests are ``UNSUPPORTED``:
ToolHive has no documented multi-tenancy, post-admission schema pinning, session
isolation, per-server audit log (that is vMCP-only), or a boundary protecting its
own injected secrets from the proxied server — so those families report
``UNSUPPORTED``, not ``FAIL`` (SPEC §4).

Provisioning is honest (invariant #8). A faithful run requires the full secure
harness — an OIDC issuer minting the principals' tokens, a Cedar authz policy, an
egress permission profile, and egress-capable fixtures — configured through the
environment (see README). Absent that, ``provision`` returns an *unavailable*
endpoint, so every test is ``INCONCLUSIVE``. It never brings ToolHive up in a
partial/insecure config and reports the resulting spurious failures, because that
would be a config artifact, not a finding.
"""

from __future__ import annotations

import os

from mcpsb.adapter import Capability, Endpoint, PolicyBundle
from mcpsb.provisioning import preflight
from mcpsb.scenario import Scenario

from targets.toolhive.client import factory as _client_factory

#: What ToolHive can express, per the sourced capability map (README). Absent
#: from this set — and therefore UNSUPPORTED — are tenancy, schema pinning,
#: session isolation, audit (CLI proxy), secret isolation, and the batch surface.
_CAPABILITIES = {
    Capability.SURFACE_LIST,
    Capability.SURFACE_CALL,
    Capability.SURFACE_PROMPT,
    Capability.SURFACE_RESOURCE,
    Capability.SURFACE_RECONNECT,
    Capability.AUTHENTICATION,       # OIDC bearer
    Capability.PRINCIPAL_BINDING,    # token's `sub` is the principal
    Capability.TOKEN_EXPIRY,         # JWT `exp`
    Capability.TOKEN_AUDIENCE,       # --oidc-audience (RFC 8707)
    Capability.AUTHORIZATION,        # Cedar per-call policy
    Capability.EGRESS_POLICY,        # permission profiles, default-on
}

#: Environment that a fully-configured live harness must provide for a faithful
#: run. Documented in README. Absent -> provision is unavailable (INCONCLUSIVE).
_REQUIRED_ENV = ("MCPSB_TOOLHIVE_OIDC_ISSUER", "MCPSB_TOOLHIVE_OIDC_AUDIENCE",
                 "MCPSB_TOOLHIVE_TOKEN_A", "MCPSB_TOOLHIVE_TOKEN_B")


class Adapter:
    name = "toolhive"

    def __init__(self) -> None:
        self._proc = None
        self._endpoint_url: str | None = None

    def capabilities(self) -> set[Capability]:
        return set(_CAPABILITIES)

    def version(self) -> str:
        """Sourced live from the `thv` binary (WS-E), never a literal."""
        import re
        import subprocess

        try:
            out = subprocess.run(
                ["thv", "version"], capture_output=True, text=True, timeout=10
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return ""
        m = re.search(r"v?\d+\.\d+\.\d+", out)
        return f"toolhive/{m.group(0)}" if m else ""

    #: The capability map and live findings were validated against v0.46.x. The
    #: bench does not opine on other ToolHive builds until they are re-reviewed.
    _TESTED_MIN, _TESTED_MAX = "0.46.0", "0.46.999"

    def tested_versions(self) -> str:
        return "0.46.x"

    def supports_version(self, version: str) -> bool:
        from mcpsb.versioning import version_supported

        return version_supported(version, minimum=self._TESTED_MIN, maximum=self._TESTED_MAX)

    def client_factory(self):
        return _client_factory

    def provision(self, bundle: PolicyBundle) -> Endpoint:
        unavailable = preflight(
            binary="thv", required_env=_REQUIRED_ENV, docs="targets/toolhive/README.md"
        )
        if unavailable is not None:
            return unavailable
        # A fully-configured environment would bring ToolHive up here (thv run
        # with --oidc-*, --authz-config, --permission-profile, proxying the
        # fixtures) and return a live Endpoint. That live bring-up is the
        # remaining integration step (README) and is intentionally not faked.
        return Endpoint(
            available=False,
            reason="live provisioning not yet implemented; harness env is present",
        )

    def scenario(self) -> Scenario:
        # Handles for a live run. Tokens come from the OIDC harness via env; tool
        # names match the fixtures ToolHive proxies. Unused while provision is
        # unavailable (every test is INCONCLUSIVE), but kept correct so a
        # configured environment has a complete contract.
        return Scenario(
            principal_a_token=os.environ.get("MCPSB_TOOLHIVE_TOKEN_A", ""),
            principal_b_token=os.environ.get("MCPSB_TOOLHIVE_TOKEN_B", ""),
            expired_token=os.environ.get("MCPSB_TOOLHIVE_TOKEN_EXPIRED", ""),
            wrong_audience_token=os.environ.get("MCPSB_TOOLHIVE_TOKEN_WRONGAUD", ""),
            authorized_tool="echo",
            hidden_tool="admin_ping",
            egress_tool="fetch",
            egress_url_arg="url",
            secret_tool="render",
            secret_template_arg="template",
            secret_probe="${MCPSB_SECRET}",
            secret_marker=os.environ.get("MCPSB_TOOLHIVE_SECRET_MARKER", ""),
            tenant_tool="read_doc",
            tenant_a_marker="",
            tenant_b_marker="",
            other_tenant_id="",
            tenant_override_arg="tenant",
            authorized_prompt="greeting",
            authorized_resource="notes",
        )

    def teardown(self) -> None:
        if self._proc is not None:
            try:
                import subprocess

                subprocess.run(["thv", "stop", self.name], timeout=15, capture_output=True)
            except Exception:  # noqa: BLE001
                pass
            self._proc = None
