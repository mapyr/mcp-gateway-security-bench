"""Shared adapter for the reference controls.

Both ``controls/secure`` and ``controls/vulnerable`` are the same adapter with a
different policy. It brings the in-process :class:`IntermediaryServer` up and
declares the full capability set — a control expresses *every* concept the bench
tests (it is the reference), so nothing on a control is ever ``UNSUPPORTED``.
The difference between the two is only whether the policy enforces those
concepts, which is what the differential gate measures.

Egress resolver wiring: by default the resolver is hermetic and knows only IP
literals (so a plain ``mcpsb run`` never touches the real internet). The
attacks (WS-4) point the resolver and connector at the live observation plane to
exercise SSRF/egress; they reach it via ``server.intermediary``.
"""

from __future__ import annotations

import json
import urllib.request

from mcpsb.adapter import Capability, Endpoint, PolicyBundle
from mcpsb.scenario import Scenario

from controls.common import egress
from controls.common.identities import DEFAULT_SECRET, SECRET_ENV, TENANT_DOCS
from controls.common.intermediary import Intermediary, IntermediaryServer
from controls.common.policy import Policy

_ALL_CAPABILITIES = set(Capability)  # controls express everything the bench tests


class ControlAdapter:
    """Base adapter; subclasses set ``policy``."""

    policy: Policy

    def __init__(self) -> None:
        self._server: IntermediaryServer | None = None

    @property
    def name(self) -> str:
        return self.policy.name

    def version(self) -> str:
        """The reference intermediary ships with the bench, so its version *is*
        the bench version — sourced from the package, not a literal."""
        from mcpsb import __version__

        return f"mcpsb-reference/{__version__}"

    def tested_versions(self) -> str:
        return "the bench's own reference intermediary (always in range)"

    def supports_version(self, version: str) -> bool:
        # The control ships with the bench; its version is always the one tested.
        return True

    #: Hosts on the egress allowlist. ``api.example.com`` is a benign allowed
    #: destination (EGRESS-001 builds a confusable child of it);
    #: ``server.attacker.test`` is an attacker-controlled but legitimately
    #: allowed upstream, used to isolate the rebinding defense (SSRF-004).
    ALLOWLISTED_HOST = "api.example.com"
    REBINDABLE_HOST = "server.attacker.test"

    def provision(self, bundle: PolicyBundle) -> Endpoint:
        allowlist = frozenset({self.ALLOWLISTED_HOST, self.REBINDABLE_HOST})
        resolver = egress.literal_or_map_resolver({})
        interm = Intermediary(
            self.policy, resolver=resolver, allowlist=allowlist, secret=DEFAULT_SECRET
        )
        self._server = IntermediaryServer(interm).start()
        return Endpoint(base_url=self._server.base_url, available=True)

    def scenario(self) -> Scenario:
        base = self._server.base_url if self._server else ""

        def read_json(path: str):
            try:
                with urllib.request.urlopen(base + path, timeout=3) as r:  # noqa: S310
                    return json.loads(r.read())
            except Exception:  # noqa: BLE001
                return []

        def reset() -> None:
            try:
                req = urllib.request.Request(base + "/__state__", method="DELETE")
                urllib.request.urlopen(req, timeout=3).read()  # noqa: S310
            except Exception:  # noqa: BLE001
                pass

        def post(path: str) -> None:
            try:
                req = urllib.request.Request(base + path, data=b"{}", method="POST")
                urllib.request.urlopen(req, timeout=3).read()  # noqa: S310
            except Exception:  # noqa: BLE001
                pass

        return Scenario(
            principal_a_token="tok-alice-acme",
            principal_b_token="tok-bob-globex",
            expired_token="tok-alice-expired",
            wrong_audience_token="tok-alice-wrongaud",
            authorized_tool="echo",
            hidden_tool="admin_ping",
            egress_tool="fetch",
            egress_url_arg="url",
            secret_tool="render",
            secret_template_arg="template",
            secret_probe="${" + SECRET_ENV + "}",
            secret_marker=DEFAULT_SECRET,
            tenant_tool="read_doc",
            tenant_a_marker=TENANT_DOCS["acme"],
            tenant_b_marker=TENANT_DOCS["globex"],
            other_tenant_id="globex",
            tenant_override_arg="tenant",
            authorized_prompt="greeting",
            authorized_resource="notes",
            impersonation_header="X-Principal",
            principal_b_identity="bob",
            tenant_override_header="X-Tenant",
            allowlisted_host=self.ALLOWLISTED_HOST,
            rebindable_host=self.REBINDABLE_HOST,
            hidden_tool_alias="Admin_Ping",
            hidden_prompt="admin_prompt",
            hidden_prompt_alias="Admin_Prompt",
            hidden_resource="admin_resource",
            hidden_resource_alias="Admin_Resource",
            session_write_tool="stash",
            session_read_tool="recall",
            session_value_arg="value",
            session_header="Mcp-Session-Id",
            schema_tool="echo",
            shadow_marker="shadowed",
            trigger_drift=lambda: post("/__drift__"),
            trigger_shadow=lambda: post("/__shadow__"),
            read_audit=lambda: read_json("/__audit__"),
            read_trace=lambda: read_json("/__trace__"),
            reset_state=reset,
        )

    def capabilities(self) -> set[Capability]:
        return set(_ALL_CAPABILITIES)

    def wire_observation(self, observation) -> None:
        """Point the intermediary's egress resolver at the bench DNS.

        After this, an attack configures a malicious hostname purely through the
        observation plane (``observation.dns.set_static`` / ``set_rebind``) — the
        same way a real containerized target uses the bench DNS as its resolver —
        so egress attacks stay target-agnostic (no control-specific endpoints).
        """
        if self._server is None:
            return
        from mcpsb.observation.dns import query_a

        dns = observation.dns
        interm = self._server.intermediary
        interm.resolver = lambda host: query_a(host, dns.host, dns.port)
        interm.configure_egress(static={}, rebind={})

    def teardown(self) -> None:
        if self._server is not None:
            self._server.stop()
            self._server = None

    # Convenience for in-process tests / attacks that need the live object.
    @property
    def server(self) -> IntermediaryServer | None:
        return self._server
