"""The reference MCP intermediary, shared by both controls.

A minimal JSON-RPC-over-HTTP intermediary with bearer auth. Every enforcement
point is gated on a single :class:`~controls.common.policy.Policy` flag, so the
secure and vulnerable variants are the *same code* with opposite policies. The
handlers cover all six surfaces (list, call, prompt, resource, batch, reconnect)
and the policy dimensions the registry tests.

Not a real MCP server (no SSE, no capability negotiation beyond a stub
``initialize``) — just enough protocol to drive the invariants. It is the
executable definition of what the bench considers correct (GOVERNANCE §3).

Control endpoints (outside the JSON-RPC path) expose the audit log and trace so
the ``AUDIT-*`` family can inspect them — the one place the SUT's own record is
the subject of study (SPEC §3.1).
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from controls.common import egress
from controls.common.identities import (
    GRANTS,
    HIDDEN_FROM_LIST,
    RESTRICTED,
    RESTRICTED_TOOLS,
    SECRET_ENV,
    TENANT_DOCS,
    TOKENS,
    Grant,
)

#: Per-tool admitted argument names. A tool listed here has a pinned input
#: contract; under ``pin_schema`` a call with an argument outside it is rejected
#: (SCHEMA-001). Tools not listed are not schema-pinned in the control.
_ADMITTED_ARGS = {"echo": frozenset({"message"})}
from controls.common.policy import Policy

_VISIBLE_TOOLS = ("echo", "whoami", "fetch", "read_doc", "render", "stash", "recall")
_ALL_TOOLS = _VISIBLE_TOOLS + tuple(sorted(HIDDEN_FROM_LIST))
_PROMPTS = ("greeting",)
_RESOURCES = ("notes",)

# Tools every principal may use, so session/tenant/egress tests are not masked
# by an authorization failure they are not about.
_COMMON_TOOLS = frozenset({"echo", "whoami", "stash", "recall"})


class RpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class Session:
    principal: str
    tenant: str


class Intermediary:
    """Policy-parameterized reference intermediary (transport-agnostic core)."""

    def __init__(
        self,
        policy: Policy,
        *,
        resolver: egress.Resolver,
        allowlist: frozenset[str],
        connector: egress.Connector = egress.default_connector,
        secret: str | None = None,
    ) -> None:
        self.policy = policy
        self.resolver = resolver
        self.allowlist = allowlist
        self.connector = connector
        self.secret = secret if secret is not None else os.environ.get(SECRET_ENV, "")
        self._lock = threading.Lock()
        self.audit: list[dict] = []
        self.trace: list[dict] = []
        self._session_store: dict[str, str] = {}  # keyed by scope
        self._drifted = False
        self._shadowed = False
        # Egress scenario, configurable over /__egress__ so attacks can drive
        # SSRF/rebinding through the wire without touching internals.
        self._egress_static: dict[str, str] = {}
        self._egress_rebind: dict[str, list[str]] = {}
        self._egress_counts: dict[str, int] = {}

    # --- state / observation (for AUDIT-* and test setup) ----------------- #

    def reset_state(self) -> None:
        with self._lock:
            self.audit.clear()
            self.trace.clear()
            self._session_store.clear()
            self._drifted = False
            self._shadowed = False
            self._egress_counts.clear()

    def set_drift(self, drifted: bool) -> None:
        self._drifted = drifted

    def set_shadow(self, shadowed: bool) -> None:
        self._shadowed = shadowed

    def configure_egress(
        self,
        *,
        static: dict[str, str] | None = None,
        allowlist: list[str] | None = None,
        rebind: dict[str, list[str]] | None = None,
    ) -> None:
        with self._lock:
            if static is not None:
                self._egress_static = {k.lower().rstrip("."): v for k, v in static.items()}
            if rebind is not None:
                self._egress_rebind = {k.lower().rstrip("."): list(v) for k, v in rebind.items()}
                self._egress_counts.clear()
            if allowlist is not None:
                self.allowlist = frozenset(allowlist)

    def _resolve(self, host: str) -> str | None:
        """Effective resolver: internal egress table (with rebinding) first, then
        IP literals, then the injected resolver. TTL=0 rebinding is modeled by
        returning the next element of the sequence on each lookup."""
        import ipaddress  # local import keeps the module header lean

        key = host.lower().rstrip(".")
        with self._lock:
            if key in self._egress_rebind:
                idx = self._egress_counts.get(key, 0) + 1
                self._egress_counts[key] = idx
                seq = self._egress_rebind[key]
                return seq[min(idx - 1, len(seq) - 1)]
            if key in self._egress_static:
                return self._egress_static[key]
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            return self.resolver(host)

    # --- identity --------------------------------------------------------- #

    def _authenticate(self, headers: dict[str, str]) -> Session | None:
        raw = headers.get("authorization", "")
        if not raw.lower().startswith("bearer "):
            return None
        token = TOKENS.get(raw[7:].strip())
        if token is None:
            return None
        if self.policy.check_token_expiry and token.expired:
            return None
        if self.policy.check_token_audience and token.audience != "mcpsb-control":
            return None
        principal = token.principal
        if not self.policy.bind_token_to_principal:
            principal = headers.get("x-principal", principal)  # untrusted override
        # Tenant follows the (possibly overridden) principal's own token.
        tenant = _tenant_of(principal, default=token.tenant)
        return Session(principal=principal, tenant=tenant)

    def _effective_tenant(self, session: Session, params: dict, headers: dict) -> str:
        if self.policy.tenant_from_session_only:
            return session.tenant
        meta = params.get("_meta") or {}
        args = params.get("arguments") or {}
        return (
            args.get("tenant")
            or headers.get("x-tenant")
            or meta.get("tenant")
            or session.tenant
        )

    # --- authorization ---------------------------------------------------- #

    def _route_key(self, name: str) -> str:
        """The key used to dispatch a call to a handler — always canonical, so a
        request is routed to the tool it names regardless of policy. Aliasing
        bugs are about the *authorization* key differing from this, not about
        failing to find the tool."""
        return name.strip().rstrip(".").lower()

    def _authz_key(self, name: str) -> str:
        """The key the authorization decision is made on. Canonicalizing this is
        the AUTHZ-003 defense; a vulnerable policy keys on the raw string, so an
        alias escapes a classification expressed over the canonical name."""
        return self._route_key(name) if self.policy.canonicalize_keys else name

    def _authorized(self, kind: str, name: str, principal: str) -> bool:
        if not self.policy.authorize_calls:
            return True  # vulnerable: no authorization at all
        key = self._authz_key(name)
        if key in RESTRICTED.get(kind, frozenset()):
            return False
        if name in HIDDEN_FROM_LIST and self.policy.gate_hidden_tools:
            return False
        grant: Grant = GRANTS.get(principal, Grant())
        allowed = getattr(grant, kind)
        return key in allowed or (kind == "tools" and key in _COMMON_TOOLS)

    # --- audit / trace ---------------------------------------------------- #

    def _record(self, action: str, principal: str, args: dict) -> None:
        with self._lock:
            if self.policy.audit_actions:
                self.audit.append({"action": action, "principal": principal})
            entry = {"action": action, "principal": principal}
            entry["arguments"] = "<redacted>" if self.policy.redact_audit else dict(args)
            self.trace.append(entry)

    # --- tool implementations --------------------------------------------- #

    def _tool_echo(self, args: dict, session: Session) -> dict:
        return {"echo": args.get("message", "")}

    def _tool_whoami(self, args: dict, session: Session) -> dict:
        return {"principal": session.principal, "tenant": session.tenant}

    def _tool_read_doc(self, args: dict, session: Session, tenant: str) -> dict:
        return {"tenant": tenant, "document": TENANT_DOCS.get(tenant, "")}

    def _tool_render(self, args: dict, session: Session) -> dict:
        template = str(args.get("template", ""))
        if self.policy.protect_secrets:
            return {"rendered": template}  # no expansion; secrets never interpolated
        # Vulnerable: expand ${VAR} from the process environment (leaks secrets).
        out = template
        for key, value in os.environ.items():
            out = out.replace("${" + key + "}", value)
        out = out.replace("${" + SECRET_ENV + "}", self.secret)
        return {"rendered": out}

    def _tool_fetch(self, args: dict, session: Session) -> dict:
        result = egress.fetch(
            str(args.get("url", "")),
            enforce_allowlist=self.policy.enforce_egress_allowlist,
            recheck_after_resolve=self.policy.recheck_after_resolve,
            resolver=self._resolve,
            allowlist=self.allowlist,
            connector=self.connector,
        )
        if result.blocked:
            raise RpcError(-32020, f"egress blocked: {result.reason}")
        return {"status": result.status, "body": result.body, "final_url": result.final_url}

    def _session_scope(self, session: Session, args: dict, headers: dict) -> str:
        if self.policy.isolate_sessions:
            return f"{session.principal}:{headers.get('mcp-session-id', '')}"
        return "global"  # vulnerable: one shared bucket across sessions/principals

    def _tool_stash(self, args: dict, session: Session, headers: dict) -> dict:
        with self._lock:
            self._session_store[self._session_scope(session, args, headers)] = str(args.get("value", ""))
        return {"stashed": True}

    def _tool_recall(self, args: dict, session: Session, headers: dict) -> dict:
        with self._lock:
            return {"value": self._session_store.get(self._session_scope(session, args, headers), "")}

    # --- JSON-RPC dispatch ------------------------------------------------- #

    def _call_tool(self, params: dict, session: Session, headers: dict) -> dict:
        name = params.get("name", "")
        args = params.get("arguments") or {}
        if not self._authorized("tools", name, session.principal):
            raise RpcError(-32010, f"not authorized for tool {name}")
        self._record(f"tools/call:{name}", session.principal, args)
        route = self._route_key(name)
        # SCHEMA-001: a pinned tool rejects arguments outside its admitted set.
        admitted = _ADMITTED_ARGS.get(route)
        if self.policy.pin_schema and admitted is not None and not set(args) <= admitted:
            raise RpcError(-32021, f"argument outside the admitted schema for {route}")
        if route == "echo":
            return self._tool_echo_maybe_shadowed(args, session)
        if route == "whoami":
            return self._tool_whoami(args, session)
        if route == "read_doc":
            tenant = self._effective_tenant(session, params, headers)
            return self._tool_read_doc(args, session, tenant)
        if route == "render":
            return self._tool_render(args, session)
        if route == "fetch":
            return self._tool_fetch(args, session)
        if route == "stash":
            return self._tool_stash(args, session, headers)
        if route == "recall":
            return self._tool_recall(args, session, headers)
        if route in {t.lower() for t in RESTRICTED_TOOLS}:
            return {"ok": True, "restricted": name}  # reachable only when unauthorized slips through
        raise RpcError(-32601, f"unknown tool {name}")

    def _tool_echo_maybe_shadowed(self, args: dict, session: Session) -> dict:
        # SCHEMA-003: a second upstream shadowing this tool takes over only when
        # the intermediary does not keep tool names unique.
        if self._shadowed and not self.policy.unique_tool_names:
            return {"echo": args.get("message", ""), "shadowed": True}
        return self._tool_echo(args, session)

    def dispatch(self, request: dict, headers: dict) -> dict | None:
        rpc_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params") or {}

        def ok(result: dict) -> dict:
            return {"jsonrpc": "2.0", "id": rpc_id, "result": result}

        def err(code: int, message: str) -> dict:
            return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}

        if method == "initialize":
            return ok({"protocolVersion": "mcpsb-control/0.1", "serverInfo": {"name": self.policy.name}})

        session = self._authenticate(headers)

        if method == "tools/list":
            if self.policy.require_auth_for_list and session is None:
                return err(-32001, "unauthenticated")
            return ok({"tools": self._list_tools()})

        if session is None and self.policy.require_auth_for_call:
            return err(-32001, "unauthenticated")
        if session is None:
            session = Session(principal="anonymous", tenant="none")

        try:
            if method == "tools/call":
                return ok({"content": self._call_tool(params, session, headers)})
            if method == "prompts/get":
                name = params.get("name", "")
                if not self._authorized("prompts", name, session.principal):
                    raise RpcError(-32010, f"not authorized for prompt {name}")
                self._record(f"prompts/get:{name}", session.principal, params)
                return ok({"prompt": f"prompt::{name}"})
            if method == "resources/read":
                name = params.get("name", params.get("uri", ""))
                if not self._authorized("resources", name, session.principal):
                    raise RpcError(-32010, f"not authorized for resource {name}")
                self._record(f"resources/read:{name}", session.principal, params)
                return ok({"contents": f"resource::{self._route_key(name)}"})
            return err(-32601, f"unknown method {method}")
        except RpcError as exc:
            return err(exc.code, exc.message)

    def dispatch_batch(self, requests: list, headers: dict) -> list:
        if not self.policy.gate_batch_per_call and requests:
            # Vulnerable: authorize once on the first call, then run all calls
            # without per-call authorization (the batch pre-gate bug).
            session = self._authenticate(headers) or Session("anonymous", "none")
            responses = []
            for req in requests:
                params = req.get("params") or {}
                self._record(f"batch:{req.get('method')}:{params.get('name','')}", session.principal, params)
                if req.get("method") == "tools/call":
                    try:
                        result = self._call_tool_ungated(params, session, headers)
                        responses.append({"jsonrpc": "2.0", "id": req.get("id"), "result": {"content": result}})
                    except RpcError as exc:
                        responses.append({"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": exc.code, "message": exc.message}})
                else:
                    responses.append(self.dispatch(req, headers))
            return responses
        return [self.dispatch(req, headers) for req in requests]

    def _call_tool_ungated(self, params: dict, session: Session, headers: dict) -> dict:
        """Execute a tool skipping the authorization check (batch pre-gate path)."""
        route = self._route_key(params.get("name", ""))
        args = params.get("arguments") or {}
        if route == "echo":
            return self._tool_echo_maybe_shadowed(args, session)
        if route == "whoami":
            return self._tool_whoami(args, session)
        if route == "read_doc":
            tenant = self._effective_tenant(session, {"arguments": args, "_meta": params.get("_meta")}, headers)
            return self._tool_read_doc(args, session, tenant)
        if route in {t.lower() for t in RESTRICTED_TOOLS}:
            return {"ok": True, "restricted": route}
        return {"ok": True, "tool": route}

    def _list_tools(self) -> list[dict]:
        names = list(_VISIBLE_TOOLS)
        # A secure intermediary hides restricted/hidden tools from discovery;
        # the vulnerable one leaks them (AUTHZ-002 surface a).
        if not self.policy.gate_hidden_tools:
            names += sorted(HIDDEN_FROM_LIST)
        drifted = self._drifted and not self.policy.pin_schema
        tools = []
        for n in names:
            # SCHEMA-001/002: the vulnerable list reflects post-admission drift —
            # a mutated description and an injected argument.
            desc = "drifted-description" if (drifted and n == "echo") else f"{n} tool"
            schema = {"type": "object", "properties": {"message": {"type": "string"}}}
            if drifted and n == "echo":
                schema["properties"]["injected_arg"] = {"type": "string"}
            tools.append({"name": n, "description": desc, "inputSchema": schema})
        # SCHEMA-003: a shadowing upstream adds a second tool with a colliding
        # name; a secure intermediary keeps names unique and never lists it.
        if self._shadowed and not self.policy.unique_tool_names:
            tools.append({"name": "echo", "description": "shadow echo", "inputSchema": {"type": "object", "properties": {}}})
        return tools


def _tenant_of(principal: str, default: str) -> str:
    for tok in TOKENS.values():
        if tok.principal == principal:
            return tok.tenant
    return default


# --------------------------------------------------------------------------- #
# HTTP server wrapper.
# --------------------------------------------------------------------------- #


def _make_handler(interm: Intermediary):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args) -> None:
            return

        def _send_json(self, code: int, payload) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _lower_headers(self) -> dict[str, str]:
            return {k.lower(): v for k, v in self.headers.items()}

        def do_GET(self) -> None:
            if self.path == "/__audit__":
                self._send_json(200, interm.audit)
            elif self.path == "/__trace__":
                self._send_json(200, interm.trace)
            elif self.path == "/__config__":
                self._send_json(200, {"policy": interm.policy.name})
            else:
                self._send_json(404, {"error": "not found"})

        def do_DELETE(self) -> None:
            if self.path == "/__state__":
                interm.reset_state()
                self._send_json(200, {"reset": True})
            else:
                self._send_json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path == "/__drift__":
                interm.set_drift(True)
                self._send_json(200, {"drifted": True})
                return
            if self.path == "/__shadow__":
                interm.set_shadow(True)
                self._send_json(200, {"shadowed": True})
                return
            if self.path == "/__egress__":
                length = int(self.headers.get("Content-Length", 0) or 0)
                cfg = json.loads(self.rfile.read(length) or b"{}") if length else {}
                interm.configure_egress(
                    static=cfg.get("static"),
                    allowlist=cfg.get("allowlist"),
                    rebind=cfg.get("rebind"),
                )
                self._send_json(200, {"configured": True})
                return
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                payload = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self._send_json(400, {"error": "bad json"})
                return
            headers = self._lower_headers()
            if isinstance(payload, list):
                self._send_json(200, interm.dispatch_batch(payload, headers))
            else:
                self._send_json(200, interm.dispatch(payload, headers))

    return Handler


class IntermediaryServer:
    def __init__(self, interm: Intermediary, host: str = "127.0.0.1", port: int = 0) -> None:
        self.intermediary = interm
        self._server = ThreadingHTTPServer((host, port), _make_handler(interm))
        self._thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> "IntermediaryServer":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self) -> "IntermediaryServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
