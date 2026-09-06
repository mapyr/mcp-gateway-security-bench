"""A generic MCP Streamable-HTTP client (WS-6/7).

Several real gateways (ToolHive, Docker MCP Gateway) expose MCP over Streamable
HTTP rather than the bench's baseline plain JSON-RPC POST. This client presents
the same surface as :class:`mcpsb.client.MCPClient` (so attacks are unchanged)
but posts to the gateway's MCP endpoint and parses either a JSON body or an
SSE-framed response. The MCP endpoint path is configurable (default ``/mcp``).

It is exercised only against a live gateway; until then it is inert.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from mcpsb.client import RpcResponse


_PROTOCOL_VERSION = "2025-06-18"


class StreamableHttpClient:
    def __init__(self, base_url: str, *, token: str | None = None, mcp_path: str = "/mcp") -> None:
        base = base_url.rstrip("/")
        self.mcp_url = base if base.endswith(mcp_path) else base + mcp_path
        self.token = token
        self._session_id: str | None = None
        self._handshake_done = False

    def _headers(self, token: str | None, extra: dict | None) -> dict:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": _PROTOCOL_VERSION,
        }
        tok = token if token is not None else self.token
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        if extra:
            headers.update(extra)
        return headers

    def _ensure_handshake(self, token: str | None) -> None:
        """Streamable HTTP requires an initialize handshake before any other
        method (the gateway returns a session id to carry on later requests).
        Best-effort: if initialize is itself rejected (e.g. a no-token 401), we
        proceed without a session so the caller sees the real block."""
        if self._handshake_done:
            return
        self._handshake_done = True
        init = {
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": _PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": "mcpsb", "version": "0.1"}},
        }
        req = urllib.request.Request(
            self.mcp_url, data=json.dumps(init).encode(),
            headers=self._headers(token, None), method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                self._session_id = resp.headers.get("Mcp-Session-Id")
                resp.read()
        except urllib.error.HTTPError:
            return  # initialize rejected; caller's request will reveal the block
        if self._session_id:
            # Notify initialized so the session leaves the init phase.
            note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
            noreq = urllib.request.Request(
                self.mcp_url, data=json.dumps(note).encode(),
                headers=self._headers(token, None), method="POST",
            )
            try:
                urllib.request.urlopen(noreq, timeout=10).read()  # noqa: S310
            except urllib.error.HTTPError:
                pass

    def raw(self, payload, *, token: str | None = None, headers: dict | None = None, path: str = "") -> RpcResponse:
        self._ensure_handshake(token)
        url = self.mcp_url + path if path else self.mcp_url
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers=self._headers(token, headers), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 — bench-controlled
                return RpcResponse(resp.status, _parse_body(resp.read(), resp.headers.get("Content-Type", "")))
        except urllib.error.HTTPError as exc:
            return RpcResponse(exc.code, _parse_body(exc.read(), exc.headers.get("Content-Type", "")))

    def request(self, method: str, params: dict | None = None, *, token=None, headers=None, rpc_id: int = 1) -> RpcResponse:
        payload = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
        if params is not None:
            payload["params"] = params
        return self.raw(payload, token=token, headers=headers)

    def tools_list(self, **kw) -> RpcResponse:
        return self.request("tools/list", {}, **kw)

    def tools_call(self, name: str, arguments: dict | None = None, *, meta: dict | None = None, **kw) -> RpcResponse:
        params: dict = {"name": name, "arguments": arguments or {}}
        if meta is not None:
            params["_meta"] = meta
        return self.request("tools/call", params, **kw)

    def prompts_get(self, name: str, **kw) -> RpcResponse:
        return self.request("prompts/get", {"name": name}, **kw)

    def resources_read(self, name: str, **kw) -> RpcResponse:
        return self.request("resources/read", {"name": name}, **kw)

    def batch(self, requests: list[dict], **kw) -> RpcResponse:
        return self.raw(requests, **kw)


def make_factory(mcp_path: str = "/mcp"):
    """A ``(base_url, token) -> client`` factory bound to an MCP endpoint path."""

    def factory(base_url: str, token: str | None = None) -> StreamableHttpClient:
        return StreamableHttpClient(base_url, token=token, mcp_path=mcp_path)

    return factory


def _parse_body(raw: bytes, content_type: str):
    text = (raw or b"").decode("utf-8", "replace").strip()
    if not text:
        return None
    if "text/event-stream" in content_type or text.startswith("event:") or text.startswith("data:"):
        for line in reversed(text.splitlines()):
            line = line.strip()
            if line.startswith("data:"):
                try:
                    return json.loads(line[len("data:"):].strip())
                except json.JSONDecodeError:
                    return None
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
