"""A minimal, target-agnostic MCP client for attacks (WS-4).

Attacks drive a target over MCP JSON-RPC and read verdicts from the observation
plane. This client speaks the baseline transport — JSON-RPC over HTTP ``POST`` —
and knows nothing about any specific target (invariant #3). It lets an attack
send well-formed calls, malformed ones, custom headers, ``_meta``, and batches,
and always returns the raw JSON-RPC response for inspection.

A target whose transport differs from the baseline supplies its own client via
its adapter in a later workstream; the attack code stays the same because it
talks to whatever ``ctx`` hands it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class RpcResponse:
    status: int
    body: dict | list | None

    @property
    def is_error(self) -> bool:
        return isinstance(self.body, dict) and "error" in self.body

    @property
    def result(self) -> dict | None:
        return self.body.get("result") if isinstance(self.body, dict) else None


class MCPClient:
    def __init__(self, base_url: str, *, token: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def _headers(self, token: str | None, extra: dict | None) -> dict:
        headers = {"Content-Type": "application/json"}
        tok = token if token is not None else self.token
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        if extra:
            headers.update(extra)
        return headers

    def raw(self, payload, *, token: str | None = None, headers: dict | None = None, path: str = "") -> RpcResponse:
        """POST an arbitrary JSON payload (object or batch array) and return the
        parsed response. Never raises on HTTP error status — attacks need to see
        the target's actual response, including 4xx/5xx bodies."""
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.base_url + path, data=data, headers=self._headers(token, headers), method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 — bench-local
                raw = resp.read()
                return RpcResponse(resp.status, _parse(raw))
        except urllib.error.HTTPError as exc:
            return RpcResponse(exc.code, _parse(exc.read()))

    def request(
        self,
        method: str,
        params: dict | None = None,
        *,
        token: str | None = None,
        headers: dict | None = None,
        rpc_id: int = 1,
    ) -> RpcResponse:
        payload = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
        if params is not None:
            payload["params"] = params
        return self.raw(payload, token=token, headers=headers)

    # Convenience wrappers per surface.
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


def _parse(raw: bytes):
    try:
        return json.loads(raw or b"null")
    except json.JSONDecodeError:
        return None
