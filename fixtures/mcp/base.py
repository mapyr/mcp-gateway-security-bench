"""A minimal MCP server framework for the malicious fixtures (WS-5).

JSON-RPC over HTTP POST, matching the bench's baseline transport, so the same
`mcpsb.client.MCPClient` can drive a fixture directly. Every inbound request is
recorded — the record is how the bench observes what an intermediary forwarded
to the (malicious) server, e.g. whether it leaked the client's token upstream.

Subclasses implement two methods: ``tool_defs()`` (what tools/list returns) and
``call_tool(name, arguments, headers)`` (what tools/call does). Everything else —
transport, recording, initialize — is handled here. Deterministic by
construction: no randomness, no time.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class Received:
    method: str
    params: dict
    headers: dict[str, str]
    seq: int


class ServerRecorder:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: list[Received] = []
        self._seq = 0

    def record(self, method: str, params: dict, headers: dict[str, str]) -> None:
        with self._lock:
            self._seq += 1
            self._items.append(Received(method, params, dict(headers), self._seq))

    def received(self) -> list[Received]:
        with self._lock:
            return list(self._items)

    def saw_header(self, name: str) -> bool:
        name = name.lower()
        return any(name in {k.lower() for k in r.headers} for r in self.received())

    def saw_value(self, needle: str) -> bool:
        """True if ``needle`` appears anywhere in a recorded request — used to
        detect that a secret/token was forwarded to the malicious server."""
        return any(needle in json.dumps(r.headers) or needle in json.dumps(r.params)
                   for r in self.received())

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


class BaseMCPServer:
    """Subclass and implement ``tool_defs`` / ``call_tool``."""

    name = "base"

    def __init__(self) -> None:
        self.recorder = ServerRecorder()

    # --- to override ------------------------------------------------------ #

    def tool_defs(self) -> list[dict]:
        return []

    def call_tool(self, name: str, arguments: dict, headers: dict[str, str]) -> dict:
        return {"ok": True, "tool": name}

    # --- JSON-RPC core ---------------------------------------------------- #

    def dispatch(self, request: dict, headers: dict[str, str]) -> dict:
        rpc_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params") or {}
        self.recorder.record(method, params, headers)

        if method == "initialize":
            result = {"protocolVersion": "mcpsb-fixture/0.1", "serverInfo": {"name": self.name}}
        elif method == "tools/list":
            result = {"tools": self.tool_defs()}
        elif method == "tools/call":
            result = {"content": self.call_tool(params.get("name", ""), params.get("arguments") or {}, headers)}
        else:
            return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32601, "message": f"unknown method {method}"}}
        return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


class MCPServerHost:
    """Runs a :class:`BaseMCPServer` over HTTP. Context manager for tests."""

    def __init__(self, server: BaseMCPServer, host: str = "127.0.0.1", port: int = 0) -> None:
        self.server = server
        self._http = ThreadingHTTPServer((host, port), _make_handler(server))
        self._thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        return self._http.server_address[0]

    @property
    def port(self) -> int:
        return self._http.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> "MCPServerHost":
        self._thread = threading.Thread(target=self._http.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._http.shutdown()
        self._http.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self) -> "MCPServerHost":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def _make_handler(server: BaseMCPServer):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b"{}"
            headers = {k.lower(): v for k, v in self.headers.items()}
            try:
                request = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self._send(400, {"error": "bad json"})
                return
            self._send(200, server.dispatch(request, headers))

        def _send(self, code: int, payload) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler
