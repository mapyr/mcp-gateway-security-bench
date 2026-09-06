"""The HTTP sink — the primary observation surface (SPEC §3.1).

The sink records every inbound HTTP request out-of-band: method, the Host header
the client used, path, headers, body, and source address. A verdict about
egress ("did the intermediary forward this call to a place it shouldn't?") is
read from what the sink recorded, never from the SUT's own logs.

Two roles on one server, separated by a reserved control prefix:

* any request NOT under ``/__mcpsb__/`` is *recorded* and answered with 200;
* ``GET /__mcpsb__/records`` returns the recorded requests as JSON, and
  ``DELETE /__mcpsb__/records`` clears them — so a separate bench process (or a
  container) can read the log without polluting it.

Stdlib only; no external dependencies (hermetic by construction).
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONTROL_PREFIX = "/__mcpsb__/"
_RECORDS_PATH = CONTROL_PREFIX + "records"


@dataclass
class SinkRequest:
    method: str
    host: str  # the Host header the client sent
    path: str
    headers: dict[str, str]
    body: str
    client_ip: str
    seq: int

    def to_json(self) -> dict:
        return {
            "method": self.method,
            "host": self.host,
            "path": self.path,
            "headers": self.headers,
            "body": self.body,
            "client_ip": self.client_ip,
            "seq": self.seq,
        }


class SinkRecorder:
    """Thread-safe store of recorded requests, shared by the handler."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[SinkRequest] = []
        self._seq = 0

    def record(self, req_without_seq: dict) -> None:
        with self._lock:
            self._seq += 1
            self._records.append(SinkRequest(seq=self._seq, **req_without_seq))

    def records(self) -> list[SinkRequest]:
        with self._lock:
            return list(self._records)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()

    # --- assertions (used by attacks in WS-4) ----------------------------- #

    def received(self, *, host: str | None = None, path: str | None = None) -> bool:
        """True if any recorded request matches the given host and/or path."""
        for r in self.records():
            if host is not None and r.host.split(":")[0] != host:
                continue
            if path is not None and r.path != path:
                continue
            return True
        return False

    def count(self) -> int:
        return len(self.records())


def _make_handler(recorder: SinkRecorder):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        # Silence default stderr logging; the recorder is the record of truth.
        def log_message(self, *args) -> None:  # noqa: D401
            return

        def _read_body(self) -> str:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length <= 0:
                return ""
            return self.rfile.read(length).decode("utf-8", "replace")

        def _send(self, code: int, body: bytes, ctype: str = "text/plain") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle_control(self) -> bool:
            if self.path != _RECORDS_PATH:
                self._send(404, b"unknown control path")
                return True
            if self.command == "GET":
                payload = json.dumps(
                    [r.to_json() for r in recorder.records()]
                ).encode()
                self._send(200, payload, "application/json")
            elif self.command == "DELETE":
                recorder.clear()
                self._send(200, b"cleared")
            else:
                self._send(405, b"method not allowed on control path")
            return True

        def _handle_any(self) -> None:
            if self.path.startswith(CONTROL_PREFIX):
                self._handle_control()
                return
            recorder.record(
                {
                    "method": self.command,
                    "host": self.headers.get("Host", ""),
                    "path": self.path,
                    "headers": {k: v for k, v in self.headers.items()},
                    "body": self._read_body(),
                    "client_ip": self.client_address[0],
                }
            )
            self._send(200, b"recorded")

        # All verbs funnel through _handle_any.
        do_GET = _handle_any
        do_POST = _handle_any
        do_PUT = _handle_any
        do_DELETE = _handle_any
        do_HEAD = _handle_any
        do_PATCH = _handle_any

    return Handler


class Sink:
    """A running sink server. Use as a context manager for in-process tests."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.recorder = SinkRecorder()
        self._server = ThreadingHTTPServer((host, port), _make_handler(self.recorder))
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

    def start(self) -> Sink:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self) -> Sink:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def serve(host: str, port: int) -> None:
    """Blocking entry point for containerized deployment (see __main__)."""
    sink = Sink(host, port).start()
    try:
        threading.Event().wait()
    finally:
        sink.stop()
