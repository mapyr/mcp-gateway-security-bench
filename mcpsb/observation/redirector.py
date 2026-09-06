"""A redirect server for the redirect-past-allowlist test (SPEC §3.1, SSRF-005).

Issues configurable 302 chains, including cross-origin, so the bench can check
that an egress allowlist governs the *final* destination reached, not just the
first hop. Every hop is recorded out-of-band.

Endpoints:

* ``GET /hop/<n>?to=<url>`` — if ``n > 0``, 302 to ``/hop/<n-1>?to=<url>``
  (same host); when ``n`` reaches 0, 302 to ``to`` (typically an internal URL or
  the sink). ``n`` builds a same-origin chain that finally jumps cross-origin.
* ``GET /to?url=<url>`` — a single 302 straight to ``url``.

The final destination is where the FAIL is observed (the sink or IMDS records
the hit); this server only records that the SUT followed the chain.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


@dataclass
class RedirectHit:
    path: str
    location: str
    client_ip: str
    seq: int


class RedirectRecorder:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: list[RedirectHit] = []
        self._seq = 0

    def record(self, path: str, location: str, client_ip: str) -> None:
        with self._lock:
            self._seq += 1
            self._hits.append(RedirectHit(path, location, client_ip, self._seq))

    def hits(self) -> list[RedirectHit]:
        with self._lock:
            return list(self._hits)

    def hop_count(self) -> int:
        return len(self.hits())

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


def _make_handler(recorder: RedirectRecorder, self_base: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args) -> None:
            return

        def _redirect(self, location: str) -> None:
            recorder.record(self.path, location, self.client_address[0])
            body = f"redirecting to {location}".encode()
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            if parsed.path.startswith("/hop/"):
                try:
                    n = int(parsed.path.split("/")[2])
                except (IndexError, ValueError):
                    self.send_error(400)
                    return
                to = qs.get("to", [""])[0]
                if n > 0:
                    self._redirect(f"{self_base}/hop/{n - 1}?to={to}")
                else:
                    self._redirect(to)
            elif parsed.path == "/to":
                self._redirect(qs.get("url", [""])[0])
            else:
                self.send_error(404)

    return Handler


class Redirector:
    """A running redirect server. Context manager for in-process tests."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, advertised_base: str | None = None) -> None:
        self.recorder = RedirectRecorder()
        self._server = ThreadingHTTPServer((host, port), None)  # handler set below
        base = advertised_base or f"http://{self._server.server_address[0]}:{self._server.server_address[1]}"
        self._server.RequestHandlerClass = _make_handler(self.recorder, base)
        self._base = base
        self._thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def base_url(self) -> str:
        return self._base

    def start(self) -> Redirector:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self) -> Redirector:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def serve(host: str, port: int, advertised_base: str | None = None) -> None:
    """Blocking entry point for containerized deployment (see __main__)."""
    redir = Redirector(host, port, advertised_base).start()
    try:
        threading.Event().wait()
    finally:
        redir.stop()
