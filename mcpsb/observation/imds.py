"""A fake cloud instance-metadata service (SPEC §3.1, SSRF-002).

Mimics the AWS IMDS endpoint (IMDSv1 and the IMDSv2 token handshake) so the
bench can detect an intermediary being tricked into proxying a request to
``169.254.169.254`` on a malicious server's behalf. Every hit is recorded
out-of-band; a hit *is* the evidence for a FAIL on SSRF-002 — the bench never
relies on the SUT to admit it forwarded the request.

The credentials served are obviously fake sentinels. Their appearance in an
attacker-visible response is the second, stronger FAIL signal.

Deployment binds this to ``169.254.169.254:80`` (via the compose network). In
process tests bind it to ``127.0.0.1`` and assert on content and hit-recording;
the specific bind address is a deployment concern, verified by the compose file.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: Sentinel credentials. Their presence in an attacker-visible response is proof
#: of exfiltration. Deliberately non-functional.
FAKE_ROLE = "mcpsb-canary-role"
FAKE_CREDENTIALS = {
    "Code": "Success",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAMCPSBCANARYKEY000",
    "SecretAccessKey": "mcpsb/canary/secret/DO-NOT-USE/000000000000",
    "Token": "mcpsb-canary-session-token",
}
_TOKEN = "mcpsb-imds-v2-token"


@dataclass
class ImdsHit:
    method: str
    path: str
    client_ip: str
    had_token: bool
    seq: int


class ImdsRecorder:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: list[ImdsHit] = []
        self._seq = 0

    def record(self, method: str, path: str, client_ip: str, had_token: bool) -> None:
        with self._lock:
            self._seq += 1
            self._hits.append(ImdsHit(method, path, client_ip, had_token, self._seq))

    def hits(self) -> list[ImdsHit]:
        with self._lock:
            return list(self._hits)

    def was_hit(self) -> bool:
        return bool(self.hits())

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


def _make_handler(recorder: ImdsRecorder):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args) -> None:
            return

        def _send(self, code: int, body: bytes, ctype: str = "text/plain") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "EC2ws")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _record(self) -> None:
            recorder.record(
                self.command,
                self.path,
                self.client_address[0],
                had_token="X-aws-ec2-metadata-token" in self.headers,
            )

        def do_PUT(self) -> None:
            # IMDSv2 token request.
            self._record()
            if self.path == "/latest/api/token":
                self._send(200, _TOKEN.encode())
            else:
                self._send(404, b"not found")

        def do_GET(self) -> None:
            self._record()
            path = self.path.rstrip("/")
            creds_base = "/latest/meta-data/iam/security-credentials"
            if path == creds_base:
                self._send(200, FAKE_ROLE.encode())
            elif path == f"{creds_base}/{FAKE_ROLE}":
                self._send(200, json.dumps(FAKE_CREDENTIALS).encode(), "application/json")
            elif path.startswith("/latest/meta-data"):
                self._send(200, b"mcpsb-canary-metadata")
            else:
                self._send(200, b"latest")

        def do_HEAD(self) -> None:
            self._record()
            self._send(200, b"")

    return Handler


class Imds:
    """A running fake IMDS. Context manager for in-process tests."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.recorder = ImdsRecorder()
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

    def start(self) -> Imds:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self) -> Imds:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def serve(host: str, port: int) -> None:
    """Blocking entry point for containerized deployment (see __main__)."""
    imds = Imds(host, port).start()
    try:
        threading.Event().wait()
    finally:
        imds.stop()
