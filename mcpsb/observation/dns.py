"""A bench-controlled DNS server with a rebinding zone (SPEC §3.1, SSRF-004).

The bench owns name resolution so it can (a) log every lookup out-of-band and
(b) make a name resolve to different addresses on successive lookups — the DNS
rebinding primitive behind SSRF-004: a name that is benign at policy-check time
and internal at connect time. Rebinding records serve TTL=0 to force the SUT to
re-resolve between the two.

This is a minimal UDP DNS server handling A/IN queries only, implemented on the
wire format directly (stdlib ``socketserver`` + ``struct``) so there is no
external dependency. Non-A/IN queries get an empty (NOERROR, ANCOUNT=0) answer.
"""

from __future__ import annotations

import socket
import socketserver
import struct
import threading
from dataclasses import dataclass, field

_TYPE_A = 1
_CLASS_IN = 1


# --------------------------------------------------------------------------- #
# Wire codec (A records only).
# --------------------------------------------------------------------------- #


def _parse_qname(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            break
        labels.append(data[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), offset


def parse_query(data: bytes) -> tuple[int, str, int, int]:
    """Return (txn_id, qname, qtype, qclass) from a DNS query packet."""
    txn_id = struct.unpack("!H", data[0:2])[0]
    qname, offset = _parse_qname(data, 12)  # header is 12 bytes
    qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    return txn_id, qname.rstrip("."), qtype, qclass


def build_response(data: bytes, ip: str | None, ttl: int = 0) -> bytes:
    """Build an A response echoing the query. ``ip=None`` -> empty answer."""
    txn_id = data[0:2]
    # Flags: QR=1, Opcode=0, AA=1, TC=0, RD(copy)=?, RA=0, RCODE=0.
    rd = data[2] & 0x01
    flags = 0x8400 | (rd << 8)
    # Question section starts at byte 12; find its end to echo it verbatim.
    _, q_end = _parse_qname(data, 12)
    q_end += 4  # QTYPE + QCLASS
    question = data[12:q_end]

    ancount = 1 if ip else 0
    header = txn_id + struct.pack("!HHHHH", flags, 1, ancount, 0, 0)

    if not ip:
        return header + question

    # Answer: name pointer to the question (0xC00C), type A, class IN, ttl, rdata.
    answer = struct.pack("!HHHIH", 0xC00C, _TYPE_A, _CLASS_IN, ttl, 4)
    answer += socket.inet_aton(ip)
    return header + question + answer


# --------------------------------------------------------------------------- #
# Zone controller.
# --------------------------------------------------------------------------- #


@dataclass
class Rebind:
    """A rebinding record: the Nth lookup returns ``sequence[N-1]``.

    The last element repeats for all further lookups. So ``["203.0.113.10",
    "127.0.0.1"]`` is benign on the first resolution and loopback on every
    resolution after — exactly the TOCTOU that SSRF-004 exercises.
    """

    sequence: list[str]


@dataclass
class DnsQuery:
    name: str
    qtype: int
    answer: str | None
    lookup_index: int  # 1-based count of lookups for this name so far


class DnsController:
    """Thread-safe zone config + query log. Shared by the UDP handler."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._static: dict[str, str] = {}
        self._rebinds: dict[str, Rebind] = {}
        self._counts: dict[str, int] = {}
        self._log: list[DnsQuery] = []

    # --- configuration ---------------------------------------------------- #

    def set_static(self, name: str, ip: str) -> None:
        with self._lock:
            self._static[name.lower().rstrip(".")] = ip

    def set_rebind(self, name: str, sequence: list[str]) -> None:
        if not sequence:
            raise ValueError("rebind sequence must be non-empty")
        with self._lock:
            self._rebinds[name.lower().rstrip(".")] = Rebind(list(sequence))

    # --- resolution (called by the handler) ------------------------------- #

    def resolve(self, name: str, qtype: int) -> str | None:
        key = name.lower().rstrip(".")
        with self._lock:
            if qtype != _TYPE_A:
                answer = None
                idx = self._counts.get(key, 0) + 1
                self._counts[key] = idx
            else:
                idx = self._counts.get(key, 0) + 1
                self._counts[key] = idx
                if key in self._rebinds:
                    seq = self._rebinds[key].sequence
                    answer = seq[min(idx - 1, len(seq) - 1)]
                else:
                    answer = self._static.get(key)
            self._log.append(
                DnsQuery(name=key, qtype=qtype, answer=answer, lookup_index=idx)
            )
            return answer

    # --- observation (used by attacks / self-tests) ----------------------- #

    def queries(self) -> list[DnsQuery]:
        with self._lock:
            return list(self._log)

    def queries_for(self, name: str) -> list[DnsQuery]:
        key = name.lower().rstrip(".")
        return [q for q in self.queries() if q.name == key]

    def clear(self) -> None:
        with self._lock:
            self._log.clear()
            self._counts.clear()


# --------------------------------------------------------------------------- #
# Server.
# --------------------------------------------------------------------------- #


def _make_handler(controller: DnsController):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data, sock = self.request
            try:
                txn_id, qname, qtype, qclass = parse_query(data)
            except (IndexError, struct.error):
                return  # malformed; drop
            ip = controller.resolve(qname, qtype) if qclass == _CLASS_IN else None
            sock.sendto(build_response(data, ip, ttl=0), self.client_address)

    return Handler


class _UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class DnsServer:
    """A running DNS server. Context manager for in-process tests."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.controller = DnsController()
        self._server = _UDPServer((host, port), _make_handler(self.controller))
        self._thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def start(self) -> DnsServer:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self) -> DnsServer:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def query_a(name: str, server_host: str, server_port: int, timeout: float = 2.0) -> str | None:
    """Minimal client: send an A query, return the first A answer or None.

    Used by the self-tests to prove the server's behavior without a resolver
    library. Builds a query packet, parses the first answer RR.
    """
    txn = b"\x12\x34"
    header = txn + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)  # RD=1
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in name.rstrip(".").split(".")
    ) + b"\x00"
    question = qname + struct.pack("!HH", _TYPE_A, _CLASS_IN)
    packet = header + question

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server_host, server_port))
        data, _ = s.recvfrom(512)

    ancount = struct.unpack("!H", data[6:8])[0]
    if ancount == 0:
        return None
    # Skip header + question to the first answer.
    _, offset = _parse_qname(data, 12)
    offset += 4  # QTYPE+QCLASS
    # Answer: name (2-byte pointer), type, class, ttl, rdlength, rdata.
    _name_ptr, atype, _aclass, _ttl, rdlen = struct.unpack(
        "!HHHIH", data[offset : offset + 12]
    )
    offset += 12
    if atype != _TYPE_A or rdlen != 4:
        return None
    return socket.inet_ntoa(data[offset : offset + 4])


def serve(host: str, port: int) -> None:
    """Blocking entry point for containerized deployment (see __main__)."""
    server = DnsServer(host, port).start()
    try:
        threading.Event().wait()
    finally:
        server.stop()
