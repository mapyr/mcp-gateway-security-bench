"""The egress engine for the reference intermediary's ``fetch`` tool.

This is where the SSRF / egress invariants are enforced (or, on the vulnerable
control, not). The flow deliberately models the real TOCTOU surface:

1. resolve the host at *policy* time and, if the allowlist is enforced, check
   both the host name (whole-label match, not suffix) and the resolved IP range;
2. resolve the host *again* at connect time — with TTL=0 rebinding, this is
   where the answer can flip to an internal address;
3. connect to the connect-time IP, following redirects, re-entering the whole
   check on every hop.

The two policy flags select what is enforced:

* ``enforce_egress_allowlist`` — the host/IP-range check at step 1 and on every
  redirect hop. Catches static-internal SSRF (loopback, RFC1918, IMDS,
  IPv4-mapped) and suffix confusion.
* ``recheck_after_resolve`` — validates the *connect-time* IP at step 2. Catches
  DNS rebinding, where the policy-time IP was benign.

Hermetic by construction (invariant #9): resolution goes through an injected
resolver, never the system DNS, and an unresolvable host fails closed.
"""

from __future__ import annotations

import http.client
import ipaddress
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin, urlsplit

Resolver = Callable[[str], "str | None"]
Connector = Callable[[str, int, str, str], "tuple[int, dict[str, str], str]"]

_REDIRECT_CODES = {301, 302, 303, 307, 308}


@dataclass
class FetchResult:
    blocked: bool
    reason: str = ""
    status: int | None = None
    body: str = ""
    final_url: str = ""
    hops: int = 0


def unwrap_ip(ip: str) -> ipaddress._BaseAddress:
    addr = ipaddress.ip_address(ip)
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped if mapped is not None else addr


def is_blocked_ip(ip: str) -> bool:
    """True if ``ip`` is in a range the intermediary must never reach for a
    server: loopback, private (RFC1918), link-local (incl. IMDS 169.254.x),
    multicast, reserved, or unspecified. IPv4-mapped IPv6 is unwrapped first."""
    try:
        addr = unwrap_ip(ip)
    except ValueError:
        return True  # unparseable -> fail closed
    return (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def host_allowed(host: str, allowlist: frozenset[str]) -> bool:
    """Whole-label match against the allowlist (SPEC EGRESS-001).

    ``api.example.com`` matches ``api.example.com`` but NOT
    ``api.example.com.evil.com`` — string suffix logic is exactly the bug this
    guards against, so matching is on the full normalized host only.
    """
    return host.lower().rstrip(".") in {h.lower().rstrip(".") for h in allowlist}


def literal_or_map_resolver(mapping: dict[str, str]) -> Resolver:
    """A hermetic resolver: returns IP literals as-is and known names from
    ``mapping``; everything else is unresolvable (fails closed, invariant #9)."""

    def resolve(host: str) -> str | None:
        try:
            ipaddress.ip_address(host)
            return host  # already an IP literal
        except ValueError:
            return mapping.get(host.lower().rstrip("."))

    return resolve


def default_connector(ip: str, port: int, host: str, path: str) -> tuple[int, dict[str, str], str]:
    """Real HTTP GET to ip:port, sending the intended ``host`` as the Host header
    so the sink records the host the caller aimed at.

    IPv4-mapped IPv6 is unwrapped for the socket, so a call to ``::ffff:127.0.0.1``
    reaches the same v4 listener it denotes — the point of SSRF-003 is that the
    encoding does not change the destination."""
    conn = http.client.HTTPConnection(str(unwrap_ip(ip)), port, timeout=3)
    try:
        conn.request("GET", path or "/", headers={"Host": host})
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.getcode(), headers, body
    finally:
        conn.close()


def _split(url: str) -> tuple[str, int, str]:
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return host, port, path


def fetch(
    url: str,
    *,
    enforce_allowlist: bool,
    recheck_after_resolve: bool,
    resolver: Resolver,
    allowlist: frozenset[str],
    connector: Connector = default_connector,
    max_redirects: int = 4,
) -> FetchResult:
    current = url
    for hop in range(max_redirects + 1):
        host, port, path = _split(current)
        if not host:
            return FetchResult(blocked=True, reason="no host", hops=hop)

        ip1 = resolver(host)
        if ip1 is None:
            return FetchResult(blocked=True, reason=f"unresolvable host {host}", hops=hop)

        if enforce_allowlist:
            if not host_allowed(host, allowlist):
                return FetchResult(blocked=True, reason=f"host not allowlisted: {host}", hops=hop)
            if is_blocked_ip(ip1):
                return FetchResult(blocked=True, reason=f"resolved to blocked range: {ip1}", hops=hop)

        # Re-resolve at connect time — rebinding flips the answer here.
        ip2 = resolver(host) or ip1
        if enforce_allowlist and recheck_after_resolve and is_blocked_ip(ip2):
            return FetchResult(blocked=True, reason=f"connect-time IP blocked: {ip2}", hops=hop)

        status, headers, body = connector(ip2, port, host, path)
        if status in _REDIRECT_CODES and headers.get("location"):
            current = urljoin(current, headers["location"])
            continue
        return FetchResult(blocked=False, status=status, body=body, final_url=current, hops=hop)

    return FetchResult(blocked=True, reason="too many redirects", hops=max_redirects)
