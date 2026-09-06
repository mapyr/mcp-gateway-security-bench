"""A minimal OIDC issuer for live auth testing (harness, not core).

An OIDC-based intermediary validates incoming client JWTs against an issuer's
JWKS. To test its AUTH/AUTHZ families live, the bench needs to mint tokens the
target trusts: this stands up a local issuer that serves OIDC discovery + a
JWKS, and mints RS256-signed JWTs for the bench's principals (valid, expired,
wrong-audience, distinct tenants). It names no specific target.

Optional dependency: requires ``PyJWT`` and ``cryptography`` (declared under the
``live`` extra). The core bench is stdlib-only; this is only imported for live
runs against OIDC targets.
"""

from __future__ import annotations

import base64
import datetime
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_KID = "mcpsb-oidc-key-1"


def _b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class OidcIssuer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0, audience: str = "mcpsb", *,
                 tenant_claim: str = "tenant", public_url: str | None = None,
                 certfile: str | None = None, keyfile: str | None = None) -> None:
        self.audience = audience
        self.tenant_claim = tenant_claim
        #: The URL targets reach this issuer at. When the issuer binds to
        #: ``0.0.0.0`` in a container, the bind host is not a usable ``iss``; the
        #: harness passes the on-network address (or alias) as ``public_url`` so
        #: discovery, ``iss``, and ``jwks_uri`` all match what the target validates.
        self._public_url = public_url.rstrip("/") if public_url else None
        #: TLS: a real OIDC issuer serves over HTTPS, and some intermediaries
        #: refuse a plain-HTTP issuer for discovery. When a cert/key are given the
        #: socket is wrapped and issuer_url defaults to https.
        self._tls = bool(certfile and keyfile)
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._private_pem = self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self._server = ThreadingHTTPServer((host, port), self._handler())
        if self._tls:
            import ssl

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
            self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self._thread: threading.Thread | None = None

    # --- addressing ------------------------------------------------------- #

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def issuer_url(self) -> str:
        scheme = "https" if self._tls else "http"
        return self._public_url or f"{scheme}://{self.host}:{self.port}"

    @property
    def jwks_uri(self) -> str:
        return self.issuer_url + "/jwks"

    # --- token minting ---------------------------------------------------- #

    def mint(self, sub: str, *, tenant: str | None = None, aud: str | None = None,
             expired: bool = False, lifetime: int = 3600) -> str:
        """Mint an RS256 JWT for ``sub``. ``expired`` backdates it; ``aud``
        overrides the audience (pass a wrong value to test audience binding)."""
        now = datetime.datetime.now(datetime.timezone.utc)
        iat = now - datetime.timedelta(hours=2) if expired else now
        exp = iat + datetime.timedelta(seconds=lifetime)
        claims = {
            "iss": self.issuer_url,
            "sub": sub,
            "aud": aud if aud is not None else self.audience,
            "iat": int(iat.timestamp()),
            "nbf": int(iat.timestamp()),
            "exp": int(exp.timestamp()),
        }
        if tenant is not None:
            claims[self.tenant_claim] = tenant
        return jwt.encode(claims, self._private_pem, algorithm="RS256", headers={"kid": _KID})

    # --- published metadata ----------------------------------------------- #

    def jwks(self) -> dict:
        pub = self._key.public_key().public_numbers()
        return {"keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": _KID,
            "n": _b64url_uint(pub.n), "e": _b64url_uint(pub.e),
        }]}

    def discovery(self) -> dict:
        return {
            "issuer": self.issuer_url,
            "jwks_uri": self.jwks_uri,
            "authorization_endpoint": self.issuer_url + "/authorize",
            "token_endpoint": self.issuer_url + "/token",
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid"],
        }

    # --- HTTP server ------------------------------------------------------ #

    def _handler(self):
        issuer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a) -> None:
                return

            def _send(self, payload: dict, status: int = 200) -> None:
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                parsed = urlsplit(self.path)
                path = parsed.path
                if path in ("/.well-known/openid-configuration",
                            "/.well-known/oauth-authorization-server"):
                    self._send(issuer.discovery())
                elif path in ("/jwks", "/.well-known/jwks.json"):
                    self._send(issuer.jwks())
                elif path == "/mint":
                    self._mint(parse_qs(parsed.query))
                else:
                    self.send_error(404)

            def _mint(self, q: dict) -> None:
                # The signing key never leaves the container; the bench asks the
                # issuer to mint a token for a principal over HTTP. A test harness
                # mint endpoint is intentionally open (no client auth).
                sub = (q.get("sub") or [""])[0]
                if not sub:
                    self._send({"error": "sub is required"}, status=400)
                    return
                tenant = (q.get("tenant") or [None])[0]
                aud = (q.get("aud") or [None])[0]
                expired = (q.get("expired") or ["0"])[0] in ("1", "true", "yes")
                token = issuer.mint(sub, tenant=tenant, aud=aud, expired=expired)
                self._send({"token": token})

        return Handler

    def start(self) -> "OidcIssuer":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self) -> "OidcIssuer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def main(argv: "list[str] | None" = None) -> int:
    """Run the issuer as a networked service (WS-A).

    First-class on the bench network: the harness attaches it to every target's
    network so a target validates the bench's tokens against a reachable issuer.
    ``--public-url`` is the address targets reach it at (the ``iss`` value).
    """
    import argparse

    parser = argparse.ArgumentParser(prog="mcpsb-oidc-issuer")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--audience", default="mcpsb")
    parser.add_argument(
        "--public-url",
        default=None,
        help="URL targets reach this issuer at (becomes iss); defaults to host:port",
    )
    parser.add_argument("--tls-cert", default=None, help="PEM cert to serve HTTPS")
    parser.add_argument("--tls-key", default=None, help="PEM private key for --tls-cert")
    args = parser.parse_args(argv)
    issuer = OidcIssuer(
        host=args.host, port=args.port, audience=args.audience, public_url=args.public_url,
        certfile=args.tls_cert, keyfile=args.tls_key,
    )
    issuer.start()
    print(f"OIDC issuer serving; iss={issuer.issuer_url} bind={args.host}:{issuer.port}", flush=True)
    try:
        issuer._thread.join()  # type: ignore[union-attr]
    except KeyboardInterrupt:
        issuer.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
