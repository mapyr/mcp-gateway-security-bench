"""Tests for the OIDC issuer live-auth harness.

Skipped unless the optional ``live`` deps (PyJWT, cryptography) are installed;
the core bench is stdlib-only. This validates the issuer the way a real resource
server does: fetch the JWKS, accept a valid token, reject expired and
wrong-audience ones."""

from __future__ import annotations

import json
import urllib.request

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

import jwt  # noqa: E402
from jwt import PyJWKClient  # noqa: E402

from fixtures.oidc.issuer import OidcIssuer  # noqa: E402

AUD = "mcpsb-test-aud"


def _decode(token: str, jwks_uri: str):
    key = PyJWKClient(jwks_uri).get_signing_key_from_jwt(token).key
    return jwt.decode(token, key, algorithms=["RS256"], audience=AUD)


def test_discovery_and_jwks_served():
    with OidcIssuer(audience=AUD) as iss:
        disc = json.load(urllib.request.urlopen(iss.issuer_url + "/.well-known/openid-configuration"))
        assert disc["issuer"] == iss.issuer_url
        assert disc["jwks_uri"] == iss.jwks_uri
        jwks = json.load(urllib.request.urlopen(iss.jwks_uri))
        assert jwks["keys"][0]["kty"] == "RSA" and jwks["keys"][0]["alg"] == "RS256"


def test_valid_token_accepted():
    with OidcIssuer(audience=AUD) as iss:
        claims = _decode(iss.mint("alice", tenant="acme"), iss.jwks_uri)
        assert claims["sub"] == "alice" and claims["tenant"] == "acme"
        assert claims["aud"] == AUD and claims["iss"] == iss.issuer_url


def test_expired_token_rejected():
    with OidcIssuer(audience=AUD) as iss:
        with pytest.raises(jwt.ExpiredSignatureError):
            _decode(iss.mint("alice", expired=True), iss.jwks_uri)


def test_wrong_audience_rejected():
    with OidcIssuer(audience=AUD) as iss:
        with pytest.raises(jwt.InvalidAudienceError):
            _decode(iss.mint("alice", aud="some-other-api"), iss.jwks_uri)


def test_public_url_overrides_iss_but_not_bind(tmp_path=None):
    # A networked issuer binds to 0.0.0.0 but advertises the on-network URL as
    # iss (WS-A). The bind host must stay usable for the local test client.
    public = "http://mcpsb-issuer:8080"
    with OidcIssuer(audience=AUD, public_url=public) as iss:
        assert iss.issuer_url == public
        assert iss.jwks_uri == public + "/jwks"
        # discovery is served over the real socket but advertises the public iss.
        disc = json.load(urllib.request.urlopen(f"http://127.0.0.1:{iss.port}/.well-known/openid-configuration"))
        assert disc["issuer"] == public and disc["jwks_uri"] == public + "/jwks"
        # a token minted here carries the public iss, so a target validating
        # against the public discovery accepts it.
        tok = iss.mint("alice", tenant="acme")
        assert jwt.get_unverified_header(tok)["kid"]
        assert jwt.decode(tok, options={"verify_signature": False})["iss"] == public


def test_mint_endpoint_returns_valid_token():
    with OidcIssuer(audience=AUD) as iss:
        raw = urllib.request.urlopen(iss.issuer_url + "/mint?sub=alice&tenant=acme").read()
        token = json.loads(raw)["token"]
        claims = _decode(token, iss.jwks_uri)
        assert claims["sub"] == "alice" and claims["tenant"] == "acme"


def test_mint_endpoint_expired_and_wrong_aud():
    with OidcIssuer(audience=AUD) as iss:
        expired = json.loads(urllib.request.urlopen(iss.issuer_url + "/mint?sub=alice&expired=1").read())["token"]
        with pytest.raises(jwt.ExpiredSignatureError):
            _decode(expired, iss.jwks_uri)
        wrongaud = json.loads(urllib.request.urlopen(iss.issuer_url + "/mint?sub=alice&aud=other").read())["token"]
        with pytest.raises(jwt.InvalidAudienceError):
            _decode(wrongaud, iss.jwks_uri)


def test_https_serving(tmp_path):
    # A real OIDC issuer serves HTTPS; some targets (ToolHive) refuse a plain-HTTP
    # issuer for discovery. Prove the issuer serves TLS and advertises https iss.
    import datetime as _dt
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.x509.oid import NameOID

    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime(2020, 1, 1))
        .not_valid_after(_dt.datetime(2035, 1, 1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certfile, keyfile = tmp_path / "cert.pem", tmp_path / "key.pem"
    certfile.write_bytes(cert.public_bytes(_ser.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(
        _ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL, _ser.NoEncryption()))

    iss = OidcIssuer(host="127.0.0.1", audience=AUD,
                     certfile=str(certfile), keyfile=str(keyfile))
    iss.start()
    try:
        assert iss.issuer_url.startswith("https://")
        ctx = ssl.create_default_context(cafile=str(certfile))
        ctx.check_hostname = False
        url = f"https://127.0.0.1:{iss.port}/.well-known/openid-configuration"
        disc = json.load(urllib.request.urlopen(url, context=ctx))
        assert disc["issuer"] == iss.issuer_url
    finally:
        iss.stop()
