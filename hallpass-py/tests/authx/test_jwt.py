"""Port of internal/authx/jwt_test.go. TestRFC7515A2 is in test_rfc7515.py
with its vector."""

from __future__ import annotations

import base64
import datetime
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from hallpass.authx.jwt import (
    PS256,
    RS256,
    Header,
    cert_thumbprint_sha256,
    decode_jwt_claims,
    new_jti,
    parse_certificate,
    parse_rsa_private_key,
    sign_jwt,
    standard_claims,
    verify,
)


def _pem(typ: str, der: bytes) -> bytes:
    """pem.EncodeToMemory."""
    b64 = base64.b64encode(der).decode()
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return (f"-----BEGIN {typ}-----\n" + "".join(line + "\n" for line in lines) + f"-----END {typ}-----\n").encode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def test_parse_keys() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pkcs1 = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    pkcs8 = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    assert pkcs1.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    n = key.private_numbers().public_numbers.n
    for inp in (pkcs1, pkcs8, b"junk\n" + pkcs8):
        k = parse_rsa_private_key(inp)
        assert k.private_numbers().public_numbers.n == n
    for bad in (b"nope", _pem("ENCRYPTED PRIVATE KEY", b"\x01"), _pem("CERTIFICATE", b"\x01")):
        with pytest.raises(Exception):  # noqa: B017 - any error
            parse_rsa_private_key(bad)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hallpass")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert_obj = (
        x509.CertificateBuilder()
        .serial_number(1)
        .subject_name(name)
        .issuer_name(name)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .public_key(key.public_key())
        .sign(key, hashes.SHA256())
    )
    der = cert_obj.public_bytes(serialization.Encoding.DER)
    cert = parse_certificate(_pem("CERTIFICATE", der))
    th = cert_thumbprint_sha256(cert)
    assert len(th) == 43 and not any(c in th for c in "+/="), f"thumbprint {th!r}"
    with pytest.raises(Exception):  # noqa: B017 - key accepted as certificate
        parse_certificate(pkcs8)


def test_sign_jwt() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for alg in (RS256, PS256):
        tok = sign_jwt(key, Header(alg=alg, kid="k1", x5t_s256="th"), standard_claims(iss="me", aud="you", exp=123, extra={"scope": "a b", "custom": True}))
        parts = tok.split(".")
        assert len(parts) == 3, tok
        hdr = json.loads(_b64url_decode(parts[0]))
        assert hdr["alg"] == alg and hdr["typ"] == "JWT" and hdr["kid"] == "k1" and hdr["x5t#S256"] == "th", f"header {hdr}"
        claims = decode_jwt_claims(tok)
        assert claims["iss"] == "me" and claims["scope"] == "a b" and claims["custom"] is True and claims["exp"] == 123, f"claims {claims}"
        assert "sub" not in claims, "empty claims must be omitted"
        sig = _b64url_decode(parts[2])
        verify(key.public_key(), alg, (parts[0] + "." + parts[1]).encode(), sig)
        other = PS256 if alg == RS256 else RS256
        with pytest.raises(Exception):  # noqa: B017 - signature verified as the other alg
            verify(key.public_key(), other, (parts[0] + "." + parts[1]).encode(), sig)
    with pytest.raises(Exception):  # noqa: B017 - nil key
        sign_jwt(None, Header(alg=RS256), "{}")
    with pytest.raises(Exception):  # noqa: B017 - unsupported alg
        sign_jwt(key, Header(alg="HS256"), "{}")
    with pytest.raises(Exception):  # noqa: B017 - bad token
        decode_jwt_claims("a.b")
    j = new_jti()
    assert len(j) == 22, j
