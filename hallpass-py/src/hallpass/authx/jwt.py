"""JWT signing (RS256, PS256) and PEM key handling.

Signing needs the ``cryptography`` package (``pip install "hallpass[crypto]"``);
it is imported only when a key is parsed, so integrations that never sign
do not need it.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Any

from hallpass.authx.util import StructDict, go_json_loads, go_json_marshal, pem_decode
from hallpass.core.errors import go_quote

__all__ = [
    "PS256",
    "RS256",
    "CryptoMissing",
    "Header",
    "cert_thumbprint_sha256",
    "decode_jwt_claims",
    "new_jti",
    "parse_certificate",
    "parse_rsa_private_key",
    "sign",
    "sign_jwt",
    "standard_claims",
    "verify",
]

RS256 = "RS256"  # RSASSA-PKCS1-v1_5 with SHA-256 (GitHub Apps, Google, Salesforce)
PS256 = "PS256"  # RSASSA-PSS with SHA-256 (Microsoft Entra certificate credentials)


class CryptoMissing(RuntimeError):
    def __init__(self) -> None:
        super().__init__('signing with a private key needs the cryptography package: pip install "hallpass[crypto]"')


def _crypto() -> Any:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        raise CryptoMissing() from None
    return hashes, serialization, padding, rsa, x509


def _der_elements(der: bytes, n: int) -> list[int]:
    """The tags of the first n elements inside the outer DER SEQUENCE, or
    fewer when the encoding ends or is malformed."""
    tags: list[int] = []
    try:
        if der[0] != 0x30:
            return tags
        i = _der_header(der, 0)[0]
        while len(tags) < n and i < len(der):
            tags.append(der[i])
            start, length = _der_header(der, i)
            i = start + length
    except IndexError:
        pass
    return tags


def _der_header(der: bytes, i: int) -> tuple[int, int]:
    """(content start, content length) of the TLV at i."""
    ln = der[i + 1]
    if ln < 0x80:
        return i + 2, ln
    k = ln & 0x7F
    return i + 2 + k, int.from_bytes(der[i + 2 : i + 2 + k], "big")


def _der_kind(der: bytes) -> str:
    """pkcs1 (RSAPrivateKey), pkcs8 (PrivateKeyInfo), sec1 (ECPrivateKey)
    or "" by the shape of the structure."""
    tags = _der_elements(der, 2)
    if len(tags) < 2 or tags[0] != 0x02:
        return ""
    return {0x02: "pkcs1", 0x30: "pkcs8", 0x04: "sec1"}.get(tags[1], "")


_OTHER_FORMAT = {"pkcs1": "ParsePKCS1PrivateKey", "pkcs8": "ParsePKCS8PrivateKey", "sec1": "ParseECPrivateKey"}


def _load_der(der: bytes, want: str) -> Any:
    """x509.ParsePKCS1PrivateKey (want pkcs1) or ParsePKCS8PrivateKey (want
    pkcs8): the DER must be that structure."""
    _, serialization, _, _, _ = _crypto()
    kind = _der_kind(der)
    if kind != want:
        if kind in _OTHER_FORMAT:
            raise ValueError(f"x509: failed to parse private key (use {_OTHER_FORMAT[kind]} instead for this key format)")
        raise ValueError("x509: failed to parse private key: malformed DER")
    try:
        return serialization.load_der_private_key(der, password=None)
    except Exception as e:  # noqa: BLE001 - ValueError, TypeError or UnsupportedAlgorithm
        raise ValueError(f"x509: failed to parse private key: {e}") from None


def _go_key_type(k: Any) -> str | None:
    """The Go type ParsePKCS8PrivateKey returns for a non-RSA key, or None
    for an algorithm it does not know."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519

    if isinstance(k, ec.EllipticCurvePrivateKey):
        return "*ecdsa.PrivateKey"
    if isinstance(k, ed25519.Ed25519PrivateKey):
        return "ed25519.PrivateKey"
    if isinstance(k, x25519.X25519PrivateKey):
        return "*ecdh.PrivateKey"
    return None


def parse_rsa_private_key(pem: bytes) -> Any:
    """A PEM private key: PKCS#1 ("RSA PRIVATE KEY") or PKCS#8 ("PRIVATE
    KEY"). Encrypted keys are not supported. The first block of one of
    these types decides; other blocks are skipped."""
    _, _, _, rsa, _ = _crypto()
    while True:
        block, rest = pem_decode(pem)
        if block is None:
            raise ValueError("no PEM private key found")
        if block.type == "RSA PRIVATE KEY":
            k = _load_der(block.bytes, "pkcs1")
            if not isinstance(k, rsa.RSAPrivateKey):
                raise ValueError("x509: failed to parse private key: not an RSA key")
            return k
        if block.type == "PRIVATE KEY":
            k = _load_der(block.bytes, "pkcs8")
            if not isinstance(k, rsa.RSAPrivateKey):
                t = _go_key_type(k)
                if t is None:
                    raise ValueError("x509: PKCS#8 wrapping contained private key with unknown algorithm")
                raise ValueError(f"PKCS#8 key is {t}, not RSA")
            return k
        if block.type == "ENCRYPTED PRIVATE KEY":
            raise ValueError("encrypted private keys are not supported; store the key unencrypted in a file secret")
        pem = rest


def parse_certificate(pem: bytes) -> Any:
    """The first PEM certificate."""
    _, _, _, _, x509 = _crypto()
    while True:
        block, rest = pem_decode(pem)
        if block is None:
            raise ValueError("no PEM certificate found")
        if block.type == "CERTIFICATE":
            try:
                return x509.load_der_x509_certificate(block.bytes)
            except Exception as e:  # noqa: BLE001
                raise ValueError(f"x509: malformed certificate: {e}") from None
        pem = rest


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """base64.RawURLEncoding.DecodeString: no padding, the URL alphabet
    only, CR and LF skipped."""
    s = s.replace("\r", "").replace("\n", "")
    m = re.search(r"[^A-Za-z0-9_-]", s)
    if m:
        raise ValueError(f"illegal base64 data at input byte {m.start()}")
    if len(s) % 4 == 1:
        raise ValueError(f"illegal base64 data at input byte {len(s) - 1}")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def cert_thumbprint_sha256(cert: Any) -> str:
    """base64url SHA-256 of the DER certificate: the JOSE "x5t#S256" value."""
    _, serialization, _, _, _ = _crypto()
    return _b64url(hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest())


@dataclass
class Header:
    """The JOSE header. Extra keys go in extra."""

    alg: str
    typ: str = ""  # "JWT" unless set
    kid: str = ""
    x5t_s256: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


def sign_jwt(key: Any, h: Header, claims: Any) -> str:
    """Build and sign a compact JWS: header.payload.signature. claims is
    marshalled as JSON the way json.Marshal would (a plain dict is a Go map,
    keys sorted; a StructDict such as standard_claims returns keeps its
    order); bytes or str are the payload as they are."""
    if key is None:
        raise ValueError("no signing key")
    hdr: dict[str, Any] = {"alg": h.alg, "typ": h.typ or "JWT"}
    if h.kid:
        hdr["kid"] = h.kid
    if h.x5t_s256:
        hdr["x5t#S256"] = h.x5t_s256
    hdr.update(h.extra)
    if isinstance(claims, bytes):
        pb = claims
    elif isinstance(claims, str):
        pb = claims.encode("utf-8")
    else:
        pb = go_json_marshal(claims)
    signing_input = _b64url(go_json_marshal(hdr)) + "." + _b64url(pb)
    return signing_input + "." + _b64url(sign(key, h.alg, signing_input.encode("ascii")))


def sign(key: Any, alg: str, data: bytes) -> bytes:
    hashes, _, padding, _, _ = _crypto()
    if alg == RS256:
        return bytes(key.sign(data, padding.PKCS1v15(), hashes.SHA256()))
    if alg == PS256:
        return bytes(key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()))
    raise ValueError(f"unsupported algorithm {go_quote(alg)}")


def verify(pub: Any, alg: str, data: bytes, sig: bytes) -> None:
    """Check a signature made by sign; raise on failure."""
    from cryptography.exceptions import InvalidSignature

    hashes, _, padding, _, _ = _crypto()
    if alg == RS256:
        pad: Any = padding.PKCS1v15()
    elif alg == PS256:
        pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    else:
        raise ValueError(f"unsupported algorithm {go_quote(alg)}")
    try:
        pub.verify(sig, data, pad, hashes.SHA256())
    except InvalidSignature:
        raise ValueError("crypto/rsa: verification error") from None


def standard_claims(
    iss: str = "",
    sub: str = "",
    aud: str = "",
    exp: int = 0,
    nbf: int = 0,
    iat: int = 0,
    jti: str = "",
    scope: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The registered claims most exchanges need (Go's StandardClaims),
    empty ones omitted. Without extra it marshals in field order, as the
    struct does; extra is merged in and the result is a plain dict that
    marshals with sorted keys, as the merged map does."""
    out: dict[str, Any] = StructDict()
    for k, v in (("iss", iss), ("sub", sub), ("aud", aud), ("exp", exp), ("nbf", nbf), ("iat", iat), ("jti", jti), ("scope", scope)):
        if v:
            out[k] = v
    if extra:
        merged = dict(out)
        merged.update(extra)
        return merged
    return out


def decode_jwt_claims(token: str) -> Any:
    """The payload of a compact JWS, unverified. For reading the expiry out
    of tokens hallpass itself received."""
    parts = token.split(".", 2)
    if len(parts) != 3:
        raise ValueError("not a compact JWS")
    return go_json_loads(_b64url_decode(parts[1]))


def new_jti() -> str:
    """A random 128-bit identifier as base64url."""
    return _b64url(os.urandom(16))
