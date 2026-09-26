"""AWS Signature Version 4 (header form)."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

from hallpass.core.catalog import ResourceError
from hallpass.core.errors import go_lower, go_trim_space
from hallpass.net.httpx import PreparedRequest

__all__ = ["EMPTY_HASH", "AWSCredentials", "SigV4Signer"]

_ALGORITHM = "AWS4-HMAC-SHA256"
EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@dataclass(frozen=True)
class AWSCredentials:
    access_key_id: str = ""
    secret_access_key: str = ""
    session_token: str = ""
    # Epoch seconds; None for static keys.
    expiry: float | None = None

    def is_zero(self) -> bool:
        return self.access_key_id == ""

    def __repr__(self) -> str:
        return f"AWSCredentials(access_key_id={self.access_key_id!r}, secret_access_key=[REDACTED], session_token=[REDACTED])"


@dataclass
class SigV4Signer:
    """Signs requests with SigV4: the URI path is URI-encoded once (S3
    excluded), query parameters are encoded and sorted by key then value,
    headers lower-cased, trimmed and sorted, the payload hash is SHA-256 of
    the body."""

    region: str
    service: str
    now: Callable[[], float] | None = None

    def sign(self, req: PreparedRequest, body: bytes | None, creds: AWSCredentials) -> None:
        """Add X-Amz-Date, X-Amz-Security-Token (when present) and
        Authorization. The Host header is always signed."""
        t = self.now() if self.now is not None else time.time()
        self.sign_at(req, body, creds, datetime.datetime.fromtimestamp(t, datetime.timezone.utc))

    def sign_at(self, req: PreparedRequest, body: bytes | None, creds: AWSCredentials, t: datetime.datetime) -> None:
        """sign with an explicit time. Tests use it. A naive datetime is UTC."""
        if t.tzinfo is None:
            t = t.replace(tzinfo=datetime.timezone.utc)
        u = t.astimezone(datetime.timezone.utc)
        amz_date = f"{u.year:04d}{u.month:02d}{u.day:02d}T{u.hour:02d}{u.minute:02d}{u.second:02d}Z"
        if req.headers.get("X-Amz-Date") == "":
            req.headers.set("X-Amz-Date", amz_date)
        else:
            amz_date = req.headers.get("X-Amz-Date")
        if creds.session_token:
            req.headers.set("X-Amz-Security-Token", creds.session_token)
        canon, signed = _canonical_request(req, _payload_hash(body))
        date = amz_date[:8]
        scope = f"{date}/{self.region}/{self.service}/aws4_request"
        sts = _string_to_sign(amz_date, scope, canon)
        sig = _signature(creds.secret_access_key, date, self.region, self.service, sts)
        req.headers.set("Authorization", f"{_ALGORITHM} Credential={creds.access_key_id}/{scope}, SignedHeaders={signed}, Signature={sig}")

    def canonical_request(self, req: PreparedRequest, body: bytes | None) -> tuple[str, str]:
        """For the test-suite comparison."""
        return _canonical_request(req, _payload_hash(body))

    def string_to_sign(self, amz_date: str, canon: str) -> str:
        """For the test-suite comparison."""
        scope = f"{amz_date[:8]}/{self.region}/{self.service}/aws4_request"
        return _string_to_sign(amz_date, scope, canon)


def _payload_hash(body: bytes | None) -> str:
    if not body:
        return EMPTY_HASH
    return hashlib.sha256(body).hexdigest()


_SKIP = frozenset({"authorization", "content-length", "user-agent", "expect"})


def _canonical_request(req: PreparedRequest, payload_hash: str) -> tuple[str, str]:
    # Lower-case names, trimmed and space-collapsed values, sorted. Host is
    # always included. Values of repeated headers are joined by ",".
    names: dict[str, list[str]] = {}
    for k, vs in req.headers.items():
        lk = go_lower(k)
        if lk in _SKIP:
            continue
        for v in vs:
            names.setdefault(lk, []).append(_collapse_spaces(go_trim_space(v)))
    u = urllib.parse.urlsplit(req.url)
    # Go signs req.Host, falling back to the URL's host; a PreparedRequest
    # carries an explicit host as its Host header.
    host = req.headers.get("Host") or u.netloc.rpartition("@")[2]
    names["host"] = [host]
    keys = sorted(names)
    ch = "".join(f"{k}:{','.join(names[k])}\n" for k in keys)
    signed = ";".join(keys)
    canon = f"{req.method}\n{_canonical_uri(_escaped_path(u.path))}\n{_canonical_query(u.query)}\n{ch}\n{signed}\n{payload_hash}"
    return canon, signed


def _collapse_spaces(s: str) -> str:
    out = []
    space = False
    for c in s:
        if c in " \t\n\r":
            if not space:
                out.append(" ")
            space = True
            continue
        space = False
        out.append(c)
    return "".join(out)


# The bytes url.shouldEscape(c, encodePath) leaves alone, plus those
# validEncoded accepts as they are (sub-delims, brackets and "%").
_PATH_KEEP = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~$&+,/:;=@")
_VALID_ENCODED = _PATH_KEEP | frozenset(b"!$&'()*+,;=:@[]%")


def _escaped_path(raw: str) -> str:
    """Go's URL.EscapedPath for a URL parsed from a string with this raw
    path: the raw path when it is a valid encoding, else the decoded path
    re-escaped with Go's path rules."""
    b = raw.encode("utf-8")
    if all(c in _VALID_ENCODED for c in b):
        return raw
    try:
        dec = _path_unescape(raw)
    except ResourceError:
        dec = b
    if dec == b"*":
        return "*"
    return "".join(chr(c) if c in _PATH_KEEP else f"%{c:02X}" for c in dec)


def _canonical_uri(p: str) -> str:
    """Dot segments removed, duplicate slashes collapsed, each segment
    decoded once and encoded with the AWS rules."""
    if p == "":
        p = "/"
    p = _remove_dot_segments(p)
    segs = []
    for s in p.split("/"):
        try:
            dec = _path_unescape(s)
        except ResourceError:
            dec = s.encode("utf-8")
        segs.append(_aws_escape(dec))
    out = "/".join(segs)
    if out == "":
        out = "/"
    if not out.startswith("/"):
        out = "/" + out
    return out


def _path_unescape(s: str) -> bytes:
    """Go's url.PathUnescape as bytes: %XX must be valid, "+" stays."""
    raw = s.encode("utf-8")
    out = bytearray()
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == 0x25:
            h = raw[i + 1 : i + 3]
            if len(h) < 2 or not all(c in b"0123456789abcdefABCDEF" for c in h):
                raise ResourceError("invalid URL escape")
            out.append(int(h, 16))
            i += 3
            continue
        out.append(b)
        i += 1
    return bytes(out)


def _remove_dot_segments(p: str) -> str:
    out: list[str] = []
    for seg in p.split("/"):
        if seg in (".", ""):
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    res = "/" + "/".join(out)
    if p.endswith("/") and res != "/":
        res += "/"
    return res


_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")


def _aws_escape(b: bytes | str) -> str:
    """Percent-encode everything except unreserved characters."""
    if isinstance(b, str):
        b = b.encode("utf-8")
    return "".join(chr(c) if c in _UNRESERVED else f"%{c:02X}" for c in b)


def _query_unescape_bytes(s: str) -> bytes:
    raw = s.encode("utf-8")
    out = bytearray()
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == 0x25:
            h = raw[i + 1 : i + 3]
            if len(h) < 2 or not all(c in b"0123456789abcdefABCDEF" for c in h):
                raise ResourceError("invalid URL escape")
            out.append(int(h, 16))
            i += 3
            continue
        out.append(0x20 if b == 0x2B else b)
        i += 1
    return bytes(out)


def _canonical_query(raw: str) -> str:
    """Each key and value decoded, encoded with the AWS rules, sorted by key
    then value."""
    if raw == "":
        return ""
    pairs = []
    for part in raw.split("&"):
        if part == "":
            continue
        k, _, v = part.partition("=")
        try:
            dk = _query_unescape_bytes(k)
        except ResourceError:
            dk = k.encode("utf-8")
        try:
            dv = _query_unescape_bytes(v)
        except ResourceError:
            dv = v.encode("utf-8")
        pairs.append((_aws_escape(dk), _aws_escape(dv)))
    pairs.sort()
    return "&".join(f"{k}={v}" for k, v in pairs)


def _string_to_sign(amz_date: str, scope: str, canon: str) -> str:
    return f"{_ALGORITHM}\n{amz_date}\n{scope}\n{hashlib.sha256(canon.encode('utf-8')).hexdigest()}"


def _hmac(key: bytes, data: str) -> bytes:
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()


def _signature(secret: str, date: str, region: str, service: str, sts: str) -> str:
    k_date = _hmac(("AWS4" + secret).encode("utf-8"), date)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    k_signing = _hmac(k_service, "aws4_request")
    return hmac.new(k_signing, sts.encode("utf-8"), hashlib.sha256).hexdigest()
