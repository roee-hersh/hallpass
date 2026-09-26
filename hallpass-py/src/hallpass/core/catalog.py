"""The vocabulary shared by every integration: actions and resources."""

from __future__ import annotations

import codecs
import re
import unicodedata
from dataclasses import dataclass, field

from hallpass.core.errors import go_quote

__all__ = [
    "MAX_ACTION_LENGTH",
    "MAX_RESOURCE_LENGTH",
    "Action",
    "Resource",
    "ResourceError",
    "go_bytes",
    "go_decode",
    "has_control",
    "is_control",
    "parse_query",
    "parse_resource",
    "query_unescape",
    "split_branch",
    "validate_action_name",
]


@dataclass(frozen=True)
class Action:
    # What callers send in the "action" field, for example "repo.push".
    name: str
    # One line for humans, shown by `hallpass catalog`.
    description: str = ""
    # True for actions matched by shape rather than by exact name, such as
    # "raw:<verb>:<resource>". The name then documents the shape.
    pattern: bool = False


class ResourceError(ValueError):
    pass


@dataclass(frozen=True)
class Resource:
    """A parsed ``type:id`` resource reference.

    ``repo:acme/api`` is type "repo", id "acme/api";
    ``namespace:payments?name=api`` adds query {name: [api]};
    ``global`` is type "global" with an empty id.
    """

    raw: str
    type: str = ""
    id: str = ""
    query: dict[str, list[str]] | None = field(default=None, compare=False)

    def __str__(self) -> str:
        return self.raw

    def q(self, key: str) -> str:
        """One query value or ""."""
        if not self.query:
            return ""
        vs = self.query.get(key)
        return vs[0] if vs else ""


MAX_RESOURCE_LENGTH = 1024
MAX_ACTION_LENGTH = 200

_TYPE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_ACTION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/*-]*")


def is_control(c: str) -> bool:
    """Go's unicode.IsControl: C0, DEL and C1 (category Cc)."""
    return unicodedata.category(c) == "Cc"


def has_control(s: str) -> bool:
    return any(unicodedata.category(c) == "Cc" for c in s)


_HEX = frozenset(b"0123456789abcdefABCDEF")


def _go_replace(e: UnicodeError) -> tuple[str, int]:
    # Go reads invalid UTF-8 one byte at a time: each bad byte is one U+FFFD.
    assert isinstance(e, UnicodeDecodeError)
    return "\ufffd" * (e.end - e.start), e.end


def _go_bytes_handler(e: UnicodeError) -> tuple[bytes, int]:
    # A surrogate escape (U+DC80..U+DCFF) is the raw byte it stands for;
    # any other lone surrogate is its three-byte (invalid) UTF-8 form.
    assert isinstance(e, UnicodeEncodeError)
    out = bytearray()
    for c in e.object[e.start : e.end]:
        cp = ord(c)
        out += bytes([cp - 0xDC00]) if 0xDC80 <= cp <= 0xDCFF else c.encode("utf-8", "surrogatepass")
    return bytes(out), e.end


codecs.register_error("hallpass-go-replace", _go_replace)
codecs.register_error("hallpass-go-bytes", _go_bytes_handler)


def go_bytes(s: str) -> bytes:
    """The bytes a Go string holding s would hold."""
    return s.encode("utf-8", "hallpass-go-bytes")


def go_decode(b: bytes) -> str:
    """Bytes as the runes Go's range loop sees: every invalid byte U+FFFD."""
    return b.decode("utf-8", "hallpass-go-replace")


def _quote_bytes(b: bytes) -> str:
    """strconv.Quote of raw bytes: invalid UTF-8 bytes print as \\xNN."""
    return go_quote(b.decode("utf-8", "surrogateescape"))


def _unescape(s: str, plus_is_space: bool) -> str:
    """Go's url.QueryUnescape / PathUnescape: %XX must be valid hex."""
    if "%" not in s and not (plus_is_space and "+" in s):
        return s
    out = bytearray()
    i = 0
    raw = go_bytes(s)
    n = len(raw)
    while i < n:
        b = raw[i]
        if b == 0x25:  # %
            if i + 2 >= n or raw[i + 1] not in _HEX or raw[i + 2] not in _HEX:
                raise ResourceError("invalid URL escape " + _quote_bytes(raw[i : i + 3]))
            out.append(int(raw[i + 1 : i + 3], 16))
            i += 3
            continue
        if b == 0x2B and plus_is_space:
            out.append(0x20)
        else:
            out.append(b)
        i += 1
    # Go keeps the bytes as they are, valid UTF-8 or not; so does this,
    # with invalid bytes as surrogate escapes (%q prints them as \\xNN).
    return bytes(out).decode("utf-8", "surrogateescape")


def query_unescape(s: str) -> str:
    return _unescape(s, True)


def parse_query(query: str) -> dict[str, list[str]]:
    """Go's url.ParseQuery, including its rejection of ';' separators.

    Like Go, a ';' error replaces any earlier error, while an escape error
    is kept only when it is the first."""
    out: dict[str, list[str]] = {}
    err: ResourceError | None = None
    for key in query.split("&"):
        if ";" in key:
            err = ResourceError("invalid semicolon separator in query")
            continue
        if key == "":
            continue
        k, _, v = key.partition("=")
        try:
            k = query_unescape(k)
            v = query_unescape(v)
        except ResourceError as e:
            if err is None:
                err = e
            continue
        out.setdefault(k, []).append(v)
    if err is not None:
        raise err
    return out


def parse_resource(raw: str) -> Resource:
    """Split a resource reference into type, id and query.

    It does not know what types an integration accepts; each integration
    validates the type and id on its own with strict rules.
    """
    if raw == "":
        raise ResourceError("resource is empty")
    if len(go_bytes(raw)) > MAX_RESOURCE_LENGTH:
        raise ResourceError(f"resource is longer than {MAX_RESOURCE_LENGTH} bytes")
    if has_control(raw):
        raise ResourceError("resource contains a control character")
    head, has_query, query = raw.partition("?")
    typ, _, rid = head.partition(":")
    if not _TYPE_RE.fullmatch(typ):
        raise ResourceError(f"resource type {go_quote(typ)} must match ^[a-z][a-z0-9_]{{0,63}}$")
    q: dict[str, list[str]] | None = None
    if has_query:
        try:
            q = parse_query(query)
        except ResourceError as e:
            raise ResourceError(f"resource query: {e}") from None
        for k, vs in q.items():
            if not _TYPE_RE.fullmatch(k) or len(vs) != 1:
                raise ResourceError(f"resource query key {go_quote(k)} must be a single lowercase key")
            # Percent-decoding can produce characters the raw check never
            # saw, including C1 controls such as NEL (%C2%85).
            if has_control(vs[0]):
                raise ResourceError(f"resource query value for {go_quote(k)} contains a control character")
        # The stored values read invalid UTF-8 as U+FFFD, one per byte, as
        # Go does wherever it iterates, prints or JSON-encodes a string, so
        # no surrogate escape reaches an integration.
        q = {k: [_go_text(v) for v in vs] for k, vs in q.items()}
    return Resource(raw=raw, type=typ, id=rid, query=q)


def _go_text(s: str) -> str:
    return go_decode(go_bytes(s))


def split_branch(rid: str) -> tuple[str, str]:
    """Separate an "@branch" suffix: "acme/webapp@main" -> ("acme/webapp", "main")."""
    i = rid.rfind("@")
    if i < 0:
        return rid, ""
    return rid[:i], rid[i + 1 :]


def validate_action_name(name: str) -> None:
    """Check the shape of a caller-supplied action name; raise ValueError."""
    if name == "":
        raise ValueError("action is empty")
    if len(go_bytes(name)) > MAX_ACTION_LENGTH:
        raise ValueError(f"action is longer than {MAX_ACTION_LENGTH} bytes")
    if not _ACTION_RE.fullmatch(name):
        raise ValueError(f"action {go_quote(name)} contains characters outside ^[A-Za-z0-9][A-Za-z0-9_.:/*-]*$")
