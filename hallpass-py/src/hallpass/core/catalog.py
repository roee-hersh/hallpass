"""The vocabulary shared by every integration: actions and resources."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

__all__ = [
    "MAX_ACTION_LENGTH",
    "MAX_RESOURCE_LENGTH",
    "Action",
    "Resource",
    "ResourceError",
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


def _unhex(c: str) -> int:
    return int(c, 16)


_HEX = frozenset("0123456789abcdefABCDEF")


def _unescape(s: str, plus_is_space: bool) -> str:
    """Go's url.QueryUnescape / PathUnescape: %XX must be valid hex."""
    if "%" not in s and not (plus_is_space and "+" in s):
        return s
    out = bytearray()
    i = 0
    raw = s.encode("utf-8", "surrogateescape")
    n = len(raw)
    while i < n:
        b = raw[i]
        if b == 0x25:  # %
            if i + 2 >= n:
                seg = raw[i : i + 3].decode("utf-8", "replace")
                raise ResourceError(f'invalid URL escape "{seg}"')
            h1, h2 = chr(raw[i + 1]), chr(raw[i + 2])
            if h1 not in _HEX or h2 not in _HEX:
                raise ResourceError(f'invalid URL escape "%{h1}{h2}"')
            out.append(_unhex(h1) * 16 + _unhex(h2))
            i += 3
            continue
        if b == 0x2B and plus_is_space:
            out.append(0x20)
        else:
            out.append(b)
        i += 1
    # Go keeps the bytes as they are; invalid UTF-8 becomes U+FFFD when
    # iterated as runes, which is what a str decode with "replace" gives.
    return out.decode("utf-8", "replace")


def query_unescape(s: str) -> str:
    return _unescape(s, True)


def parse_query(query: str) -> dict[str, list[str]]:
    """Go's url.ParseQuery, including its rejection of ';' separators."""
    out: dict[str, list[str]] = {}
    first_err: ResourceError | None = None
    for key in query.split("&"):
        if key == "":
            continue
        if ";" in key:
            if first_err is None:
                first_err = ResourceError("invalid semicolon separator in query")
            continue
        k, _, v = key.partition("=")
        try:
            k = query_unescape(k)
            v = query_unescape(v)
        except ResourceError as e:
            if first_err is None:
                first_err = e
            continue
        out.setdefault(k, []).append(v)
    if first_err is not None:
        raise first_err
    return out


def parse_resource(raw: str) -> Resource:
    """Split a resource reference into type, id and query.

    It does not know what types an integration accepts; each integration
    validates the type and id on its own with strict rules.
    """
    if raw == "":
        raise ResourceError("resource is empty")
    if len(raw.encode("utf-8", "surrogatepass")) > MAX_RESOURCE_LENGTH:
        raise ResourceError(f"resource is longer than {MAX_RESOURCE_LENGTH} bytes")
    if has_control(raw):
        raise ResourceError("resource contains a control character")
    head, has_query, query = raw.partition("?")
    typ, _, rid = head.partition(":")
    if not _TYPE_RE.fullmatch(typ):
        raise ResourceError(f'resource type "{typ}" must match ^[a-z][a-z0-9_]{{0,63}}$')
    q: dict[str, list[str]] | None = None
    if has_query:
        try:
            q = parse_query(query)
        except ResourceError as e:
            raise ResourceError(f"resource query: {e}") from None
        for k, vs in q.items():
            if not _TYPE_RE.fullmatch(k) or len(vs) != 1:
                raise ResourceError(f'resource query key "{k}" must be a single lowercase key')
            # Percent-decoding can produce characters the raw check never
            # saw, including C1 controls such as NEL (%C2%85).
            if has_control(vs[0]):
                raise ResourceError(f'resource query value for "{k}" contains a control character')
    return Resource(raw=raw, type=typ, id=rid, query=q)


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
    if len(name.encode("utf-8", "surrogatepass")) > MAX_ACTION_LENGTH:
        raise ValueError(f"action is longer than {MAX_ACTION_LENGTH} bytes")
    if not _ACTION_RE.fullmatch(name):
        raise ValueError(f'action "{name}" contains characters outside ^[A-Za-z0-9][A-Za-z0-9_.:/*-]*$')
