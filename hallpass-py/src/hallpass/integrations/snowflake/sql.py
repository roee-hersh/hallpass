"""Identifiers and literals for SHOW statements.

Snowflake resolves unquoted identifiers to upper case and keeps quoted ones
as written. hallpass stores every name in resolved form (the exact
characters Snowflake compares) and renders it quoted, so that a name built
from caller input can never change the shape of a statement.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from hallpass.core.errors import go_quote, go_trim_space

__all__ = ["like_literal", "parse_identifier", "parse_name", "quote", "quote_name", "same_name", "split_name", "string_literal"]

# (Used with fullmatch: Go's $ does not match before a trailing newline.)
_UNQUOTED_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$]{0,254}")


def _nbytes(s: str) -> int:
    return len(s.encode("utf-8", "surrogatepass"))


def parse_identifier(s: str) -> str:
    """One identifier part, quoted or not, in its resolved form; raise
    ValueError."""
    if _UNQUOTED_RE.fullmatch(s):
        return s.upper()  # ASCII only, by the pattern
    if _nbytes(s) >= 3 and s.startswith('"') and s.endswith('"'):
        inner = s[1:-1].replace('""', "\x00")
        if '"' in inner:
            raise ValueError("a quoted identifier has an unescaped quote")
        inner = inner.replace("\x00", '"')
        if inner == "" or _nbytes(inner) > 255:
            raise ValueError("a quoted identifier is empty or longer than 255 characters")
        for c in inner:
            if c < "\x20" or c == "\x7f":
                raise ValueError("a quoted identifier carries a control character")
        return inner
    raise ValueError(f"{go_quote(s)} is not an identifier (letters, digits, _ and $, or double-quoted)")


def split_name(s: str) -> list[str]:
    """Split a dotted name into its parts, honouring quotes."""
    parts: list[str] = []
    cur: list[str] = []
    in_quote = False
    for c in s:
        if c == '"':
            in_quote = not in_quote
            cur.append(c)
        elif c == "." and not in_quote:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    if in_quote:
        raise ValueError("unterminated quoted identifier")
    parts.append("".join(cur))
    return parts


def parse_name(s: str, n: int) -> tuple[str, ...]:
    """A name of exactly n dotted parts, in resolved parts."""
    raw = split_name(go_trim_space(s))
    if len(raw) != n:
        raise ValueError(f"expected {n} dotted part(s), found {len(raw)}")
    return tuple(parse_identifier(p) for p in raw)


def quote(id: str) -> str:
    """A resolved identifier rendered for a statement."""
    return '"' + id.replace('"', '""') + '"'


def quote_name(parts: Sequence[str]) -> str:
    """Resolved parts as a dotted quoted name."""
    return ".".join(quote(p) for p in parts)


def same_name(a: Sequence[str] | None, b: Sequence[str] | None) -> bool:
    """Whether two resolved names are equal."""
    return tuple(a or ()) == tuple(b or ())


def string_literal(s: str) -> str:
    """s as a single-quoted SQL string literal."""
    s = s.replace("\\", "\\\\")
    s = s.replace("'", "''")
    return "'" + s + "'"


def like_literal(s: str) -> str:
    """s for SHOW ... LIKE: the wildcards % and _ are escaped so the pattern
    is the literal name."""
    s = s.replace("\\", "\\\\")
    s = s.replace("%", "\\%")
    s = s.replace("_", "\\_")
    return string_literal(s)
