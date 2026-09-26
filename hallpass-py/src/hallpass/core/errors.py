"""Error chains: Go's errors.Is / errors.As over Python exceptions.

A cause is attached with ``raise X from cause`` (``__cause__``); a
:class:`JoinedError` carries several (Go's errors.Join). ``__context__``,
the exception that happened to be in flight, is deliberately not followed:
it is an accident of where the error was raised, not a wrapped cause.
"""

from __future__ import annotations

import errno as _errno
import os
import unicodedata
from collections.abc import Iterator
from typing import TypeVar

__all__ = [
    "JoinedError",
    "as_error",
    "chain",
    "go_lower",
    "go_quote",
    "go_trim_space",
    "is_error",
    "os_error_text",
    "path_error_text",
    "wrap",
]

E = TypeVar("E", bound=BaseException)


class JoinedError(Exception):
    """Several errors reported as one; each is part of the chain."""

    def __init__(self, *errors: BaseException) -> None:
        self.errors = tuple(e for e in errors if e is not None)
        super().__init__("\n".join(str(e) for e in self.errors))


def chain(err: BaseException | None) -> Iterator[BaseException]:
    """Walk err and its causes depth-first, each exception once."""
    seen: set[int] = set()
    stack: list[BaseException] = [err] if err is not None else []
    while stack:
        e = stack.pop()
        if id(e) in seen:
            continue
        seen.add(id(e))
        yield e
        if isinstance(e, JoinedError):
            stack.extend(reversed(e.errors))
        if e.__cause__ is not None:
            stack.append(e.__cause__)


def as_error(err: BaseException | None, cls: type[E]) -> E | None:
    """The first exception in err's chain that is a cls, or None."""
    for e in chain(err):
        if isinstance(e, cls):
            return e
    return None


def is_error(err: BaseException | None, cls: type[BaseException]) -> bool:
    return as_error(err, cls) is not None


def wrap(err: E, cause: BaseException | None) -> E:
    """Attach cause to err and return err (``raise wrap(X(...), e)``)."""
    err.__cause__ = cause
    return err


# Go string semantics the error texts and validators depend on. They live
# here, in a module that imports nothing of hallpass, so every package can
# use them without an import cycle.

_HEX = "0123456789abcdef"
_ESCAPES = {"\a": "\\a", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\v": "\\v"}


def _go_is_print(c: str) -> bool:
    """strconv.IsPrint: letters, marks, numbers, punctuation, symbols and
    the ASCII space; no other space and no control or format character."""
    if c == " ":
        return True
    return unicodedata.category(c)[0] in "LMNPS"


def go_quote(s: str) -> str:
    """Go's strconv.Quote, the %q verb: a double-quoted literal with Go
    escapes, printable runes (including non-ASCII) kept as they are."""
    out = ['"']
    for c in s:
        cp = ord(c)
        if c == '"' or c == "\\":
            out.append("\\" + c)
        elif 0xD800 <= cp <= 0xDFFF:
            # Not a rune: Go would hold invalid UTF-8 bytes here, which it
            # prints as \x escapes. A surrogateescape'd byte is that byte.
            bs = bytes([cp - 0xDC00]) if 0xDC80 <= cp <= 0xDCFF else c.encode("utf-8", "surrogatepass")
            out.extend("\\x" + _HEX[b >> 4] + _HEX[b & 0xF] for b in bs)
        elif _go_is_print(c):
            out.append(c)
        elif c in _ESCAPES:
            out.append(_ESCAPES[c])
        elif cp < 0x20 or cp == 0x7F:
            out.append("\\x" + _HEX[cp >> 4] + _HEX[cp & 0xF])
        elif cp < 0x10000:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(f"\\U{cp:08x}")
    out.append('"')
    return "".join(out)


# unicode.IsSpace: the White_Space property. Python's str.isspace also
# counts U+001C..U+001F, which Go does not.
_GO_SPACE = "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"


def go_trim_space(s: str) -> str:
    """Go's strings.TrimSpace."""
    return s.strip(_GO_SPACE)


def go_lower(s: str) -> str:
    """Go's strings.ToLower: the simple, one-rune-for-one lowercase mapping.
    str.lower() uses the full mapping (U+0130 becomes two runes) and a
    final-sigma rule; Go does neither."""
    if s.isascii():
        return s.lower()
    return "".join("i" if c == "\u0130" else c.lower() for c in s)


def os_error_text(e: BaseException) -> str:
    """The text Go gives the errno behind e ("no such file or directory")."""
    if isinstance(e, ValueError):  # an embedded NUL byte in a path
        return os.strerror(_errno.EINVAL)[:1].lower() + os.strerror(_errno.EINVAL)[1:]
    code = getattr(e, "errno", None)
    if isinstance(code, int):
        text = os.strerror(code)
        return text[:1].lower() + text[1:]
    return str(e)


def path_error_text(op: str, path: str, e: BaseException) -> str:
    """Go's *fs.PathError text: "open /x: no such file or directory"."""
    return f"{op} {path}: {os_error_text(e)}"
