"""Go regexp (RE2) syntax on Python's re.

Argo CD's regex match mode compiles policy patterns with Go's regexp, so a
pattern must mean the same here: what RE2 rejects is rejected (and then
never matches), and where the two dialects read the same text differently
the RE2 reading is translated into Python syntax:

- ``$`` is the end of the text unless the m flag is used (Python's also
  matches before a final newline);
- ``\\d \\w \\s \\b`` and POSIX classes are ASCII, as in RE2 (Python's are
  Unicode), without making case folding ASCII-only;
- ``\\z``, ``\\Q...\\E``, ``\\x{...}``, octal escapes and ``(?<name>...)``
  become their Python spellings;
- a flag group such as ``(?i)`` in the middle of a pattern applies to the
  rest of its group (Python only allows global flags at the start);
- ``{`` that does not start a valid repetition is a literal, and repeat
  counts above 1000 are rejected;
- lookaround, backreferences, conditionals, atomic groups and possessive
  quantifiers, which RE2 does not have, are rejected.

Unicode general categories (``\\pL``, ``\\p{Lu}``, ``\\PN``, ``\\p{^N}``,
``\\p{Any}``) are expanded into ranges from Python's Unicode database, whose
version may trail Go's by a release.

Not supported (rejected, so such a pattern never matches): Unicode scripts
such as ``\\p{Greek}``, ``\\C``, the U (ungreedy) flag, negated POSIX classes
inside a larger bracket expression.
"""

from __future__ import annotations

import re
import sys
import threading
import unicodedata

__all__ = ["RE2Error", "compile_re2", "translate"]


class RE2Error(ValueError):
    pass


_WORD = "0-9A-Za-z_"
_DIGIT = "0-9"
_SPACE = "\\t\\n\\f\\r "
# The complements, for use inside a bracket expression.
_NOT_DIGIT = "\\x00-/:-\\U0010ffff"
_NOT_WORD = "\\x00-/:-@\\[-\\^`{-\\U0010ffff"
_NOT_SPACE = "\\x00-\\x08\\x0b\\x0e-\\x1f!-\\U0010ffff"

_CLASS_ESC = {"d": _DIGIT, "w": _WORD, "s": _SPACE, "D": _NOT_DIGIT, "W": _NOT_WORD, "S": _NOT_SPACE}

_POSIX = {
    "alnum": "0-9A-Za-z",
    "alpha": "A-Za-z",
    "ascii": "\\x00-\\x7f",
    "blank": "\\t ",
    "cntrl": "\\x00-\\x1f\\x7f",
    "digit": "0-9",
    "graph": "!-~",
    "lower": "a-z",
    "print": " -~",
    "punct": "!-/:-@\\[-`{-~",
    "space": "\\t\\n\\v\\f\\r ",
    "upper": "A-Z",
    "word": "0-9A-Za-z_",
    "xdigit": "0-9A-Fa-f",
}

_SIMPLE_ESC = {"a": "\\a", "f": "\\f", "t": "\\t", "n": "\\n", "r": "\\r", "v": "\\v", "A": "\\A", "z": "\\Z"}

_B = f"(?:(?<![{_WORD}])(?=[{_WORD}])|(?<=[{_WORD}])(?![{_WORD}]))"
_NB = f"(?:(?<![{_WORD}])(?![{_WORD}])|(?<=[{_WORD}])(?=[{_WORD}]))"

_REPEAT = re.compile(r"\{([0-9]+)(,([0-9]*))?\}")
_FLAGS = re.compile(r"\(\?([imsU]*(?:-[imsU]*)?)([:)])")
_NAME = re.compile(r"\(\?P?<([A-Za-z0-9_]+)>")

_MAX_REPEAT = 1000


# Go's unicode.Categories: the one-letter classes cover their two-letter
# ones, and C (Other) does not include unassigned code points.
_CATEGORIES = frozenset(
    [
        "C",
        "Cc",
        "Cf",
        "Co",
        "Cs",
        "L",
        "Ll",
        "Lm",
        "Lo",
        "Lt",
        "Lu",
        "M",
        "Mc",
        "Me",
        "Mn",
        "N",
        "Nd",
        "Nl",
        "No",
        "P",
        "Pc",
        "Pd",
        "Pe",
        "Pf",
        "Pi",
        "Po",
        "Ps",
        "S",
        "Sc",
        "Sk",
        "Sm",
        "So",
        "Z",
        "Zl",
        "Zp",
        "Zs",
    ]
)
_cat_lock = threading.Lock()
_cat_ranges: dict[str, list[tuple[int, int]]] = {}


def _ranges_of(name: str) -> list[tuple[int, int]]:
    """The code point ranges of a general category (or "Any")."""
    with _cat_lock:
        r = _cat_ranges.get(name)
        if r is not None:
            return r
        if name == "Any":
            r = [(0, sys.maxunicode)]
        else:
            r = []
            start = -1
            for cp in range(sys.maxunicode + 1):
                cat = unicodedata.category(chr(cp))
                hit = cat != "Cn" and (cat == name or (len(name) == 1 and cat[0] == name))
                if hit and start < 0:
                    start = cp
                elif not hit and start >= 0:
                    r.append((start, cp - 1))
                    start = -1
            if start >= 0:
                r.append((start, sys.maxunicode))
        _cat_ranges[name] = r
        return r


def _class_body(ranges: list[tuple[int, int]], negate: bool) -> str:
    if negate:
        comp = []
        nxt = 0
        for lo, hi in ranges:
            if lo > nxt:
                comp.append((nxt, lo - 1))
            nxt = hi + 1
        if nxt <= sys.maxunicode:
            comp.append((nxt, sys.maxunicode))
        ranges = comp
    return "".join(f"\\U{lo:08x}" if lo == hi else f"\\U{lo:08x}-\\U{hi:08x}" for lo, hi in ranges)


def _unicode_class(p: str, i: int) -> tuple[str, int]:
    """The class body for the \\p or \\P escape at p[i]; (body, next index)."""
    negate = p[i + 1] == "P"
    j = i + 2
    if j >= len(p):
        raise RE2Error("invalid character class range")
    if p[j] == "{":
        end = p.find("}", j)
        if end < 0:
            raise RE2Error("invalid character class range")
        name = p[j + 1 : end]
        j = end + 1
        if name.startswith("^"):
            negate = not negate
            name = name[1:]
    else:
        name = p[j]
        j += 1
    if name != "Any" and name not in _CATEGORIES:
        raise RE2Error("invalid or unsupported character class range")
    body = _class_body(_ranges_of(name), negate)
    if body == "":
        raise RE2Error("empty character class")
    return body, j


def _is_punct(c: str) -> bool:
    return c < "\x80" and not c.isalnum()


def _char(cp: int) -> str:
    if cp > 0x10FFFF:
        raise RE2Error("invalid escape sequence")
    return f"\\U{cp:08x}"


def _escape(p: str, i: int, in_class: bool) -> tuple[str, int]:
    """Translate the escape at p[i] == "\\"; return (python text, next index)."""
    if i + 1 >= len(p):
        raise RE2Error("trailing backslash at end of expression")
    c = p[i + 1]
    j = i + 2
    if c in _SIMPLE_ESC and not (in_class and c in "Az"):
        return _SIMPLE_ESC[c], j
    if c in _CLASS_ESC:
        body = _CLASS_ESC[c]
        return (body, j) if in_class else ("[" + body + "]", j)
    if c in "bB" and not in_class:
        return (_B if c == "b" else _NB), j
    if c == "x":
        if j < len(p) and p[j] == "{":
            end = p.find("}", j)
            h = p[j + 1 : end] if end > 0 else ""
            if end < 0 or not h or any(x not in "0123456789abcdefABCDEF" for x in h):
                raise RE2Error("invalid escape sequence")
            return _char(int(h, 16)), end + 1
        h = p[j : j + 2]
        if len(h) != 2 or any(x not in "0123456789abcdefABCDEF" for x in h):
            raise RE2Error("invalid escape sequence")
        return _char(int(h, 16)), j + 2
    if c in "01234567":
        # A single non-zero digit is a backreference, which RE2 rejects.
        if c != "0" and (j >= len(p) or p[j] not in "01234567"):
            raise RE2Error("invalid escape sequence")
        k = i + 1
        while k < len(p) and k < i + 4 and p[k] in "01234567":
            k += 1
        return _char(int(p[i + 1 : k], 8)), k
    if _is_punct(c):
        return "\\" + c, j
    raise RE2Error("invalid escape sequence")


def _bracket(p: str, i: int) -> tuple[str, int]:
    """Translate the bracket expression starting at p[i] == "["."""
    j = i + 1
    out = ["["]
    if j < len(p) and p[j] == "^":
        out.append("^")
        j += 1
    first = True
    while True:
        if j >= len(p):
            raise RE2Error("missing closing ]")
        c = p[j]
        if c == "]" and not first:
            out.append("]")
            return "".join(out), j + 1
        first = False
        if c == "[" and p.startswith("[:", j):
            end = p.find(":]", j + 2)
            if end >= 0:
                name = p[j + 2 : end]
                if name in _POSIX:
                    out.append(_POSIX[name])
                    j = end + 2
                    continue
                if name.startswith("^") and name[1:] in _POSIX:
                    raise RE2Error("negated POSIX class not supported")
                raise RE2Error("invalid character class range")
        if c == "\\":
            if p.startswith("\\Q", j):
                raise RE2Error("unsupported escape in character class")
            if p.startswith("\\p", j) or p.startswith("\\P", j):
                t, j = _unicode_class(p, j)
                out.append(t)
                continue
            t, j = _escape(p, j, True)
            out.append(t)
            continue
        if c in "[&~|":
            # Literal in RE2; escaped so Python does not read a set operation.
            out.append("\\" + c)
        elif c == "-" and out[-1] in ("[", "^"):
            out.append("\\-")
        else:
            out.append(c)
        j += 1


def translate(p: str) -> str:
    """The Python pattern equivalent to the RE2 pattern p. Raises RE2Error
    for what RE2 would reject or what cannot be translated."""
    multiline = False
    for fm in _FLAGS.finditer(p):
        on = fm.group(1).split("-", 1)[0]
        if "m" in on:
            multiline = True
    out: list[str] = []
    # Per open group: the flag strings of mid-group flag settings, each
    # turned into a scoped group that must close with it.
    stack: list[list[str]] = [[]]
    i = 0
    n = len(p)
    while i < n:
        c = p[i]
        if c == "\\":
            if p.startswith("\\Q", i):
                end = p.find("\\E", i + 2)
                lit = p[i + 2 :] if end < 0 else p[i + 2 : end]
                out.append(re.escape(lit))
                i = n if end < 0 else end + 2
                continue
            if i + 1 < n and p[i + 1] in "pP":
                t, i = _unicode_class(p, i)
                out.append("[" + t + "]")
                continue
            if i + 1 < n and p[i + 1] == "C":
                raise RE2Error("unsupported escape")
            t, i = _escape(p, i, False)
            out.append(t)
            continue
        if c == "[":
            t, i = _bracket(p, i)
            out.append(t)
            continue
        if c == "(":
            if p.startswith("(?", i):
                mn = _NAME.match(p, i)
                if mn:
                    out.append(f"(?P<{mn.group(1)}>")
                    stack.append([])
                    i = mn.end()
                    continue
                if p.startswith("(?:", i):
                    out.append("(?:")
                    stack.append([])
                    i += 3
                    continue
                m = _FLAGS.match(p, i)
                if not m or m.group(1) in ("", "-") or m.group(1).endswith("-") or "U" in m.group(1):
                    raise RE2Error("invalid or unsupported Perl syntax")
                flags = m.group(1)
                if m.group(2) == ":":
                    out.append(f"(?{flags}:")
                    stack.append([])
                else:
                    out.append(f"(?{flags}:")
                    stack[-1].append(flags)
                i = m.end()
                continue
            out.append("(")
            stack.append([])
            i += 1
            continue
        if c == ")":
            if len(stack) == 1:
                raise RE2Error("unexpected )")
            pending = stack.pop()
            out.append(")" * len(pending) + ")")
            i += 1
            continue
        if c == "|":
            pending = stack[-1]
            out.append(")" * len(pending) + "|" + "".join(f"(?{f}:" for f in pending))
            i += 1
            continue
        if c == "{":
            m = _REPEAT.match(p, i)
            if not m:
                out.append("\\{")
                i += 1
                continue
            lo = int(m.group(1))
            hi = lo if m.group(2) is None else (int(m.group(3)) if m.group(3) else -1)
            if lo > _MAX_REPEAT or hi > _MAX_REPEAT or (hi >= 0 and hi < lo):
                raise RE2Error("invalid repeat count")
            out.append(m.group(0))
            i = m.end()
            if i < n and p[i] == "?":
                out.append("?")
                i += 1
            if i < n and p[i] in "*+?{":
                raise RE2Error("invalid nested repetition operator")
            continue
        if c in "*+?":
            out.append(c)
            i += 1
            if i < n and p[i] == "?":
                out.append("?")
                i += 1
            if i < n and (p[i] in "*+?" or _REPEAT.match(p, i)):
                raise RE2Error("invalid nested repetition operator")
            continue
        if c == "$" and not multiline:
            out.append("\\Z")
            i += 1
            continue
        if c == "}":
            out.append("\\}")
            i += 1
            continue
        out.append(c)
        i += 1
    if len(stack) != 1:
        raise RE2Error("missing closing )")
    out.append(")" * len(stack[0]))
    return "".join(out)


def compile_re2(p: str) -> re.Pattern[str]:
    """Compile an RE2 pattern. Raises RE2Error (a ValueError)."""
    try:
        return re.compile(translate(p))
    except re.error as e:
        raise RE2Error(str(e)) from None
