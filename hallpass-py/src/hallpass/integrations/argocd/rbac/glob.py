"""A matcher compatible with github.com/gobwas/glob compiled with no
separators, which is how Argo CD calls it. With no separators ``*`` and
``**`` both match any sequence of characters, including "/".

Syntax: ``*`` and ``**`` any sequence; ``?`` one character; ``[abc]``,
``[a-z]``, ``[!abc]`` character classes; ``{a,b}`` alternatives, which may
nest; ``\\x`` escapes x.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from hallpass.core.errors import go_quote

__all__ = ["GlobError", "GlobPattern", "compile_glob", "glob_match", "parse_glob"]

_TEXT, _ANY, _SUPER, _CLASS = 0, 1, 2, 3


class GlobError(ValueError):
    pass


@dataclass
class _Node:
    kind: int
    text: str = ""
    # class
    negate: bool = False
    ranges: list[tuple[str, str]] = field(default_factory=list)

    def class_match(self, r: str) -> bool:
        inside = any(lo <= r <= hi for lo, hi in self.ranges)
        return inside != self.negate


@dataclass
class GlobPattern:
    """A compiled pattern: a set of alternative flat sequences."""

    alts: list[list[_Node]]

    def match(self, text: str) -> bool:
        return any(_match_seq(seq, text) for seq in self.alts)


_lock = threading.Lock()
_cache: dict[str, GlobPattern] = {}
_errs: dict[str, GlobError] = {}


def glob_match(pattern: str, text: str) -> bool:
    """Whether text matches pattern. An invalid pattern never matches, as in
    Argo CD (which logs the compile error and returns false)."""
    try:
        p = compile_glob(pattern)
    except GlobError:
        return False
    return p.match(text)


def compile_glob(pattern: str) -> GlobPattern:
    global _cache, _errs
    with _lock:
        p = _cache.get(pattern)
        if p is not None:
            return p
        e = _errs.get(pattern)
        if e is not None:
            raise e
        if len(_cache) + len(_errs) > 10000:
            _cache = {}
            _errs = {}
        try:
            p = parse_glob(pattern)
        except GlobError as err:
            _errs[pattern] = err
            raise
        _cache[pattern] = p
        return p


def parse_glob(pattern: str) -> GlobPattern:
    """Parse the whole pattern. Raises GlobError."""
    alts, rest = _parse_seq(pattern, False)
    if rest != "":
        raise GlobError(f"glob {go_quote(pattern)}: unexpected {go_quote(rest)}")
    return GlobPattern(alts)


def _parse_seq(s: str, in_brace: bool) -> tuple[list[list[_Node]], str]:
    """Parse until end of input or, inside braces, until "," or "}".
    Return every alternative expansion of the parsed sequence."""
    alts: list[list[_Node]] = [[]]

    def append_node(n: _Node) -> None:
        for a in alts:
            a.append(n)

    while s:
        r = s[0]
        if r == "\\":
            if len(s) < 2:
                raise GlobError("glob: trailing backslash")
            append_node(_Node(_TEXT, s[1]))
            s = s[2:]
        elif r == "*":
            s = s[1:].lstrip("*")
            append_node(_Node(_SUPER))
        elif r == "?":
            append_node(_Node(_ANY))
            s = s[1:]
        elif r == "[":
            n, s = _parse_class(s[1:])
            append_node(n)
        elif r == "{":
            s = s[1:]
            sub: list[list[_Node]] = []
            while True:
                a, rest = _parse_seq(s, True)
                sub.extend(a)
                if rest.startswith(","):
                    s = rest[1:]
                    continue
                if rest.startswith("}"):
                    s = rest[1:]
                    break
                raise GlobError("glob: unclosed {")
            alts = [x + y for x in alts for y in sub]
        elif r in ",}":
            if in_brace:
                return _merge_text(alts), s
            append_node(_Node(_TEXT, r))
            s = s[1:]
        else:
            append_node(_Node(_TEXT, r))
            s = s[1:]
    if in_brace:
        raise GlobError("glob: unclosed {")
    return _merge_text(alts), ""


def _merge_text(alts: list[list[_Node]]) -> list[list[_Node]]:
    """Join adjacent text nodes."""
    out_alts = []
    for seq in alts:
        out: list[_Node] = []
        for n in seq:
            if n.kind == _TEXT and out and out[-1].kind == _TEXT:
                out[-1] = _Node(_TEXT, out[-1].text + n.text)
                continue
            out.append(n)
        out_alts.append(out)
    return out_alts


def _parse_class(s: str) -> tuple[_Node, str]:
    """Parse the body of [...] after the opening bracket."""
    n = _Node(_CLASS)
    if s.startswith("!"):
        n.negate = True
        s = s[1:]
    first = True
    while True:
        if s == "":
            raise GlobError("glob: unclosed [")
        r = s[0]
        size = 1
        if r == "]" and not first:
            return n, s[1:]
        first = False
        if r == "\\" and len(s) > 1:
            r = s[1]
            size = 2
        s = s[size:]
        lo = hi = r
        if s.startswith("-") and len(s) > 1 and s[1] != "]":
            r2 = s[1]
            size2 = 1
            if r2 == "\\" and len(s) > 2:
                r2 = s[2]
                size2 = 2
            hi = r2
            s = s[1 + size2 :]
        if hi < lo:
            raise GlobError(f"glob: bad range {lo}-{hi}")
        n.ranges.append((lo, hi))


def _match_seq(seq: list[_Node], text: str) -> bool:
    """Match one flat sequence. The set of text positions reachable after
    each node is tracked, so matching is linear in len(seq) * len(text)
    (Go: memoised backtracking, the same answers)."""
    n = len(text)
    states = {0}
    for node in seq:
        if not states:
            return False
        nxt: set[int] = set()
        if node.kind == _SUPER:
            nxt = set(range(min(states), n + 1))
        elif node.kind == _TEXT:
            for pos in states:
                if text.startswith(node.text, pos):
                    nxt.add(pos + len(node.text))
        elif node.kind == _ANY:
            nxt = {pos + 1 for pos in states if pos < n}
        else:
            nxt = {pos + 1 for pos in states if pos < n and node.class_match(text[pos])}
        states = nxt
    return n in states
