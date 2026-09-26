"""Vault ACL policies: the HCL and JSON parser, identity templates, and the
evaluation Vault itself applies (the most specific matching path wins, deny
beats everything, "+" spans one segment and a trailing "*" any suffix)."""

from __future__ import annotations

import json.decoder
import re
from dataclasses import dataclass, field
from typing import Any

from hallpass.core.errors import go_lower, go_quote, go_trim_space

__all__ = [
    "CAPABILITIES",
    "LEGACY_POLICY",
    "Alias",
    "Evaluation",
    "PolicyError",
    "Rule",
    "TemplateContext",
    "evaluate",
    "first_wildcard",
    "less_priority",
    "match_pattern",
    "parse_policy",
    "plus_segments",
    "resolve_templates",
]


class PolicyError(ValueError):
    """A policy hallpass does not parse."""


@dataclass
class Rule:
    """One path stanza of an ACL policy."""

    # The path as written, templates resolved; templates that could not be
    # resolved are replaced by a glob and unresolved is set.
    pattern: str
    caps: set[str] = field(default_factory=set)
    unresolved: bool = False
    # params is set when allowed_parameters, denied_parameters or
    # required_parameters restrict the stanza; wrapping when a wrapping TTL
    # is required. Both make the answer unknown: hallpass does not see the
    # request's parameters, and reads carry them too (KV's version).
    params: bool = False
    wrapping: bool = False
    policy: str = ""


# The capabilities Vault knows.
CAPABILITIES = frozenset({"create", "read", "update", "patch", "delete", "list", "sudo", "deny", "subscribe", "recover"})

# The deprecated `policy = "..."` stanza attribute.
# UNVERIFIED: taken from Vault's policy package (write = create, read,
# update, delete, list; read = read, list; sudo = all of them plus sudo).
LEGACY_POLICY: dict[str, tuple[str, ...]] = {
    "deny": ("deny",),
    "read": ("read", "list"),
    "write": ("create", "read", "update", "delete", "list"),
    "sudo": ("create", "read", "update", "delete", "list", "sudo"),
}


@dataclass
class Alias:
    id: str = ""
    name: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class TemplateContext:
    """Resolves {{identity...}} placeholders for one entity."""

    entity_id: str = ""
    entity_name: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
    # Aliases by mount accessor: id, name and metadata.
    aliases: dict[str, Alias] = field(default_factory=dict)
    # Groups by id (id -> name) and by name (name -> id).
    group_names: dict[str, str] = field(default_factory=dict)
    group_ids: dict[str, str] = field(default_factory=dict)

    def lookup(self, key: str) -> tuple[str, bool]:
        """Resolve one template key."""
        parts = key.split(".")
        if len(parts) < 3 or parts[0] != "identity":
            return "", False
        if parts[1] == "entity":
            if len(parts) == 3 and parts[2] == "id":
                return self.entity_id, True
            if len(parts) == 3 and parts[2] == "name":
                return self.entity_name, True
            if len(parts) == 4 and parts[2] == "metadata":
                return _get(self.metadata, parts[3])
            if len(parts) >= 5 and parts[2] == "aliases":
                a = self.aliases.get(parts[3])
                if a is None:
                    return "", False
                if len(parts) == 5 and parts[4] == "id":
                    return a.id, True
                if len(parts) == 5 and parts[4] == "name":
                    return a.name, True
                if len(parts) == 6 and parts[4] == "metadata":
                    return _get(a.metadata, parts[5])
        elif parts[1] == "groups":
            if len(parts) == 5 and parts[2] == "ids" and parts[4] == "name":
                return _get(self.group_names, parts[3])
            if len(parts) == 5 and parts[2] == "names" and parts[4] == "id":
                return _get(self.group_ids, parts[3])
        return "", False


def _get(m: dict[str, str], k: str) -> tuple[str, bool]:
    if k in m:
        return m[k], True
    return "", False


def parse_policy(name: str, src: str, tc: TemplateContext | None) -> list[Rule]:
    """Parse an ACL policy in HCL or JSON; PolicyError when it does not parse."""
    trimmed = go_trim_space(src)
    try:
        rules = _parse_json_policy(trimmed) if trimmed.startswith("{") else _parse_hcl_policy(trimmed)
    except PolicyError as e:
        raise PolicyError(f"policy {name}: {e}") from e
    for r in rules:
        r.policy = name
        # Vault drops one leading slash: paths start after the / of the API.
        pattern = r.pattern[1:] if r.pattern.startswith("/") else r.pattern
        if pattern == "":
            raise PolicyError(f"policy {name}: a path stanza has an empty path")
        r.pattern, r.unresolved = resolve_templates(pattern, tc)
    return rules


# -- JSON ----------------------------------------------------------------------
#
# Go decodes the policy into structs with json.RawMessage fields, so the
# parser keeps each value's raw text: `{ }` is a non-empty parameter
# constraint where `{}` is an empty one, exactly as nonEmptyJSON reads it.


@dataclass
class _Node:
    kind: str  # object, array, string, number, bool, null
    # object: [(key, node)] in document order; array: [node]; else the value.
    value: Any
    raw: str


_JSON_WS = " \t\n\r"
_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_SURROGATE_RE = re.compile("[\ud800-\udfff]")
_MAX_DEPTH = 10000


class _JSONParser:
    def __init__(self, s: str) -> None:
        self.s = s
        self.i = 0

    def ws(self) -> None:
        while self.i < len(self.s) and self.s[self.i] in _JSON_WS:
            self.i += 1

    def fail(self, what: str) -> PolicyError:
        if self.i >= len(self.s):
            return PolicyError("unexpected end of JSON input")
        return PolicyError(f"invalid character {go_quote(self.s[self.i])} {what}")

    def value(self, depth: int) -> _Node:
        if depth > _MAX_DEPTH:
            raise PolicyError("exceeded max depth")
        self.ws()
        start = self.i
        if self.i >= len(self.s):
            raise self.fail("looking for beginning of value")
        c = self.s[self.i]
        if c == "{":
            self.i += 1
            pairs: list[tuple[str, _Node]] = []
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == "}":
                self.i += 1
                return _Node("object", pairs, self.s[start : self.i])
            while True:
                self.ws()
                if self.i >= len(self.s) or self.s[self.i] != '"':
                    raise self.fail("looking for beginning of object key string")
                key = self.string()
                self.ws()
                if self.i >= len(self.s) or self.s[self.i] != ":":
                    raise self.fail("after object key")
                self.i += 1
                pairs.append((key, self.value(depth + 1)))
                self.ws()
                if self.i < len(self.s) and self.s[self.i] == ",":
                    self.i += 1
                    continue
                if self.i < len(self.s) and self.s[self.i] == "}":
                    self.i += 1
                    return _Node("object", pairs, self.s[start : self.i])
                raise self.fail("after object key:value pair")
        if c == "[":
            self.i += 1
            items: list[_Node] = []
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == "]":
                self.i += 1
                return _Node("array", items, self.s[start : self.i])
            while True:
                items.append(self.value(depth + 1))
                self.ws()
                if self.i < len(self.s) and self.s[self.i] == ",":
                    self.i += 1
                    continue
                if self.i < len(self.s) and self.s[self.i] == "]":
                    self.i += 1
                    return _Node("array", items, self.s[start : self.i])
                raise self.fail("after array element")
        if c == '"':
            v = self.string()
            return _Node("string", v, self.s[start : self.i])
        for lit, kind, val in (("true", "bool", True), ("false", "bool", False), ("null", "null", None)):
            if self.s.startswith(lit, self.i):
                self.i += len(lit)
                return _Node(kind, val, lit)
        m = _NUMBER_RE.match(self.s, self.i)
        if m:
            self.i = m.end()
            return _Node("number", m.group(0), m.group(0))
        raise self.fail("looking for beginning of value")

    def string(self) -> str:
        try:
            v, end = json.decoder.scanstring(self.s, self.i + 1, True)
        except json.JSONDecodeError as e:
            raise PolicyError(f"invalid string: {e.msg}") from None
        self.i = end
        # Go replaces an unpaired surrogate escape with U+FFFD.
        return _SURROGATE_RE.sub("�", v)


def _parse_json(s: str) -> _Node:
    p = _JSONParser(s)
    try:
        n = p.value(0)
    except RecursionError:
        raise PolicyError("exceeded max depth") from None
    p.ws()
    if p.i != len(s):
        raise p.fail("after top-level value")
    return n


def _fold(s: str) -> str:
    """encoding/json's folded field name: ASCII upper case, the Kelvin sign
    and the long s folded to K and S."""
    return "".join("K" if c == "K" else "S" if c == "ſ" else c.upper() if c.isascii() else c for c in s)


def _member(n: _Node, name: str) -> _Node | None:
    """The member Go decodes into the struct field name: the last one whose
    key matches exactly or case-insensitively."""
    out = None
    fname = _fold(name)
    for k, v in n.value:
        if k == name or _fold(k) == fname:
            out = v
    return out


def _type_error(n: _Node, want: str) -> PolicyError:
    return PolicyError(f"json: cannot unmarshal {n.kind} into Go value of type {want}")


def _parse_json_policy(src: str) -> list[Rule]:
    try:
        doc = _parse_json(src)
    except PolicyError as e:
        raise PolicyError(f"not JSON: {e}") from None
    if doc.kind != "object":
        # Only an object reaches here (the text starts with "{").
        raise PolicyError(f"not JSON: {_type_error(doc, 'struct')}")
    path = _member(doc, "path")
    if path is None:
        return []
    stanzas: dict[str, _Node] = {}
    if path.kind == "object":
        for k, v in path.value:
            stanzas[k] = v
    elif path.kind == "null":
        pass
    elif path.kind == "array":
        # The list form: [{"secret/foo": {...}}, ...].
        for m in path.value:
            if m.kind == "null":
                continue
            if m.kind != "object":
                raise PolicyError("path is neither an object nor a list")
            for k, v in m.value:
                stanzas[k] = v
    else:
        raise PolicyError("path is neither an object nor a list")
    rules: list[Rule] = []
    for pattern, raw in stanzas.items():
        caps, legacy, params, wrapping = _decode_stanza(pattern, raw)
        r = _new_rule(pattern, caps, legacy)
        r.params, r.wrapping = params, wrapping
        rules.append(r)
    rules.sort(key=lambda r: r.pattern)
    return rules


def _decode_stanza(pattern: str, n: _Node) -> tuple[list[str], str, bool, bool]:
    """Go's json.Unmarshal of one stanza body into its struct."""
    if n.kind == "null":
        return [], "", False, False
    if n.kind != "object":
        raise PolicyError(f"stanza {go_quote(pattern)}: {_type_error(n, 'struct')}")
    caps: list[str] = []
    legacy = ""
    raws: dict[str, str] = {}
    err: PolicyError | None = None
    fields = ("capabilities", "policy", "allowed_parameters", "denied_parameters", "required_parameters", "min_wrapping_ttl", "max_wrapping_ttl")
    for k, v in n.value:
        name = k if k in fields else next((f for f in fields if _fold(f) == _fold(k)), None)
        if name is None:
            continue
        if name == "capabilities":
            if v.kind == "null":
                caps = []
            elif v.kind == "array":
                caps = []
                for x in v.value:
                    if x.kind == "string":
                        caps.append(x.value)
                    elif x.kind == "null":
                        caps.append("")
                    else:
                        caps.append("")
                        err = err or _type_error(x, "string")
            else:
                err = err or _type_error(v, "[]string")
        elif name == "policy":
            if v.kind == "string":
                legacy = v.value
            elif v.kind != "null":
                err = err or _type_error(v, "string")
        else:
            raws[name] = v.raw
    if err is not None:
        raise PolicyError(f"stanza {go_quote(pattern)}: {err}")
    params = any(_non_empty_json(raws.get(f, "")) for f in ("allowed_parameters", "denied_parameters", "required_parameters"))
    wrapping = any(_non_empty_json(raws.get(f, "")) for f in ("min_wrapping_ttl", "max_wrapping_ttl"))
    return caps, legacy, params, wrapping


def _non_empty_json(raw: str) -> bool:
    s = go_trim_space(raw)
    return s not in ("", "null", "{}", "[]", '""', "0")


def _new_rule(pattern: str, caps: list[str], legacy: str) -> Rule:
    r = Rule(pattern=pattern)
    if pattern == "":
        raise PolicyError("a path stanza has an empty path")
    for c in caps:
        c = go_lower(go_trim_space(c))
        if c not in CAPABILITIES:
            raise PolicyError(f"stanza {go_quote(pattern)} has unknown capability {go_quote(c)}")
        r.caps.add(c)
    if legacy != "":
        mapped = LEGACY_POLICY.get(go_lower(legacy))
        if mapped is None:
            raise PolicyError(f"stanza {go_quote(pattern)} has unknown policy {go_quote(legacy)}")
        r.caps.update(mapped)
    return r


# -- HCL -----------------------------------------------------------------------


@dataclass(frozen=True)
class _Tok:
    kind: str = ""  # n name, s string, p punctuation, d number, e end of line
    val: str = ""
    pos: int = 0


_NAME_START = frozenset("_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_NAME_CHARS = _NAME_START | frozenset("-.0123456789")
_DIGITS = frozenset("0123456789")
_NUMBER_CHARS = _DIGITS | frozenset(".hms")


def _go_quote_byte(c: str) -> str:
    """%q of a byte: a single-quoted character literal."""
    q = go_quote(c)[1:-1]
    if c == '"':
        q = '"'
    elif c == "'":
        q = "\\'"
    return "'" + q + "'"


def _hcl_lex(src: str) -> list[_Tok]:
    toks: list[_Tok] = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c in " \t\r,":
            i += 1
        elif c == "\n":
            toks.append(_Tok("e", "\n", i))
            i += 1
        elif c == "#" or (c == "/" and i + 1 < n and src[i + 1] == "/"):
            while i < n and src[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            end = src.find("*/", i + 2)
            if end < 0:
                raise PolicyError(f"unterminated comment at {i}")
            i = end + 2
        elif c == '"':
            start = i
            i += 1
            b: list[str] = []
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    i += 1
                    e = src[i]
                    b.append("\n" if e == "n" else "\t" if e == "t" else e)
                    i += 1
                    continue
                if src[i] == "\n":
                    raise PolicyError(f"newline in string at {start}")
                b.append(src[i])
                i += 1
            if i >= n:
                raise PolicyError(f"unterminated string at {start}")
            i += 1
            toks.append(_Tok("s", "".join(b), start))
        elif c == "<" and src.startswith("<<", i):
            raise PolicyError(f"heredoc at {i} is not supported")
        elif c in "{}[]=:":
            toks.append(_Tok("p", c, i))
            i += 1
        elif c == "-" or c in _DIGITS:
            j = i + 1
            while j < n and src[j] in _NUMBER_CHARS:
                j += 1
            toks.append(_Tok("d", src[i:j], i))
            i = j
        elif c in _NAME_START:
            j = i
            while j < n and src[j] in _NAME_CHARS:
                j += 1
            toks.append(_Tok("n", src[i:j], i))
            i = j
        else:
            raise PolicyError(f"unexpected byte {_go_quote_byte(c)} at {i}")
    return toks


class _HCLParser:
    def __init__(self, toks: list[_Tok]) -> None:
        self.toks = toks
        self.i = 0

    def skip_newlines(self) -> None:
        while self.i < len(self.toks) and self.toks[self.i].kind == "e":
            self.i += 1

    def peek(self) -> _Tok:
        self.skip_newlines()
        if self.i < len(self.toks):
            return self.toks[self.i]
        return _Tok()

    def more(self) -> bool:
        self.skip_newlines()
        return self.i < len(self.toks)

    def next(self) -> _Tok:
        t = self.peek()
        self.i += 1
        return t

    def is_(self, kind: str, val: str) -> bool:
        t = self.peek()
        return self.more() and t.kind == kind and (val == "" or t.val == val)

    def value(self) -> bool:
        """Skip one value (string, number, name, list or object) and report
        whether it was non-empty."""
        t = self.peek()
        if t.kind == "s":
            self.next()
            return t.val != ""
        if t.kind == "d":
            self.next()
            return t.val != "0"
        if t.kind == "n":
            self.next()
            return t.val not in ("null", "false")
        if t.kind == "p" and t.val == "[":
            self.next()
            count = 0
            while not self.is_("p", "]"):
                if not self.more():
                    raise PolicyError("unterminated list")
                self.value()
                count += 1
            self.next()
            return count > 0
        if t.kind == "p" and t.val == "{":
            self.next()
            count = 0
            while not self.is_("p", "}"):
                if not self.more():
                    raise PolicyError("unterminated object")
                k = self.next()
                if k.kind not in ("s", "n"):
                    raise PolicyError(f"expected a key at {k.pos}")
                # key = value, key : value, or a nested block with optional
                # labels: factor "ops" { ... } (control groups).
                while self.is_("s", ""):
                    self.next()
                if self.is_("p", "=") or self.is_("p", ":"):
                    self.next()
                elif not self.is_("p", "{"):
                    raise PolicyError(f"expected = or a block after key {go_quote(k.val)}")
                self.value()
                count += 1
            self.next()
            return count > 0
        raise PolicyError(f"expected a value at {t.pos}, found {go_quote(t.val)}")

    def string_list(self) -> list[str]:
        """["a", "b"] or a single string."""
        if self.is_("s", ""):
            return [self.next().val]
        if not self.is_("p", "["):
            raise PolicyError(f"expected a list at {self.peek().pos}")
        self.next()
        out: list[str] = []
        while not self.is_("p", "]"):
            if not self.more():
                raise PolicyError("unterminated list")
            t = self.next()
            if t.kind != "s":
                raise PolicyError(f"expected a string at {t.pos}")
            out.append(t.val)
        self.next()
        return out

    def stanza(self, pattern: str) -> Rule:
        """{ capabilities = [...] ... } for pattern."""
        if not self.is_("p", "{"):
            raise PolicyError(f"expected {{ for path {go_quote(pattern)}")
        self.next()
        caps: list[str] = []
        legacy = ""
        params = wrapping = False
        while not self.is_("p", "}"):
            if not self.more():
                raise PolicyError(f"unterminated stanza for {go_quote(pattern)}")
            k = self.next()
            if k.kind not in ("n", "s"):
                raise PolicyError(f"expected an attribute in {go_quote(pattern)} at {k.pos}")
            if not self.is_("p", "=") and not self.is_("p", ":"):
                raise PolicyError(f"expected = after {go_quote(k.val)} in {go_quote(pattern)}")
            self.next()
            if k.val == "capabilities":
                try:
                    caps.extend(self.string_list())
                except PolicyError as e:
                    raise PolicyError(f"{go_quote(pattern)} capabilities: {e}") from e
            elif k.val == "policy":
                t = self.next()
                if t.kind != "s":
                    raise PolicyError(f"{go_quote(pattern)} policy: expected a string")
                legacy = t.val
            elif k.val in ("allowed_parameters", "denied_parameters", "required_parameters"):
                params = self.value() or params
            elif k.val in ("min_wrapping_ttl", "max_wrapping_ttl"):
                wrapping = self.value() or wrapping
            else:
                # control_group, subscribe_event_types and future attributes.
                self.value()
        self.next()
        r = _new_rule(pattern, caps, legacy)
        r.params, r.wrapping = params, wrapping
        return r


def _parse_hcl_policy(src: str) -> list[Rule]:
    """The subset of HCL that Vault policies use: `path "<pattern>" { attr =
    value ... }` blocks, and top-level attributes such as `name`, which are
    ignored."""
    p = _HCLParser(_hcl_lex(src))
    rules: list[Rule] = []
    while p.more():
        t = p.next()
        if t.kind != "n":
            raise PolicyError(f"expected a block or attribute at {t.pos}, found {go_quote(t.val)}")
        if t.val != "path":
            # A top-level attribute (name = "...") or an unknown block.
            if p.is_("p", "="):
                p.next()
                p.value()
                continue
            raise PolicyError(f"unknown block {go_quote(t.val)} at {t.pos}")
        # path "pattern" { ... } or path = { "pattern" = { ... } }.
        if p.is_("p", "="):
            p.next()
            if not p.is_("p", "{"):
                raise PolicyError(f"expected {{ after path = at {p.peek().pos}")
            p.next()
            while not p.is_("p", "}"):
                k = p.next()
                if k.kind not in ("s", "n"):
                    raise PolicyError(f"expected a path at {k.pos}")
                if p.is_("p", "=") or p.is_("p", ":"):
                    p.next()
                rules.append(p.stanza(k.val))
            p.next()
            continue
        name = p.next()
        if name.kind != "s":
            raise PolicyError(f"expected a quoted path at {name.pos}")
        rules.append(p.stanza(name.val))
    return rules


# -- templates -----------------------------------------------------------------


def resolve_templates(pattern: str, tc: TemplateContext | None) -> tuple[str, bool]:
    """Substitute {{identity.*}} placeholders. From the first placeholder it
    cannot resolve (unknown selector, empty value, or a value with a slash
    or wildcard, whose rendering could take any shape) the pattern becomes a
    glob of its literal prefix, so that it matches everything Vault's
    rendering might, and unresolved is reported."""
    if "{{" not in pattern:
        return pattern, False
    b: list[str] = []
    rest = pattern
    while True:
        i = rest.find("{{")
        if i < 0:
            b.append(rest)
            return "".join(b), False
        b.append(rest[:i])
        j = rest.find("}}", i)
        if j < 0:
            return "".join(b) + "*", True
        key = go_trim_space(rest[i + 2 : j])
        rest = rest[j + 2 :]
        v, ok = tc.lookup(key) if tc is not None else ("", False)
        if not ok or v == "" or any(c in v for c in "/*+"):
            return "".join(b) + "*", True
        b.append(v)


# -- matching ------------------------------------------------------------------


def _blen(s: str) -> int:
    """len() of a Go string: its UTF-8 bytes."""
    return len(s.encode("utf-8", "surrogatepass"))


def match_pattern(pattern: str, path: str) -> bool:
    """Whether a policy pattern covers path: a segment that is exactly "+"
    matches any one segment, a trailing "*" matches any suffix, everything
    else (a "+" inside a segment included) is literal."""
    glob = pattern.endswith("*")
    if glob:
        pattern = pattern[:-1]
    psegs, segs = pattern.split("/"), path.split("/")
    for i, ps in enumerate(psegs):
        if i >= len(segs):
            return False
        if glob and i == len(psegs) - 1:
            # The partial last segment is a prefix of the rest of the path.
            return "/".join(segs[i:]).startswith(ps)
        if ps != "+" and ps != segs[i]:
            return False
    return len(segs) == len(psegs)


def less_priority(a: str, b: str) -> bool:
    """Whether pattern a has lower priority than b under Vault's rules: an
    earlier first wildcard, a trailing glob, more "+" segments, a shorter
    length, then lexicographic order."""
    fa, fb = first_wildcard(a), first_wildcard(b)
    if fa != fb:
        return fa < fb
    ga, gb = a.endswith("*"), b.endswith("*")
    if ga != gb:
        return ga
    pa, pb = plus_segments(a), plus_segments(b)
    if pa != pb:
        return pa > pb
    la, lb = _blen(a), _blen(b)
    if la != lb:
        return la < lb
    return a < b


def plus_segments(pattern: str) -> int:
    """The number of segments that are exactly "+"."""
    p = pattern[:-1] if pattern.endswith("*") else pattern
    return sum(1 for seg in p.split("/") if seg == "+")


def first_wildcard(pattern: str) -> int:
    """The byte index of the first "+" segment or the trailing glob, or past
    the end when there is none."""
    off = 0
    for seg in pattern.split("/"):
        if seg in ("+", "*"):
            return off
        off += _blen(seg) + 1
    if pattern.endswith("*"):
        return _blen(pattern) - 1
    return _blen(pattern) + 1


@dataclass
class Evaluation:
    """The outcome of matching a path and capability against a rule set."""

    # "allow", "deny", "unknown".
    outcome: str = ""
    # The winning pattern, and the policies carrying it.
    pattern: str = ""
    policies: list[str] = field(default_factory=list)
    # Explains deny and unknown outcomes.
    reason: str = ""


def evaluate(rules: list[Rule], path: str, need: list[str] | tuple[str, ...]) -> Evaluation:
    """Vault's matching: the highest-priority matching pattern decides, with
    the union of capabilities the policies grant it; deny wins; parameter
    and wrapping constraints make the answer unknown."""
    if not rules:
        return Evaluation(outcome="deny", reason="no policy path matches")
    # Group rules by pattern, taking the union of capabilities.
    by_pattern: dict[str, list[Rule]] = {}
    winner = ""
    for r in rules:
        if not match_pattern(r.pattern, path):
            continue
        by_pattern.setdefault(r.pattern, []).append(r)
        if winner == "" or less_priority(winner, r.pattern):
            winner = r.pattern
    if winner == "":
        return Evaluation(outcome="deny", reason="no policy path matches " + path)
    caps: set[str] = set()
    params = wrapping = winner_unresolved = False
    policies: list[str] = []
    for r in by_pattern[winner]:
        caps |= r.caps
        params = params or r.params
        wrapping = wrapping or r.wrapping
        winner_unresolved = winner_unresolved or r.unresolved
        policies.append(r.policy)
    policies.sort()
    ev = Evaluation(pattern=winner, policies=policies)
    if winner_unresolved:
        ev.outcome, ev.reason = "unknown", f"policy path {go_quote(winner)} carries a template hallpass could not resolve"
        return ev
    # Another matching stanza with an unresolved template could, once
    # rendered by Vault, be the same pattern as the winner (and add a deny)
    # or outrank it; either way the answer is unknown.
    for pattern, rs in by_pattern.items():
        if pattern == winner:
            continue
        for r in rs:
            if r.unresolved:
                ev.outcome, ev.reason = "unknown", f"policy path {go_quote(pattern)} carries a template hallpass could not resolve"
                return ev
    if "deny" in caps:
        ev.outcome, ev.reason = "deny", f"policy path {go_quote(winner)} denies"
        return ev
    missing = [c for c in need if c not in caps]
    if missing:
        ev.outcome, ev.reason = "deny", f"policy path {go_quote(winner)} grants {_cap_list(caps)} but not {', '.join(missing)}"
        return ev
    if params:
        ev.outcome = "unknown"
        ev.reason = (
            f"policy path {go_quote(winner)} restricts the request parameters (allowed, denied or required parameters), which hallpass does not evaluate"
        )
        return ev
    if wrapping:
        ev.outcome, ev.reason = "unknown", f"policy path {go_quote(winner)} requires response wrapping, which hallpass does not evaluate"
        return ev
    ev.outcome = "allow"
    return ev


def _cap_list(caps: set[str]) -> str:
    out = sorted(caps)
    if not out:
        return "nothing"
    return ", ".join(out)
