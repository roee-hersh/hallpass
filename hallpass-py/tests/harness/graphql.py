"""GraphQL validation against a schema in SDL form: the POST body's query
must parse, every selected field must exist on its type with the
arguments the schema declares, required arguments must be given,
selection sets must sit on composite types only, and the variables must
match their declared input types.

A port of internal/integration/itest/graphql.go. Load a schema through
tests.harness.spec.load_spec (it detects SDL) or new_graphql directly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from tests.harness.spec import SpecError, SpecRequest, go_json, go_json_kind, go_quote

__all__ = ["GraphQL", "looks_like_sdl", "new_graphql"]


# A type reference: a name, wrapped in lists, each level possibly non-null.
@dataclass
class _Ref:
    name: str = ""
    non_null: bool = False
    elem: _Ref | None = None  # the element type of a list

    def base(self) -> str:
        if self.elem is not None:
            return self.elem.base()
        return self.name

    def __str__(self) -> str:
        s = self.name
        if self.elem is not None:
            s = "[" + str(self.elem) + "]"
        if self.non_null:
            s += "!"
        return s


@dataclass
class _Arg:
    typ: _Ref = field(default_factory=_Ref)
    has_default: bool = False


@dataclass
class _Field:
    typ: _Ref = field(default_factory=_Ref)
    args: dict[str, _Arg] = field(default_factory=dict)


@dataclass
class _Type:
    kind: str  # OBJECT, INTERFACE, INPUT, ENUM, SCALAR, UNION
    fields: dict[str, _Field] = field(default_factory=dict)
    enum: set[str] = field(default_factory=set)
    members: list[str] = field(default_factory=list)


# A type definition at the start of a line: `type Query {`, `schema {`,
# `directive @x`, `scalar DateTime`, `union U = A | B`. A YAML description
# that happens to start a line with "type of ..." does not match, since the
# name must be followed by a brace, "implements", "=", "@" or the end of the
# line.
_SDL_RE = re.compile(
    r"^\s*(?:(?:extend\s+)?(?:type|interface|input|enum|scalar|union)\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\{|implements\b|=|@|$)"
    r"|(?:extend\s+)?schema\s*(?:\{|@)|directive\s+@)",
    re.MULTILINE | re.ASCII,
)


def looks_like_sdl(raw: bytes | str) -> bool:
    """Whether raw is a GraphQL schema rather than JSON or YAML. Consulted
    only when the text is not a JSON or YAML document of a known
    description format."""
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", errors="replace")
    trim = raw.strip()
    return trim != "" and trim[0] != "{" and _SDL_RE.search(trim) is not None


# -- lexer ----------------------------------------------------------------------


@dataclass
class _Tok:
    kind: str = ""  # 'n' name, 's' string, 'p' punctuation, 'd' number, 'v' variable
    val: str = ""
    pos: int = 0


class _GQLError(Exception):
    pass


def _is_name_char(c: str) -> bool:
    return c == "_" or "a" <= c <= "z" or "A" <= c <= "Z" or "0" <= c <= "9"


_GO_ESCAPES = {"\a": "\\a", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\v": "\\v", "'": "\\'", "\\": "\\\\"}


def _go_char(c: str) -> str:
    """Go's %q for a byte (c is one char of the latin-1 view)."""
    if c in _GO_ESCAPES:
        return "'" + _GO_ESCAPES[c] + "'"
    if c.isprintable():
        return f"'{c}'"
    if ord(c) < 0x80:
        return f"'\\x{ord(c):02x}'"
    return f"'\\u{ord(c):04x}'"


def _utf8(latin: str) -> str:
    return latin.encode("latin-1").decode("utf-8", errors="replace")


def _lex(text: str | bytes) -> list[_Tok]:
    """Tokens of a GraphQL document. Like Go's lexer it works on bytes:
    positions are byte offsets (string values are decoded back)."""
    toks: list[_Tok] = []
    raw = text if isinstance(text, bytes) else text.encode("utf-8", errors="surrogatepass")
    src = raw.decode("latin-1")
    if src.startswith("\xef\xbb\xbf"):
        src = src[3:]
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c in " \t\n\r,":
            i += 1
        elif c == "#":
            while i < n and src[i] != "\n":
                i += 1
        elif c == '"':
            start = i
            if src.startswith('"""', i):
                end = src.find('"""', i + 3)
                end = end - (i + 3) if end >= 0 else -1
                while end >= 0 and src[i + 3 + end - 1] == "\\":
                    nxt = src.find('"""', i + 3 + end + 3)
                    if nxt < 0:
                        end = -1
                        break
                    end += 3 + (nxt - (i + 3 + end + 3))
                if end < 0:
                    raise _GQLError(f"unterminated block string at {start}")
                toks.append(_Tok("s", _utf8(src[i + 3 : i + 3 + end]), start))
                i += 3 + end + 3
                continue
            i += 1
            b: list[str] = []
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    i += 1
                if src[i] == "\n":
                    raise _GQLError(f"newline in string at {start}")
                b.append(src[i])
                i += 1
            if i >= n:
                raise _GQLError(f"unterminated string at {start}")
            i += 1
            toks.append(_Tok("s", _utf8("".join(b)), start))
        elif c == "$":
            start = i
            i += 1
            j = i
            while j < n and _is_name_char(src[j]):
                j += 1
            if j == i:
                raise _GQLError(f"bare $ at {start}")
            toks.append(_Tok("v", src[i:j], start))
            i = j
        elif c == ".":
            if not src.startswith("...", i):
                raise _GQLError(f"stray . at {i}")
            toks.append(_Tok("p", "...", i))
            i += 3
        elif c in "{}()[]:!=@|&":
            toks.append(_Tok("p", c, i))
            i += 1
        elif c == "-" or "0" <= c <= "9":
            j = i + 1
            while j < n and ("0" <= src[j] <= "9" or src[j] in ".eE+-"):
                j += 1
            toks.append(_Tok("d", src[i:j], i))
            i = j
        elif _is_name_char(c):
            j = i
            while j < n and _is_name_char(src[j]):
                j += 1
            toks.append(_Tok("n", src[i:j], i))
            i = j
        else:
            raise _GQLError(f"unexpected byte {_go_char(c)} at {i}")
    return toks


# -- parser -----------------------------------------------------------------------


@dataclass
class _Value:
    kind: str  # 'v' variable, 's' string, 'd' number, 'n' name (enum, true, false, null), 'l' list, 'o' object
    val: str = ""
    items: list[_Value] = field(default_factory=list)
    obj: dict[str, _Value] = field(default_factory=dict)
    obj_order: list[str] = field(default_factory=list)


@dataclass
class _Sel:
    name: str = ""
    alias: str = ""
    args: dict[str, _Value] = field(default_factory=dict)
    sels: list[_Sel] = field(default_factory=list)
    spread: str = ""  # named fragment spread
    inline: bool = False
    on_type: str = ""


@dataclass
class _Op:
    kind: str
    vars: dict[str, _Arg] = field(default_factory=dict)
    sels: list[_Sel] = field(default_factory=list)


@dataclass
class _Fragment:
    on: str
    sels: list[_Sel]


class _Parser:
    def __init__(self, toks: list[_Tok]) -> None:
        self.toks = toks
        self.i = 0

    def more(self) -> bool:
        return self.i < len(self.toks)

    def peek(self) -> _Tok:
        if self.i < len(self.toks):
            return self.toks[self.i]
        return _Tok()

    def is_(self, kind: str, val: str = "") -> bool:
        t = self.peek()
        return self.more() and t.kind == kind and (val == "" or t.val == val)

    def next(self) -> _Tok:
        t = self.peek()
        self.i += 1
        return t

    def expect(self, kind: str, val: str = "") -> _Tok:
        if not self.is_(kind, val):
            raise _GQLError(f"expected {go_quote(val)} at {self.peek().pos}, found {go_quote(self.peek().val)}")
        return self.next()

    def name(self) -> str:
        return self.expect("n").val

    def type_ref(self) -> _Ref:
        """Name, [Type] and the ! suffixes."""
        r = _Ref()
        if self.is_("p", "["):
            self.next()
            inner = self.type_ref()
            self.expect("p", "]")
            r.elem = inner
        else:
            r.name = self.name()
        if self.is_("p", "!"):
            self.next()
            r.non_null = True
        return r

    def skip_value(self) -> None:
        self.value()

    def skip_directives(self) -> None:
        """Consume @name(args) sequences."""
        while self.is_("p", "@"):
            self.next()
            self.name()
            if self.is_("p", "("):
                self.arguments()

    def skip_description(self) -> None:
        if self.is_("s"):
            self.next()

    def arg_defs(self) -> dict[str, _Arg]:
        """( name: Type = default ... )"""
        args: dict[str, _Arg] = {}
        self.expect("p", "(")
        while not self.is_("p", ")"):
            if not self.more():
                raise _GQLError("unterminated argument list")
            self.skip_description()
            n = self.name()
            self.expect("p", ":")
            a = _Arg(self.type_ref())
            if self.is_("p", "="):
                self.next()
                self.skip_value()
                a.has_default = True
            self.skip_directives()
            args[n] = a
        self.next()
        return args

    def field_defs(self, input: bool) -> dict[str, _Field]:
        """{ name(args): Type ... } for object, interface and input types
        (input fields take no arguments)."""
        fields: dict[str, _Field] = {}
        self.expect("p", "{")
        while not self.is_("p", "}"):
            if not self.more():
                raise _GQLError("unterminated field list")
            self.skip_description()
            n = self.name()
            f = _Field()
            if not input and self.is_("p", "("):
                f.args = self.arg_defs()
            self.expect("p", ":")
            f.typ = self.type_ref()
            if input and self.is_("p", "="):
                self.next()
                self.skip_value()
                # A defaulted input field is optional; record it as such.
                f.args["="] = _Arg(has_default=True)
            self.skip_directives()
            fields[n] = f
        self.next()
        return fields

    # -- query documents --

    def value(self) -> _Value:
        t = self.peek()
        if t.kind == "v":
            self.next()
            return _Value("v", t.val)
        if t.kind in ("s", "d", "n"):
            self.next()
            return _Value(t.kind, t.val)
        if t.kind == "p" and t.val == "[":
            self.next()
            v = _Value("l")
            while not self.is_("p", "]"):
                if not self.more():
                    raise _GQLError("unterminated list")
                v.items.append(self.value())
            self.next()
            return v
        if t.kind == "p" and t.val == "{":
            self.next()
            v = _Value("o")
            while not self.is_("p", "}"):
                if not self.more():
                    raise _GQLError("unterminated object")
                k = self.name()
                self.expect("p", ":")
                v.obj[k] = self.value()
                v.obj_order.append(k)
            self.next()
            return v
        raise _GQLError(f"expected a value at {t.pos}, found {go_quote(t.val)}")

    def arguments(self) -> dict[str, _Value]:
        """( name: value ... )"""
        args: dict[str, _Value] = {}
        self.expect("p", "(")
        while not self.is_("p", ")"):
            if not self.more():
                raise _GQLError("unterminated arguments")
            n = self.name()
            self.expect("p", ":")
            args[n] = self.value()
        self.next()
        return args

    def selection_set(self) -> list[_Sel]:
        self.expect("p", "{")
        sels: list[_Sel] = []
        while not self.is_("p", "}"):
            if not self.more():
                raise _GQLError("unterminated selection set")
            s = _Sel()
            if self.is_("p", "..."):
                self.next()
                s.inline = True
                if self.is_("n", "on"):
                    self.next()
                    s.on_type = self.name()
                elif self.is_("n"):
                    s.inline = False
                    s.spread = self.next().val
                    self.skip_directives()
                    sels.append(s)
                    continue
                self.skip_directives()
                s.sels = self.selection_set()
                sels.append(s)
                continue
            s.name = self.name()
            if self.is_("p", ":"):
                self.next()
                s.alias = s.name
                s.name = self.name()
            if self.is_("p", "("):
                s.args = self.arguments()
            self.skip_directives()
            if self.is_("p", "{"):
                s.sels = self.selection_set()
            sels.append(s)
        self.next()
        return sels

    def document(self) -> tuple[dict[str, _Op], dict[str, _Fragment]]:
        """Operations and fragments."""
        ops: dict[str, _Op] = {}
        frags: dict[str, _Fragment] = {}
        while self.more():
            if self.is_("p", "{"):
                sels = self.selection_set()
                if "" in ops:
                    raise _GQLError("two anonymous operations")
                ops[""] = _Op("query", {}, sels)
                continue
            kw = self.name()
            if kw == "fragment":
                n = self.name()
                self.expect("n", "on")
                on = self.name()
                self.skip_directives()
                frags[n] = _Fragment(on, self.selection_set())
                continue
            if kw not in ("query", "mutation", "subscription"):
                raise _GQLError(f"unexpected {go_quote(kw)} at {self.peek().pos}")
            op = _Op(kw)
            op_name = ""
            if self.is_("n"):
                op_name = self.next().val
            if self.is_("p", "("):
                self.next()
                while not self.is_("p", ")"):
                    v = self.expect("v")
                    self.expect("p", ":")
                    a = _Arg(self.type_ref())
                    if self.is_("p", "="):
                        self.next()
                        self.skip_value()
                        a.has_default = True
                    self.skip_directives()
                    op.vars[v.val] = a
                self.next()
            self.skip_directives()
            op.sels = self.selection_set()
            if op_name in ops:
                raise _GQLError(f"operation {go_quote(op_name)} defined twice")
            ops[op_name] = op
        if "" in ops and len(ops) > 1:
            raise _GQLError("an anonymous operation mixed with named ones")
        return ops, frags


# -- the schema ----------------------------------------------------------------------


def new_graphql(name: str, raw: bytes | str) -> GraphQL:
    """Parse an SDL schema. Raises SpecError."""
    try:
        toks = _lex(bytes(raw) if isinstance(raw, bytearray) else raw)
    except _GQLError as e:
        raise SpecError(f"{name}: {e}") from None
    g = GraphQL(name)
    try:
        g._parse(_Parser(toks))
    except _GQLError as e:
        raise SpecError(str(e)) from None
    return g


class GraphQL:
    """A GraphQL schema that validates POST bodies {"query": ..., "variables": ...}."""

    def __init__(self, name: str) -> None:
        self._name = name
        self.types: dict[str, _Type] = {s: _Type("SCALAR") for s in ("Int", "Float", "String", "Boolean", "ID")}
        self.roots = {"query": "Query", "mutation": "Mutation", "subscription": "Subscription"}

    def name(self) -> str:
        return self._name

    def _define(self, n: str, kind: str) -> _Type:
        t = self.types.get(n)
        if t is None or (t.kind == "SCALAR" and kind != "SCALAR"):
            t = _Type(kind)
            self.types[n] = t
        return t

    def _parse(self, p: _Parser) -> None:
        name = self._name
        while p.more():
            p.skip_description()
            if p.is_("n", "extend"):
                p.next()
            try:
                kw = p.name()
            except _GQLError as e:
                raise _GQLError(f"{name}: {e}") from None
            if kw == "schema":
                p.skip_directives()
                p.expect("p", "{")
                while not p.is_("p", "}"):
                    op = p.name()
                    p.expect("p", ":")
                    self.roots[op] = p.name()
                p.next()
            elif kw == "scalar":
                self._define(p.name(), "SCALAR")
                p.skip_directives()
            elif kw in ("type", "interface"):
                n = p.name()
                t = self._define(n, "INTERFACE" if kw == "interface" else "OBJECT")
                if p.is_("n", "implements"):
                    p.next()
                    if p.is_("p", "&"):
                        p.next()
                    while True:
                        p.name()
                        if not p.is_("p", "&"):
                            break
                        p.next()
                p.skip_directives()
                if p.is_("p", "{"):
                    try:
                        fields = p.field_defs(False)
                    except _GQLError as e:
                        raise _GQLError(f"{name}: type {n}: {e}") from None
                    t.fields.update(fields)
            elif kw == "input":
                n = p.name()
                t = self._define(n, "INPUT")
                p.skip_directives()
                if p.is_("p", "{"):
                    try:
                        fields = p.field_defs(True)
                    except _GQLError as e:
                        raise _GQLError(f"{name}: input {n}: {e}") from None
                    t.fields.update(fields)
            elif kw == "enum":
                t = self._define(p.name(), "ENUM")
                p.skip_directives()
                if p.is_("p", "{"):
                    p.next()
                    while not p.is_("p", "}"):
                        p.skip_description()
                        t.enum.add(p.name())
                        p.skip_directives()
                    p.next()
            elif kw == "union":
                t = self._define(p.name(), "UNION")
                p.skip_directives()
                if p.is_("p", "="):
                    p.next()
                    if p.is_("p", "|"):
                        p.next()
                    while True:
                        t.members.append(p.name())
                        if not p.is_("p", "|"):
                            break
                        p.next()
            elif kw == "directive":
                p.expect("p", "@")
                p.name()
                if p.is_("p", "("):
                    p.arg_defs()
                if p.is_("n", "repeatable"):
                    p.next()
                p.expect("n", "on")
                if p.is_("p", "|"):
                    p.next()
                while True:
                    p.name()
                    if not p.is_("p", "|"):
                        break
                    p.next()
            else:
                raise _GQLError(f"{name}: unexpected {go_quote(kw)} at {p.peek().pos}")

    # -- validation --

    def validate(self, r: SpecRequest, body: bytes) -> None:
        """Check a POST body {"query": ..., "variables": ...}."""
        name = self._name
        if r.method != "POST":
            raise SpecError(f"{name}: GraphQL takes POST, not {r.method}")
        try:
            query, operation_name, variables = _envelope(body)
        except ValueError as e:
            raise SpecError(f"{name}: body is not a GraphQL request: {e}") from None
        if query.strip() == "":
            raise SpecError(f"{name}: empty query")
        try:
            toks = _lex(query)
        except _GQLError as e:
            raise SpecError(f"{name}: {e}") from None
        try:
            ops, frags = _Parser(toks).document()
        except _GQLError as e:
            raise SpecError(f"{name}: query does not parse: {e}") from None
        if not ops:
            raise SpecError(f"{name}: no operation")
        if operation_name != "":
            op = ops.get(operation_name)
            if op is None:
                raise SpecError(f"{name}: operationName {go_quote(operation_name)} is not in the document")
        elif len(ops) == 1:
            op = next(iter(ops.values()))
        else:
            raise SpecError(f"{name}: {len(ops)} operations and no operationName")
        root = self.roots.get(op.kind, "")
        if root not in self.types:
            raise SpecError(f"{name}: the schema has no {op.kind} type")
        # Variables: declared ones typed, undeclared ones refused.
        for n, a in op.vars.items():
            if a.typ.base() not in self.types:
                raise SpecError(f"{name}: variable ${n} has unknown type {a.typ}")
            if n not in variables:
                if a.typ.non_null and not a.has_default:
                    raise SpecError(f"{name}: variable ${n}: {a.typ} is required but not given")
                continue
            try:
                self._check_json(variables[n], a.typ)
            except _GQLError as e:
                raise SpecError(f"{name}: variable ${n}: {e}") from None
        for n in variables:
            if n not in op.vars:
                raise SpecError(f"{name}: variable ${n} is not declared by the operation")
        v = _Validator(self, frags, op.vars)
        try:
            v.sels(root, op.sels, root)
        except _GQLError as e:
            raise SpecError(str(e)) from None

    def _check_json(self, v: Any, ref: _Ref) -> None:
        """Check a variable's JSON value against its declared type."""
        if v is None:
            if ref.non_null:
                raise _GQLError(f"null given for {ref}")
            return
        if ref.elem is not None:
            items = v if isinstance(v, list) else [v]
            for it in items:
                self._check_json(it, ref.elem)
            return
        t = self.types.get(ref.name)
        if t is None:
            raise _GQLError(f"unknown type {ref.name}")
        if t.kind == "ENUM":
            if not isinstance(v, str) or v not in t.enum:
                raise _GQLError(f"{_go_value(v)} is not a value of enum {ref.name}")
        elif t.kind == "INPUT":
            if not isinstance(v, dict):
                raise _GQLError(f"{ref.name} wants an object")
            for k, fv in v.items():
                f = t.fields.get(k)
                if f is None:
                    raise _GQLError(f"input {ref.name} has no field {k}")
                try:
                    self._check_json(fv, f.typ)
                except _GQLError as e:
                    raise _GQLError(f"{ref.name}.{k}: {e}") from None
            for k, f in t.fields.items():
                if k not in v and f.typ.non_null and "=" not in f.args:
                    raise _GQLError(f"input {ref.name} requires field {k}")
        elif t.kind == "SCALAR":
            if ref.name == "String":
                if not isinstance(v, str):
                    raise _GQLError(f"String wants a string, not {_go_type(v)}")
            elif ref.name == "ID":
                if not (isinstance(v, str) or _is_number(v)):
                    raise _GQLError(f"ID wants a string, not {_go_type(v)}")
            elif ref.name in ("Int", "Float"):
                if not _is_number(v):
                    raise _GQLError(f"{ref.name} wants a number, not {_go_type(v)}")
            elif ref.name == "Boolean":
                if not isinstance(v, bool):
                    raise _GQLError(f"Boolean wants true or false, not {_go_type(v)}")
        else:
            raise _GQLError(f"{t.kind.lower()} {ref.name} is not an input type")


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _go_type(v: Any) -> str:
    """Go's %T for a value json.Unmarshal put in an `any`."""
    if isinstance(v, bool):
        return "bool"
    if _is_number(v):
        return "float64"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "[]interface {}"
    if isinstance(v, dict):
        return "map[string]interface {}"
    return "<nil>"


def _go_value(v: Any) -> str:
    """Go's %v for a value json.Unmarshal put in an `any`."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e21:
        return str(int(v))
    if isinstance(v, list):
        return "[" + " ".join(_go_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "map[" + " ".join(f"{k}:{_go_value(v[k])}" for k in sorted(v)) + "]"
    return str(v)


def _envelope(body: bytes) -> tuple[str, str, dict[str, Any]]:
    """json.Unmarshal into struct{Query, OperationName string; Variables
    map[string]any}: keys match case-insensitively, a later key wins, null
    leaves a field zero and a mistyped field is an error."""
    v = go_json(body)
    if v is None:
        return "", "", {}
    if not isinstance(v, dict):
        raise ValueError(f"json: cannot unmarshal {go_json_kind(v)} into Go value of type struct")
    query, operation_name, variables = "", "", {}
    for k, val in v.items():
        key = k.lower()
        if key in ("query", "operationname"):
            if val is None:
                continue
            if not isinstance(val, str):
                raise ValueError(f"json: cannot unmarshal {go_json_kind(val)} into Go struct field .{k} of type string")
            if key == "query":
                query = val
            else:
                operation_name = val
        elif key == "variables":
            if val is None:
                continue
            if not isinstance(val, dict):
                raise ValueError(f"json: cannot unmarshal {go_json_kind(val)} into Go struct field .{k} of type map[string]interface {{}}")
            variables = val
    return query, operation_name, variables


class _Validator:
    def __init__(self, g: GraphQL, frags: dict[str, _Fragment], vars: dict[str, _Arg]) -> None:
        self.g = g
        self.frags = frags
        self.vars = vars

    def sels(self, type_name: str, sels: list[_Sel], path: str) -> None:
        t = self.g.types.get(type_name)
        if t is None:
            raise _GQLError(f"{path}: unknown type {type_name}")
        for s in sels:
            if s.spread != "":
                f = self.frags.get(s.spread)
                if f is None:
                    raise _GQLError(f"{path}: fragment {s.spread} is not defined")
                self.sels(f.on, f.sels, path + "/..." + s.spread)
            elif s.inline:
                on = s.on_type if s.on_type != "" else type_name
                self.sels(on, s.sels, path + "/... on " + on)
            elif s.name == "__typename":
                pass
            else:
                if t.kind not in ("OBJECT", "INTERFACE"):
                    raise _GQLError(f"{path}: field {s.name} selected on {t.kind.lower()} {type_name}")
                fd = t.fields.get(s.name)
                if fd is None:
                    raise _GQLError(f"{path}: {type_name} has no field {s.name}")
                for n, val in s.args.items():
                    a = fd.args.get(n)
                    if a is None:
                        raise _GQLError(f"{path}: {type_name}.{s.name} takes no argument {n}")
                    try:
                        self.value(val, a.typ)
                    except _GQLError as e:
                        raise _GQLError(f"{path}: {type_name}.{s.name}({n}): {e}") from None
                for n, a in fd.args.items():
                    if n not in s.args and a.typ.non_null and not a.has_default:
                        raise _GQLError(f"{path}: {type_name}.{s.name} requires argument {n}")
                ft = self.g.types.get(fd.typ.base())
                if ft is None:
                    raise _GQLError(f"{path}: {type_name}.{s.name} has unknown type {fd.typ}")
                composite = ft.kind in ("OBJECT", "INTERFACE", "UNION")
                if composite and not s.sels:
                    raise _GQLError(f"{path}: {type_name}.{s.name} ({fd.typ}) needs a selection set")
                if not composite and s.sels:
                    raise _GQLError(f"{path}: {type_name}.{s.name} ({fd.typ}) takes no selection set")
                if composite:
                    self.sels(fd.typ.base(), s.sels, path + "/" + s.name)

    def value(self, val: _Value, ref: _Ref) -> None:
        """Check a literal argument against its type."""
        if val.kind == "v":
            decl = self.vars.get(val.val)
            if decl is None:
                raise _GQLError(f"variable ${val.val} is not declared")
            # A single value coerces to a list of one; a list never
            # coerces to a single value.
            if decl.typ.base() != ref.base() or (decl.typ.elem is not None and ref.elem is None):
                raise _GQLError(f"variable ${val.val} is {decl.typ}, argument wants {ref}")
            if ref.non_null and not decl.typ.non_null and not decl.has_default:
                raise _GQLError(f"variable ${val.val} ({decl.typ}) may be null, argument wants {ref}")
            return
        if val.kind == "n" and val.val == "null":
            if ref.non_null:
                raise _GQLError(f"null given for {ref}")
            return
        if ref.elem is not None:
            items = val.items if val.kind == "l" else [val]
            for it in items:
                self.value(it, ref.elem)
            return
        t = self.g.types.get(ref.name)
        if t is None:
            raise _GQLError(f"unknown type {ref.name}")
        if t.kind == "ENUM":
            if val.kind != "n" or val.val not in t.enum:
                raise _GQLError(f"{go_quote(val.val)} is not a value of enum {ref.name}")
        elif t.kind == "INPUT":
            if val.kind != "o":
                raise _GQLError(f"{ref.name} wants an object")
            for k in val.obj_order:
                f = t.fields.get(k)
                if f is None:
                    raise _GQLError(f"input {ref.name} has no field {k}")
                try:
                    self.value(val.obj[k], f.typ)
                except _GQLError as e:
                    raise _GQLError(f"{ref.name}.{k}: {e}") from None
            for k, f in t.fields.items():
                if k not in val.obj and f.typ.non_null and "=" not in f.args:
                    raise _GQLError(f"input {ref.name} requires field {k}")
        elif t.kind == "SCALAR":
            _scalar_literal(ref.name, val)
        else:
            raise _GQLError(f"{t.kind.lower()} {ref.name} is not an input type")


def _scalar_literal(name: str, val: _Value) -> None:
    if name in ("String", "ID"):
        if val.kind != "s" and not (name == "ID" and val.kind == "d"):
            raise _GQLError(f"{name} wants a string")
    elif name in ("Int", "Float"):
        if val.kind != "d":
            raise _GQLError(f"{name} wants a number")
    elif name == "Boolean":
        if val.kind != "n" or val.val not in ("true", "false"):
            raise _GQLError("Boolean wants true or false")
