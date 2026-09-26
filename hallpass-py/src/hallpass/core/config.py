"""Load and strictly validate the hallpass YAML file.

The file is one flat list of connections. Every key is a scalar string.
Unknown keys, inline secrets and dangling connection references are
reported with file:line, all of them in one pass.
"""

from __future__ import annotations

import collections
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import yaml

from hallpass.core import secret as secretmod
from hallpass.core.duration import parse_duration_ns
from hallpass.core.errors import go_quote, path_error_text
from hallpass.core.integration import COMMON_FIELDS, Integration, Registry, Settings
from hallpass.core.secret import Secret

__all__ = [
    "DEFAULT_DECISION_CACHE",
    "DEFAULT_DECISION_LOG",
    "DEFAULT_IDENTITY_CACHE",
    "DEFAULT_LISTEN",
    "Config",
    "ConfigError",
    "ConfigErrors",
    "from_mapping",
    "load",
    "parse",
]

DEFAULT_LISTEN = ":8080"
DEFAULT_DECISION_CACHE = 30.0
DEFAULT_IDENTITY_CACHE = 15 * 60.0
DEFAULT_DECISION_LOG = "stderr"

_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


@dataclass
class Config:
    # The address for serve.
    listen: str = DEFAULT_LISTEN
    # The key callers must present as a bearer token.
    api_key: Secret = field(default_factory=Secret)
    # A file path, "stderr", "stdout" or "none".
    decision_log: str = DEFAULT_DECISION_LOG
    # How long allow/deny answers are reused (0 disables), in seconds.
    decision_cache: float = DEFAULT_DECISION_CACHE
    # How long resolved identities are reused, in seconds.
    identity_cache: float = DEFAULT_IDENTITY_CACHE
    # Connections in dependency order.
    connections: list[Settings] = field(default_factory=list)
    # Connection id to its integration.
    integrations: dict[str, Integration] = field(default_factory=dict)


class ConfigError(ValueError):
    """A validation problem with a location."""

    def __init__(self, file: str, line: int, msg: str) -> None:
        self.file = file
        self.line = line
        self.msg = msg
        super().__init__(str(self))

    def __str__(self) -> str:
        if self.line > 0:
            return f"{self.file}:{self.line}: {self.msg}"
        return f"{self.file}: {self.msg}"


class ConfigErrors(ValueError):
    """Every problem found, so the owner fixes them in one pass."""

    def __init__(self, errors: list[ConfigError]) -> None:
        self.errors = errors
        super().__init__("\n".join(str(e) for e in errors))


# The YAML layer mirrors gopkg.in/yaml.v3 decoding into a yaml.Node: the
# events come from libyaml (the C library yaml.v3 is a port of) through
# PyYAML's CParser when it is built in, so syntax errors carry the same text
# and line; a node records its kind, the line of its first event, its raw
# value and whether its tag is !!null. Aliases are never expanded: an alias
# is not a single value, so it is rejected like a list, and no alias bomb
# can blow up the loader.

_SCALAR, _MAPPING, _SEQUENCE, _ALIAS = "scalar", "mapping", "sequence", "alias"
_YAML_NULLS = frozenset({"", "~", "null", "Null", "NULL"})
_NULL_TAGS = frozenset({"!!null", "tag:yaml.org,2002:null"})


class _Node:
    """A yaml.v3 Node, reduced to what the loader reads."""

    __slots__ = ("items", "kind", "line", "null", "value")

    def __init__(self, kind: str, line: int, value: str = "", null: bool = False) -> None:
        self.kind = kind
        # 1-based, like yaml.Node.Line.
        self.line = line
        # A scalar's text, or an alias's anchor name (yaml.v3's Node.Value).
        self.value = value
        self.null = null
        # A mapping's (key, value) pairs or a sequence's items.
        self.items: list[Any] = []


class _YAMLFailure(Exception):
    """A failure yaml.v3 raises itself, outside libyaml."""

    def __init__(self, msg: str, mark: Any) -> None:
        super().__init__(msg)
        self.mark = mark


def _event_parser(data: bytes | str) -> Any:
    if getattr(yaml, "__with_libyaml__", False):
        from yaml.cyaml import CParser

        return CParser(data)

    class _PyParser(yaml.reader.Reader, yaml.scanner.Scanner, yaml.parser.Parser):  # type: ignore[misc]
        def __init__(self, stream: Any) -> None:
            yaml.reader.Reader.__init__(self, stream)
            yaml.scanner.Scanner.__init__(self)
            yaml.parser.Parser.__init__(self)

    return _PyParser(data)


class _Composer:
    """yaml.v3's parser: first document only, anchors may be redefined,
    an alias to an unknown anchor fails the whole file."""

    def __init__(self, data: bytes | str, parser: Any = None) -> None:
        self.data = data
        self.p = parser if parser is not None else _event_parser(data)
        self.anchors: set[str] = set()

    def document(self) -> _Node | None:
        p = self.p
        p.get_event()  # StreamStartEvent
        if p.check_event(yaml.StreamEndEvent):
            return None
        start = p.get_event()  # DocumentStartEvent
        version = getattr(start, "version", None)
        if version is not None and tuple(version) != (1, 1):
            # yaml.v3 reads YAML 1.1 only; libyaml also takes %YAML 1.2.
            raise yaml.parser.ParserError(None, None, "found incompatible YAML document", _directive_mark(self.data))
        node = self.node()
        p.get_event()  # DocumentEndEvent
        return node

    def node(self) -> _Node:
        p = self.p
        ev = p.get_event()
        line = int(ev.start_mark.line) + 1
        if isinstance(ev, yaml.AliasEvent):
            if ev.anchor not in self.anchors:
                raise _YAMLFailure(f"unknown anchor '{ev.anchor}' referenced", ev.start_mark)
            return _Node(_ALIAS, line, str(ev.anchor))
        if ev.anchor is not None:
            self.anchors.add(ev.anchor)
        if isinstance(ev, yaml.ScalarEvent):
            return _Node(_SCALAR, line, str(ev.value), _scalar_is_null(ev))
        if isinstance(ev, yaml.SequenceStartEvent):
            n = _Node(_SEQUENCE, line)
            while not p.check_event(yaml.SequenceEndEvent):
                n.items.append(self.node())
            p.get_event()
            return n
        if isinstance(ev, yaml.MappingStartEvent):
            n = _Node(_MAPPING, line)
            while not p.check_event(yaml.MappingEndEvent):
                k = self.node()
                n.items.append((k, self.node()))
            p.get_event()
            return n
        raise _YAMLFailure(f"unexpected event {type(ev).__name__}")  # pragma: no cover


def _directive_mark(data: bytes | str) -> Any:
    """Where the %YAML directive is: yaml.v3 reports its line."""
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    index = 0
    for i, line in enumerate(text.split("\n")):
        if line.startswith("%YAML"):
            return yaml.error.Mark("", index, i, 0, None, None)
        index += len(line) + 1
    return None


def _scalar_is_null(ev: Any) -> bool:
    """yaml.v3's tag for a scalar is !!null: an explicit !!null tag, or no
    tag (or the non-specific "!") on a plain scalar that resolves to null.
    A quoted or block scalar is a string."""
    tag = ev.tag
    if tag is not None and tag != "!":
        return tag in _NULL_TAGS
    return ev.style in (None, "") and ev.value in _YAML_NULLS


def _compose(data: bytes | str) -> _Node | None:
    c = _Composer(data)
    err: Exception | None = None
    doc: _Node | None = None
    try:
        doc = c.document()
    except (yaml.YAMLError, _YAMLFailure) as e:
        err = e
    finally:
        _dispose(c.p)
    # yaml.v3's scanner keeps two tokens more in hand than libyaml's (for
    # comments), so it can meet a scanner error before the point where
    # libyaml's parser fails or finishes; that error is what it reports.
    early = _lookahead_scanner_error(data)
    if early is not None:
        raise early
    if err is not None:
        raise err
    return doc


def _dispose(p: Any) -> None:
    dispose = getattr(p, "dispose", None)
    if dispose is not None:
        dispose()


class _LookaheadParser(yaml.parser.Parser):  # type: ignore[misc]
    """libyaml's parser state machine (PyYAML's port of it) fed by libyaml's
    scanner the way yaml.v3 feeds its parser: whenever the parser looks at a
    token, the scanner has produced that token and two more."""

    def __init__(self, data: bytes | str) -> None:
        from yaml.cyaml import CParser

        self._scanner = CParser(data)
        self._buf: collections.deque[Any] = collections.deque()
        self._done = False
        yaml.parser.Parser.__init__(self)

    def _fill(self) -> None:
        while not self._done and len(self._buf) < 3:
            tok = self._scanner.get_token()
            if tok is None or isinstance(tok, yaml.StreamEndToken):
                self._done = True
            if tok is not None:
                self._buf.append(tok)

    def check_token(self, *choices: Any) -> bool:
        self._fill()
        if not self._buf:
            return False
        return not choices or isinstance(self._buf[0], choices)

    def peek_token(self) -> Any:
        self._fill()
        return self._buf[0] if self._buf else None

    def get_token(self) -> Any:
        self._fill()
        return self._buf.popleft() if self._buf else None


def _lookahead_scanner_error(data: bytes | str) -> Exception | None:
    """The scanner (or reader) error yaml.v3 would meet while parsing the
    first document, if any. Needs libyaml, whose messages yaml.v3 shares."""
    if not getattr(yaml, "__with_libyaml__", False):
        return None
    c = _Composer(data, _LookaheadParser(data))
    try:
        c.document()
    except (yaml.scanner.ScannerError, yaml.reader.ReaderError) as e:
        return e
    except (yaml.YAMLError, _YAMLFailure):
        return None
    return None


def _yaml_msg(e: Exception) -> str:
    """The text yaml.v3 gives a syntax error ("yaml: line 3: did not find
    expected key"), including its choice of line: the context mark's
    0-based line when it is not 0, else the problem mark's, one more for
    a scanner error, and no line at all when both are 0."""
    if isinstance(e, _YAMLFailure):
        return f"yaml: {e}"
    if isinstance(e, yaml.reader.ReaderError):
        return f"yaml: {e.reason}"
    problem = getattr(e, "problem", None) or "unknown problem parsing YAML content"
    bump = 1 if isinstance(e, yaml.scanner.ScannerError) else 0
    line = 0
    for mark in (getattr(e, "context_mark", None), getattr(e, "problem_mark", None)):
        if mark is not None and mark.line != 0:
            line = int(mark.line) + bump
            break
    where = f"line {line}: " if line else ""
    return f"yaml: {where}{problem}"


def _line(n: _Node | None) -> int:
    return 0 if n is None else n.line


def load(path: str, reg: Registry, *, require_api_key: bool = True) -> Config:
    """Read and validate the file at path against the registry."""
    with open(path, "rb") as f:
        data = f.read()
    return parse(path, data, reg, require_api_key=require_api_key)


def parse(name: str, data: bytes | str, reg: Registry, *, require_api_key: bool = True) -> Config:
    """Validate YAML data. name is used in error messages.

    require_api_key is False for the in-process engine, which serves no
    HTTP and so needs no key; everything else is validated the same."""
    try:
        doc = _compose(data)
    except (yaml.YAMLError, _YAMLFailure) as e:
        raise ConfigError(name, 0, _yaml_msg(e)) from None
    if doc is None:
        raise ConfigError(name, 0, "file is empty")
    ld = _Loader_(name, reg, require_api_key)
    ld.top(doc)
    if ld.errs:
        raise ConfigErrors(ld.errs)
    return ld.cfg


class _Loader_:
    def __init__(self, file: str, reg: Registry, require_api_key: bool = True) -> None:
        self.require_api_key = require_api_key
        self.file = file
        self.reg = reg
        self.cfg = Config()
        self.errs: list[ConfigError] = []

    def errf(self, n: _Node | None, msg: str) -> None:
        self.errs.append(ConfigError(self.file, _line(n), msg))

    def top(self, n: _Node) -> None:
        if n.kind != _MAPPING:
            self.errf(n, "top level must be a mapping")
            return
        seen_connections = False
        seen: dict[str, _Node] = {}
        for k, v in n.items:
            key = k.value
            if key in seen:
                self.errf(k, f"key {go_quote(key)} repeated (first set at line {_line(seen[key])})")
                continue
            seen[key] = k
            if key == "api_key":
                s = self.scalar(v, "api_key")
                if s is not None:
                    try:
                        self.cfg.api_key = secretmod.parse(s)
                    except secretmod.SecretError as e:
                        self.errf(v, f"api_key: {e}")
            elif key == "listen":
                s = self.scalar(v, "listen")
                if s is not None:
                    self.cfg.listen = s
            elif key == "decision_log":
                s = self.scalar(v, "decision_log")
                if s is not None:
                    self.cfg.decision_log = s
            elif key == "decision_cache_seconds":
                s = self.scalar(v, key)
                if s is not None:
                    self.cfg.decision_cache = self.seconds(v, s, 0, 3600)
            elif key == "identity_cache_seconds":
                s = self.scalar(v, key)
                if s is not None:
                    self.cfg.identity_cache = self.seconds(v, s, 0, 24 * 3600)
            elif key == "connections":
                seen_connections = True
                self.connections(v)
            else:
                self.errf(
                    k,
                    f"unknown key {go_quote(key)} (known: api_key, listen, decision_log, decision_cache_seconds, identity_cache_seconds, connections)",
                )
        if self.cfg.api_key.is_zero() and self.require_api_key:
            self.errf(n, "api_key is required (env:NAME or file:/path)")
        if not seen_connections:
            self.errf(n, "connections is required")

    def seconds(self, n: _Node, s: str, lo: int, hi: int) -> float:
        v = _atoi(s)
        if v is None or v < lo or v > hi:
            self.errf(n, f"must be a whole number of seconds between {lo} and {hi}")
            return 0.0
        return float(v)

    def scalar(self, n: _Node, key: str) -> str | None:
        if n.kind != _SCALAR:
            self.errf(n, f"{key} must be a single value, not a list or mapping")
            return None
        if n.null:
            self.errf(n, f"{key} is empty")
            return None
        return n.value

    def connections(self, n: _Node) -> None:
        if n.kind != _SEQUENCE:
            self.errf(n, "connections must be a list")
            return
        ids: dict[str, _Node] = {}
        pending: list[tuple[Settings, _Node, dict[str, str]]] = []
        for item in n.items:
            if item.kind != _MAPPING:
                self.errf(item, "each connection must be a mapping")
                continue
            raw: dict[str, _Node] = {}
            for k, v in item.items:
                key = k.value
                if key in raw:
                    self.errf(k, f"key {go_quote(key)} repeated")
                    continue
                raw[key] = v
            id_node = raw.get("id")
            if id_node is None:
                self.errf(item, "connection has no id")
                continue
            cid = self.scalar(id_node, "id")
            if cid is None:
                continue
            if not _ID_RE.fullmatch(cid):
                self.errf(id_node, f"id {go_quote(cid)} must match ^[a-z0-9][a-z0-9-]{{0,63}}$")
                continue
            if cid in ids:
                self.errf(id_node, f"id {go_quote(cid)} already used at line {_line(ids[cid])}")
                continue
            ids[cid] = id_node
            int_node = raw.get("integration")
            if int_node is None:
                self.errf(item, f"connection {go_quote(cid)} has no integration")
                continue
            int_name = self.scalar(int_node, "integration")
            if int_name is None:
                continue
            integ = self.reg.lookup(int_name)
            if integ is None:
                self.errf(int_node, f"connection {go_quote(cid)}: unknown integration {go_quote(int_name)} (known: {', '.join(self.reg.names())})")
                continue
            res = self.connection(cid, integ, raw)
            if res is None:
                continue
            s, refs = res
            pending.append((s, item, refs))
        _resolve(self, pending)

    def connection(self, cid: str, integ: Integration, raw: Mapping[str, _Node]) -> tuple[Settings, dict[str, str]] | None:
        """Validate one mapping against the integration's fields."""
        fields = {f.name: f for f in integ.fields()}
        values: dict[str, str] = {}
        secrets: dict[str, Secret] = {}
        refs: dict[str, str] = {}
        common: dict[str, Any] = {"ca_file": "", "tls_server_name": "", "proxy_url": "", "timeout": 0.0}
        q = go_quote(cid)
        ok = True
        for key, node in raw.items():
            if key in ("id", "integration"):
                continue
            val = self.scalar(node, key)
            if val is None:
                ok = False
                continue
            if key in COMMON_FIELDS:
                err = _common(key, val, common)
                if err:
                    self.errf(node, f"connection {q}: {err}")
                    ok = False
                continue
            f = fields.get(key)
            if f is None:
                self.errf(node, f"connection {q}: integration {integ.name()} does not accept key {go_quote(key)} (accepted: {_accepted_keys(integ)})")
                ok = False
                continue
            if f.secret:
                try:
                    secrets[key] = secretmod.parse(val)
                except secretmod.SecretError as e:
                    self.errf(node, f"connection {q}: {key}: {e}")
                    ok = False
                continue
            if val == "":
                self.errf(node, f"connection {q}: {key} is empty")
                ok = False
                continue
            if f.enum and val not in f.enum:
                self.errf(node, f"connection {q}: {key} must be one of {', '.join(f.enum)}")
                ok = False
                continue
            if f.validate is not None:
                try:
                    f.validate(val)
                except ValueError as e:
                    self.errf(node, f"connection {q}: {key}: {e}")
                    ok = False
                    continue
            if f.ref:
                refs[key] = f.ref
            values[key] = val
        for f in integ.fields():
            present = f.name in raw
            if f.required and not present:
                self.errf(raw.get("id"), f"connection {q}: {integ.name()} requires {f.name}")
                ok = False
            if not present and f.default:
                values[f.name] = f.default
        if not ok:
            return None
        return Settings(cid, integ.name(), values, secrets, **common), refs


def _common(key: str, val: str, out: dict[str, Any]) -> str:
    """Validate one common transport key into out; return an error or ""."""
    err = ""
    if key == "ca_file":
        try:
            os.stat(val)
        except (OSError, ValueError) as e:
            err = "ca_file: " + path_error_text("stat", val, e)
        out["ca_file"] = val
    elif key == "tls_server_name":
        out["tls_server_name"] = val
    elif key == "proxy_url":
        if not (val.startswith("http://") or val.startswith("https://")):
            err = "proxy_url must start with http:// or https://"
        out["proxy_url"] = val
    elif key == "timeout":
        try:
            ns = parse_duration_ns(val)
        except ValueError:
            ns = -1
        if ns <= 0 or ns > 5 * 60 * 1_000_000_000:
            err = "timeout must be a duration such as 10s, up to 5m"
        out["timeout"] = max(ns, 0) / 1e9
    return err


def _resolve(ld: _Loader_, pending: list[tuple[Settings, _Node, dict[str, str]]]) -> None:
    """Resolve references and order connections so dependencies come first."""
    by_id = {s.id: (s, node, refs) for s, node, refs in pending}
    for s, node, refs in pending:
        for fld, want in refs.items():
            target = s.get(fld)
            tp = by_id.get(target)
            if tp is None:
                ld.errf(node, f"connection {go_quote(s.id)}: {fld} refers to unknown connection {go_quote(target)}")
                continue
            if tp[0].integration != want:
                ld.errf(node, f"connection {go_quote(s.id)}: {fld} must name a {want} connection, but {go_quote(target)} is {tp[0].integration}")
            if target == s.id:
                ld.errf(node, f"connection {go_quote(s.id)}: {fld} refers to itself")
    if ld.errs:
        return
    state: dict[str, int] = {}
    order: list[Settings] = []

    def visit(p: tuple[Settings, _Node, dict[str, str]]) -> bool:
        s, node, refs = p
        st = state.get(s.id, 0)
        if st == 1:
            ld.errf(node, f"connection {go_quote(s.id)}: reference cycle")
            return False
        if st == 2:
            return True
        state[s.id] = 1
        for fld in sorted(refs):
            if not visit(by_id[s.get(fld)]):
                return False
        state[s.id] = 2
        order.append(s)
        return True

    for p in pending:
        visit(p)
    ld.cfg.connections = order
    for s, _, _ in pending:
        integ = ld.reg.lookup(s.integration)
        if integ is not None:
            ld.cfg.integrations[s.id] = integ


def _accepted_keys(i: Integration) -> str:
    ks = ["ca_file", "tls_server_name", "proxy_url", "timeout"]
    ks.extend(f.name for f in i.fields())
    return ", ".join(sorted(ks))


def _atoi(s: str) -> int | None:
    """Go's strconv.Atoi: an optional sign and decimal digits only."""
    if not re.fullmatch(r"[+-]?[0-9]+", s):
        return None
    return int(s)


def from_mapping(doc: Mapping[str, Any], reg: Registry, name: str = "<config>", *, require_api_key: bool = True) -> Config:
    """Validate a config given as Python data (connections configured in
    code) with exactly the rules of the file. Values are rendered to YAML
    and loaded, so a dict and a file can never be validated differently.
    Secret fields may be given as Secret objects (literal, env or file);
    they are applied after validation."""
    plain: dict[str, Any] = {}
    in_code: dict[tuple[int, str], Secret] = {}
    for k, v in doc.items():
        if k == "connections" and isinstance(v, (list, tuple)):
            conns = []
            for i, c in enumerate(v):
                if isinstance(c, Mapping):
                    cc: dict[str, Any] = {}
                    for ck, cv in c.items():
                        if isinstance(cv, Secret):
                            in_code[(i, str(ck))] = cv
                            cc[ck] = "env:HALLPASS_IN_CODE_SECRET"
                        else:
                            cc[ck] = cv
                    conns.append(cc)
                else:
                    conns.append(c)
            plain[k] = conns
        elif k == "api_key" and isinstance(v, Secret):
            plain[k] = "env:HALLPASS_IN_CODE_SECRET"
            in_code[(-1, "api_key")] = v
        else:
            plain[k] = v
    text = yaml.safe_dump(_stringify(plain), sort_keys=False, allow_unicode=True)
    cfg = parse(name, text, reg, require_api_key=require_api_key)
    if in_code:
        by_index = _connection_indexes(plain.get("connections"))
        for (i, key), sec in in_code.items():
            if i < 0:
                cfg.api_key = sec
                continue
            cid = by_index.get(i)
            for s in cfg.connections:
                if s.id == cid:
                    s._secrets[key] = sec
    return cfg


def _connection_indexes(conns: Any) -> dict[int, str]:
    out: dict[int, str] = {}
    if isinstance(conns, list):
        for i, c in enumerate(conns):
            if isinstance(c, Mapping) and isinstance(c.get("id"), str):
                out[i] = c["id"]
    return out


def _stringify(v: Any) -> Any:
    """Scalars as the strings the file would carry (true, 30, 10s)."""
    if isinstance(v, Mapping):
        return {str(k): _stringify(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_stringify(x) for x in v]
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return str(v)
    return v
