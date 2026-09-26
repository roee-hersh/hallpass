"""Load and strictly validate the hallpass YAML file.

The file is one flat list of connections. Every key is a scalar string.
Unknown keys, inline secrets and dangling connection references are
reported with file:line, all of them in one pass.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import yaml
from yaml.composer import Composer
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from hallpass.core import secret as secretmod
from hallpass.core.duration import parse_duration
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
_NULL_TAG = "tag:yaml.org,2002:null"


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


class _AliasNode(Node):
    """An alias kept as such: an alias is not a single value, so it is
    rejected like a list, and no alias expansion can blow up the loader."""

    id = "alias"


class _Composer(Composer):
    def compose_node(self, parent: Any, index: Any) -> Any:  # type: ignore[override]
        if self.check_event(AliasEvent):
            event = self.get_event()
            return _AliasNode("alias", event.anchor, event.start_mark, event.end_mark)
        return super().compose_node(parent, index)


class _Loader(yaml.reader.Reader, yaml.scanner.Scanner, yaml.parser.Parser, _Composer, yaml.resolver.Resolver):  # type: ignore[misc]
    def __init__(self, stream: Any) -> None:
        yaml.reader.Reader.__init__(self, stream)
        yaml.scanner.Scanner.__init__(self)
        yaml.parser.Parser.__init__(self)
        _Composer.__init__(self)
        yaml.resolver.Resolver.__init__(self)


def _line(n: Node | None) -> int:
    if n is None:
        return 0
    return int(n.start_mark.line) + 1


def load(path: str, reg: Registry, *, require_api_key: bool = True) -> Config:
    """Read and validate the file at path against the registry."""
    with open(path, "rb") as f:
        data = f.read()
    return parse(path, data, reg, require_api_key=require_api_key)


def parse(name: str, data: bytes | str, reg: Registry, *, require_api_key: bool = True) -> Config:
    """Validate YAML data. name is used in error messages.

    require_api_key is False for the in-process engine, which serves no
    HTTP and so needs no key; everything else is validated the same."""
    loader = _Loader(data)
    try:
        # Only the first document counts, as the original loader read it.
        doc = loader.get_node() if loader.check_node() else None
    except yaml.YAMLError as e:
        raise ConfigError(name, 0, _yaml_msg(e)) from None
    finally:
        loader.dispose()
    if doc is None:
        raise ConfigError(name, 0, "file is empty")
    ld = _Loader_(name, reg, require_api_key)
    ld.top(doc)
    if ld.errs:
        raise ConfigErrors(ld.errs)
    return ld.cfg


def _yaml_msg(e: yaml.YAMLError) -> str:
    mark = getattr(e, "problem_mark", None)
    problem = getattr(e, "problem", None) or str(e)
    if mark is not None:
        return f"yaml: line {mark.line + 1}: {problem}"
    return f"yaml: {problem}"


class _Loader_:
    def __init__(self, file: str, reg: Registry, require_api_key: bool = True) -> None:
        self.require_api_key = require_api_key
        self.file = file
        self.reg = reg
        self.cfg = Config()
        self.errs: list[ConfigError] = []

    def errf(self, n: Node | None, msg: str) -> None:
        self.errs.append(ConfigError(self.file, _line(n), msg))

    def top(self, n: Node) -> None:
        if not isinstance(n, MappingNode):
            self.errf(n, "top level must be a mapping")
            return
        seen_connections = False
        seen: dict[str, Node] = {}
        for k, v in n.value:
            key = k.value if isinstance(k, ScalarNode) else ""
            if key in seen:
                self.errf(k, f'key "{key}" repeated (first set at line {_line(seen[key])})')
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
                    f'unknown key "{key}" (known: api_key, listen, decision_log, decision_cache_seconds, identity_cache_seconds, connections)',
                )
        if self.cfg.api_key.is_zero() and self.require_api_key:
            self.errf(n, "api_key is required (env:NAME or file:/path)")
        if not seen_connections:
            self.errf(n, "connections is required")

    def seconds(self, n: Node, s: str, lo: int, hi: int) -> float:
        v = _atoi(s)
        if v is None or v < lo or v > hi:
            self.errf(n, f"must be a whole number of seconds between {lo} and {hi}")
            return 0.0
        return float(v)

    def scalar(self, n: Node, key: str) -> str | None:
        if not isinstance(n, ScalarNode):
            self.errf(n, f"{key} must be a single value, not a list or mapping")
            return None
        if n.tag == _NULL_TAG:
            self.errf(n, f"{key} is empty")
            return None
        return str(n.value)

    def connections(self, n: Node) -> None:
        if not isinstance(n, SequenceNode):
            self.errf(n, "connections must be a list")
            return
        ids: dict[str, Node] = {}
        pending: list[tuple[Settings, Node, dict[str, str]]] = []
        for item in n.value:
            if not isinstance(item, MappingNode):
                self.errf(item, "each connection must be a mapping")
                continue
            raw: dict[str, Node] = {}
            for k, v in item.value:
                key = k.value if isinstance(k, ScalarNode) else ""
                if key in raw:
                    self.errf(k, f'key "{key}" repeated')
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
                self.errf(id_node, f'id "{cid}" must match ^[a-z0-9][a-z0-9-]{{0,63}}$')
                continue
            if cid in ids:
                self.errf(id_node, f'id "{cid}" already used at line {_line(ids[cid])}')
                continue
            ids[cid] = id_node
            int_node = raw.get("integration")
            if int_node is None:
                self.errf(item, f'connection "{cid}" has no integration')
                continue
            int_name = self.scalar(int_node, "integration")
            if int_name is None:
                continue
            integ = self.reg.lookup(int_name)
            if integ is None:
                self.errf(int_node, f'connection "{cid}": unknown integration "{int_name}" (known: {", ".join(self.reg.names())})')
                continue
            res = self.connection(cid, integ, raw)
            if res is None:
                continue
            s, refs = res
            pending.append((s, item, refs))
        _resolve(self, pending)

    def connection(self, cid: str, integ: Integration, raw: Mapping[str, Node]) -> tuple[Settings, dict[str, str]] | None:
        """Validate one mapping against the integration's fields."""
        fields = {f.name: f for f in integ.fields()}
        values: dict[str, str] = {}
        secrets: dict[str, Secret] = {}
        refs: dict[str, str] = {}
        common: dict[str, Any] = {"ca_file": "", "tls_server_name": "", "proxy_url": "", "timeout": 0.0}
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
                    self.errf(node, f'connection "{cid}": {err}')
                    ok = False
                continue
            f = fields.get(key)
            if f is None:
                self.errf(node, f'connection "{cid}": integration {integ.name()} does not accept key "{key}" (accepted: {_accepted_keys(integ)})')
                ok = False
                continue
            if f.secret:
                try:
                    secrets[key] = secretmod.parse(val)
                except secretmod.SecretError as e:
                    self.errf(node, f'connection "{cid}": {key}: {e}')
                    ok = False
                continue
            if val == "":
                self.errf(node, f'connection "{cid}": {key} is empty')
                ok = False
                continue
            if f.enum and val not in f.enum:
                self.errf(node, f'connection "{cid}": {key} must be one of {", ".join(f.enum)}')
                ok = False
                continue
            if f.validate is not None:
                try:
                    f.validate(val)
                except ValueError as e:
                    self.errf(node, f'connection "{cid}": {key}: {e}')
                    ok = False
                    continue
            if f.ref:
                refs[key] = f.ref
            values[key] = val
        for f in integ.fields():
            present = f.name in raw
            if f.required and not present:
                self.errf(raw.get("id"), f'connection "{cid}": {integ.name()} requires {f.name}')
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
        if not os.path.exists(val):
            err = f"ca_file: stat {val}: no such file or directory"
        out["ca_file"] = val
    elif key == "tls_server_name":
        out["tls_server_name"] = val
    elif key == "proxy_url":
        if not (val.startswith("http://") or val.startswith("https://")):
            err = "proxy_url must start with http:// or https://"
        out["proxy_url"] = val
    elif key == "timeout":
        try:
            d = parse_duration(val)
        except ValueError:
            d = -1.0
        if d <= 0 or d > 300:
            err = "timeout must be a duration such as 10s, up to 5m"
        out["timeout"] = max(d, 0.0)
    return err


def _resolve(ld: _Loader_, pending: list[tuple[Settings, Node, dict[str, str]]]) -> None:
    """Resolve references and order connections so dependencies come first."""
    by_id = {s.id: (s, node, refs) for s, node, refs in pending}
    for s, node, refs in pending:
        for fld, want in refs.items():
            target = s.get(fld)
            tp = by_id.get(target)
            if tp is None:
                ld.errf(node, f'connection "{s.id}": {fld} refers to unknown connection "{target}"')
                continue
            if tp[0].integration != want:
                ld.errf(node, f'connection "{s.id}": {fld} must name a {want} connection, but "{target}" is {tp[0].integration}')
            if target == s.id:
                ld.errf(node, f'connection "{s.id}": {fld} refers to itself')
    if ld.errs:
        return
    state: dict[str, int] = {}
    order: list[Settings] = []

    def visit(p: tuple[Settings, Node, dict[str, str]]) -> bool:
        s, node, refs = p
        st = state.get(s.id, 0)
        if st == 1:
            ld.errf(node, f'connection "{s.id}": reference cycle')
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
