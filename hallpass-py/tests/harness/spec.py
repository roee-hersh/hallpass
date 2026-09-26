"""Spec-aware fakes: every request an integration sends to the fake upstream
can be validated against the vendor's published API description, so a
wrong path, method, missing required parameter or missing body field
fails the test even though the fake would have answered anyway.

Supported descriptions: OpenAPI 3 and Swagger 2 (JSON or YAML), Google
API discovery documents, botocore service models (AWS Query and JSON
protocols) and GraphQL schemas in SDL form (see graphql.py). Descriptions
are loaded from $HALLPASS_SPECS_DIR/<name>.spec; when the directory or
file is absent validation is skipped and the test says so once.

A port of internal/integration/itest/spec.go and Server.validate in
itest.go. Go's ``error`` returns become a raised SpecError; the server
hook validate_request turns one into the message the Go harness reports.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import sys
import threading
import urllib.parse
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

import yaml

from hallpass.core.catalog import ResourceError, query_unescape
from hallpass.net import httpx

__all__ = [
    "Spec",
    "SpecError",
    "SpecOptions",
    "SpecRequest",
    "any_spec",
    "escaped_path",
    "load_spec",
    "parse_query",
    "server_path",
    "spec_from_env",
    "validate_request",
    "with_optional",
]


class SpecError(ValueError):
    """A request the description does not accept, or a description that
    does not load."""


class Spec(Protocol):
    """Validates requests against an API description."""

    def validate(self, r: SpecRequest, body: bytes) -> None:
        """Return when the request is one the API accepts; raise SpecError
        otherwise."""

    def name(self) -> str:
        """Identifies the description in messages."""


@dataclass(frozen=True)
class SpecRequest:
    """The parts of an HTTP request a spec looks at (Go's *http.Request).

    raw_path is the escaped path (Go's URL.EscapedPath()), so %2F stays
    inside one segment; optional names parameters not to require (Go's
    WithOptional context value)."""

    method: str
    raw_path: str
    raw_query: str = ""
    header: httpx.Headers = field(default_factory=httpx.Headers)
    optional: frozenset[str] = frozenset()

    @classmethod
    def from_url(cls, method: str, url: str, content_type: str = "", header: httpx.Headers | None = None) -> SpecRequest:
        """A request for an absolute or origin-form URL."""
        u = urllib.parse.urlsplit(url)
        h = header.clone() if header is not None else httpx.Headers()
        if content_type:
            h.set("Content-Type", content_type)
        return cls(method, escaped_path(u.path), u.query, h)

    def query(self) -> dict[str, list[str]]:
        """Go's URL.Query(): malformed pairs are dropped."""
        return parse_query(self.raw_query)[0]


def with_optional(r: SpecRequest, names: Iterable[str]) -> SpecRequest:
    """A request whose validation treats the named parameters as optional."""
    names = list(names)
    if not names:
        return r
    return dataclasses.replace(r, optional=frozenset(names))


def _is_optional(r: SpecRequest, name: str) -> bool:
    return name in getattr(r, "optional", frozenset())


@dataclass
class SpecOptions:
    """How a spec is applied to a fake server."""

    # Patterns removed from the start of the request path before matching
    # (a gateway prefix such as /ex/jira/<cloudid>).
    strip_prefix: Sequence[str] = ()
    # Request paths (regexps) that are not part of the description, such as
    # a token endpoint the fake also serves.
    ignore_paths: Sequence[str] = ()
    # Query parameters accepted on every operation even when the
    # description does not declare them.
    allow_query: Sequence[str] = ()
    # Parameters the description marks required but the API also accepts
    # elsewhere (Slack's legacy "token" in the query when the token travels
    # in the Authorization header).
    optional_params: Sequence[str] = ()


# -- the server hook (Go: Server.validate) ------------------------------------


def validate_request(srv: Any, r: Any) -> str | None:
    """Check one request the fake server received against srv.spec. Returns
    the failure message, or None when the request matches (or there is no
    spec). r is a tests.harness.Request."""
    spec = srv.spec
    if spec is None:
        return None
    opts: SpecOptions = srv.spec_opts if srv.spec_opts is not None else SpecOptions()
    for p in opts.ignore_paths:
        if re.search(p, r.path):
            return None
    esc = escaped_path(r.raw_path)
    for p in opts.strip_prefix:
        m = re.search("^" + p, esc)
        if m is not None:
            esc = esc[m.end() :]
            if not esc.startswith("/"):
                esc = "/" + esc
            break
    raw_query = r.raw_query
    if opts.allow_query:
        q = parse_query(raw_query)[0]
        for a in opts.allow_query:
            q.pop(a, None)
        raw_query = _encode_query(q)
    rc = with_optional(SpecRequest(r.method, esc, raw_query, r.header), opts.optional_params)
    try:
        spec.validate(rc, r.body)
    except SpecError as e:
        return f"request does not match the {spec.name()} API description: {e}"
    return None


# -- loading ----------------------------------------------------------------

_spec_lock = threading.Lock()
_spec_cache: dict[str, Any] = {}
_spec_noted: set[str] = set()


def spec_from_env(name: str) -> Spec | None:
    """Load $HALLPASS_SPECS_DIR/<name>.spec. Returns None, and notes once per
    name, when validation is not possible. A description that does not load
    fails the test."""
    d = os.environ.get("HALLPASS_SPECS_DIR", "")
    if d == "":
        _note_once(name, f"HALLPASS_SPECS_DIR not set: requests are not validated against the {name} API description")
        return None
    path = os.path.join(d, name + ".spec")
    with _spec_lock:
        s = _spec_cache.get(path)
    if s is not None:
        return s
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        _note_once(name, f"no {path}: requests are not validated against the {name} API description")
        return None
    try:
        s = load_spec(name, raw)
    except SpecError as e:
        import pytest

        pytest.fail(f"load {path}: {e}")
    with _spec_lock:
        _spec_cache[path] = s
    return s


def _note_once(name: str, msg: str) -> None:
    with _spec_lock:
        if name in _spec_noted:
            return
        _spec_noted.add(name)
    print(msg, file=sys.stderr)


def load_spec(name: str, raw: bytes | str) -> Spec:
    """Parse a description, detecting its format."""
    from tests.harness import graphql

    if isinstance(raw, str):
        raw = raw.encode()
    doc: Any
    try:
        doc = _json_object(raw)
    except ValueError:
        try:
            doc = _yaml_object(raw)
        except Exception as e:
            # Not a document: a GraphQL schema in SDL form is plain text.
            if graphql.looks_like_sdl(raw):
                return graphql.new_graphql(name, raw)
            raise SpecError(f"{name}: neither JSON nor YAML: {e}") from None
    if doc.get("openapi") is not None or doc.get("swagger") is not None:
        return _OpenAPI(name, doc)
    if doc.get("discoveryVersion") is not None:
        return _Discovery(name, doc)
    if doc.get("metadata") is not None and doc.get("operations") is not None and doc.get("shapes") is not None:
        return _Botocore(name, doc)
    if graphql.looks_like_sdl(raw):
        return graphql.new_graphql(name, raw)
    raise SpecError(f"{name}: unknown description format")


def _reject_constant(s: str) -> Any:
    raise ValueError(f"invalid character {s[0]!r} looking for beginning of value")


def go_json(data: bytes | str) -> Any:
    """json.Unmarshal into `any`: invalid UTF-8 becomes U+FFFD, NaN and
    Infinity are refused."""
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("utf-8", errors="replace")
    return json.loads(data, parse_constant=_reject_constant)


def _json_object(raw: bytes) -> dict[str, Any] | None:
    """json.Unmarshal into map[string]any: null leaves a nil map, anything
    but an object is an error."""
    v = go_json(raw)
    if v is None:
        return None
    if not isinstance(v, dict):
        raise ValueError(f"json: cannot unmarshal {go_json_kind(v)} into Go value of type map[string]interface {{}}")
    return v


def _json_doc(raw: bytes) -> dict[str, Any]:
    d = _json_object(raw)
    return d if d is not None else {}


def go_json_kind(v: Any) -> str:
    """How encoding/json names a JSON value's kind in its errors."""
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    return "object"


# libyaml's parser when present: the big descriptions (Microsoft Graph is
# tens of megabytes of YAML) take minutes with the pure-Python one.
_LoaderBase: Any = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class _Loader(_LoaderBase):  # type: ignore[misc, valid-type]
    """A SafeLoader closer to gopkg.in/yaml.v3 decoding into `any`: only
    true/false are booleans (not yes/no/on/off), timestamps stay strings
    and a key defined twice in one mapping is an error."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        seen: set[Any] = set()
        for k, _ in node.value:
            key = self.construct_object(k, deep=True)
            try:
                dup = key in seen
            except TypeError:
                raise yaml.constructor.ConstructorError(None, None, "invalid map key", k.start_mark) from None
            if dup:
                raise yaml.constructor.ConstructorError(None, None, f"mapping key {key!r} already defined", k.start_mark)
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


_Loader.yaml_implicit_resolvers = {
    ch: [(tag, rx) for tag, rx in resolvers if tag not in ("tag:yaml.org,2002:bool", "tag:yaml.org,2002:timestamp", "tag:yaml.org,2002:value")]
    for ch, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_Loader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)
_Loader.add_constructor("tag:yaml.org,2002:mapping", _Loader.construct_mapping)  # type: ignore[arg-type]


def _yaml_object(raw: bytes) -> dict[str, Any]:
    v = yaml.load(raw, Loader=_Loader)  # a SafeLoader subclass
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise ValueError(f"cannot unmarshal !!{type(v).__name__} into map[string]interface {{}}")
    return _normalise_yaml(v)


def _normalise_yaml(v: Any) -> Any:
    """Keys become strings the way Go's fmt.Sprint prints them."""
    if isinstance(v, dict):
        return {_sprint(k): _normalise_yaml(val) for k, val in v.items()}
    if isinstance(v, list):
        return [_normalise_yaml(x) for x in v]
    return v


def _sprint(k: Any) -> str:
    if isinstance(k, str):
        return k
    if isinstance(k, bool):
        return "true" if k else "false"
    if k is None:
        return "<nil>"
    return str(k)


# -- shared helpers ---------------------------------------------------------


def as_map(v: Any) -> dict[str, Any] | None:
    return v if isinstance(v, dict) else None


def _m(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def as_slice(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def as_string(v: Any) -> str:
    return v if isinstance(v, str) else ""


def as_bool(v: Any) -> bool:
    return v if isinstance(v, bool) else False


def go_quote(s: str) -> str:
    """Go's %q for a string."""
    return json.dumps(s, ensure_ascii=False)


def go_list(items: Iterable[str]) -> str:
    """Go's %v for a []string."""
    return "[" + " ".join(items) + "]"


def parse_query(query: str) -> tuple[dict[str, list[str]], str | None]:
    """Go's url.ParseQuery: the values parsed and the error, if any, with
    malformed pairs dropped."""
    out: dict[str, list[str]] = {}
    err: str | None = None
    for key in query.split("&"):
        if ";" in key:
            err = "invalid semicolon separator in query"
            continue
        if key == "":
            continue
        k, _, v = key.partition("=")
        try:
            k = query_unescape(k)
            v = query_unescape(v)
        except ResourceError as e:
            if err is None:
                err = str(e)
            continue
        out.setdefault(k, []).append(v)
    return out, err


def _encode_query(q: Mapping[str, list[str]]) -> str:
    """Go's url.Values.Encode: sorted by key."""
    parts = []
    for k in sorted(q):
        for v in q[k]:
            parts.append(urllib.parse.quote_plus(k, safe="") + "=" + urllib.parse.quote_plus(v, safe=""))
    return "&".join(parts)


_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
# Go's shouldEscape(c, encodePath) is false for these.
_PATH_SAFE = _ALNUM | frozenset("-_.~$&+,/:;=@")
# Go's validEncoded also accepts these (and '%') in a raw path.
_PATH_VALID = _PATH_SAFE | frozenset("!'()*[]%")


def escaped_path(raw: str) -> str:
    """Go's URL.EscapedPath() for a path received or parsed in raw form: the
    raw spelling when it is a valid encoding, else the unescaped path
    escaped again."""
    if all(c in _PATH_VALID for c in raw):
        return raw
    try:
        p = urllib.parse.unquote_to_bytes(raw)
    except Exception:
        return raw
    return "".join(chr(b) if chr(b) in _PATH_SAFE else f"%{b:02X}" for b in p)


class _PathTemplate:
    __slots__ = ("literals", "raw", "segments")

    def __init__(self, p: str) -> None:
        self.raw = p
        self.segments: list[str] = []  # literal or "{}" for a variable
        self.literals = 0
        for seg in p.strip("/").split("/"):
            if seg.startswith("{") and seg.endswith("}"):
                self.segments.append("{}")
            elif "{" in seg:
                # mixed segment such as "{owner}.json": treat as variable
                self.segments.append("{}")
            else:
                self.segments.append(seg)
                self.literals += 1

    def match(self, path: str) -> bool:
        segs = path.strip("/").split("/")
        if len(self.segments) > 1 and self.segments[0] == "{}" and self.literals > 0:
            # A template that starts with a variable and continues with
            # literals (Azure's /{scope}/providers/...) takes a whole
            # resource path there: the variable spans one or more non-empty
            # segments. A bare /{id} template keeps matching one segment, or
            # it would match every path.
            n = len(segs) - len(self.segments) + 1
            if n < 1:
                return False
            if any(seg == "" for seg in segs[:n]):
                return False
            return _match_segments(self.segments[1:], segs[n:])
        return _match_segments(self.segments, segs)


def _match_segments(tpl: list[str], segs: list[str]) -> bool:
    if len(segs) != len(tpl):
        return False
    for s, seg in zip(tpl, segs, strict=True):
        if s == "{}":
            if seg == "":
                return False
            continue
        if s != seg:
            return False
    return True


def _best_templates(templates: list[_PathTemplate], path: str) -> list[_PathTemplate]:
    """Every matching template with the most literal segments, in a stable
    order."""
    best: list[_PathTemplate] = []
    for t in templates:
        if not t.match(path):
            continue
        if not best or t.literals > best[0].literals:
            best = [t]
        elif t.literals == best[0].literals:
            best.append(t)
    best.sort(key=lambda t: t.raw)
    return best


def _best_template(templates: list[_PathTemplate], path: str) -> _PathTemplate | None:
    """The matching template with the most literal segments."""
    best = _best_templates(templates, path)
    return best[0] if best else None


def _resolve_ref(doc: dict[str, Any], ref: str) -> dict[str, Any] | None:
    """Follow a local JSON pointer such as #/components/parameters/x."""
    if not ref.startswith("#/"):
        return None
    cur: Any = doc
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return as_map(cur)


def _deref(doc: dict[str, Any], v: Any) -> dict[str, Any] | None:
    m = as_map(v)
    ref = as_string(_m(m).get("$ref"))
    if ref != "":
        r = _resolve_ref(doc, ref)
        if r is not None:
            return r
    return m


def _required_top_level(doc: dict[str, Any], schema: dict[str, Any] | None) -> list[str]:
    """The required property names of a JSON schema, following $ref and
    allOf one level."""
    sch = _m(_deref(doc, schema))
    req = [as_string(r) for r in as_slice(sch.get("required"))]
    for sub in as_slice(sch.get("allOf")):
        req.extend(as_string(r) for r in as_slice(_m(_deref(doc, sub)).get("required")))
    return req


def _check_json_body(body: bytes, required: list[str], what: str) -> None:
    if not required:
        return
    try:
        m = _json_doc(body)
    except ValueError as e:
        raise SpecError(f"{what}: body is not a JSON object: {e}") from None
    missing = sorted(r for r in required if r not in m)
    if missing:
        raise SpecError(f"{what}: body lacks required properties {go_list(missing)}")


# -- OpenAPI 3 / Swagger 2 -----------------------------------------------------

_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")


class _OpenAPI:
    def __init__(self, name: str, doc: dict[str, Any]) -> None:
        self._name = name
        self.doc = doc
        self.templates: list[_PathTemplate] = []
        self.prefixes: list[str] = []  # server/base paths that may precede the path
        self.ops: dict[str, dict[str, dict[str, Any]]] = {}
        self.v2 = doc.get("swagger") is not None
        paths = _m(doc.get("paths"))
        if not paths:
            raise SpecError(f"{name}: no paths")
        for p, item in paths.items():
            self.templates.append(_PathTemplate(p))
            self.ops[p] = {}
            item_m = _m(item)
            for method, op in item_m.items():
                if method not in _METHODS:
                    continue
                m = as_map(op)
                # merge path-level parameters
                pp = as_slice(item_m.get("parameters"))
                if pp:
                    cp = dict(m or {})
                    cp["parameters"] = list(pp) + as_slice(_m(m).get("parameters"))
                    m = cp
                self.ops[p][method.upper()] = m if m is not None else {}
        if self.v2:
            bp = as_string(doc.get("basePath"))
            if bp not in ("", "/"):
                self.prefixes.append(bp.rstrip("/"))
        else:
            for srv in as_slice(doc.get("servers")):
                sp = server_path(as_map(srv))
                if sp != "":
                    self.prefixes.append(sp)

    def name(self) -> str:
        return self._name

    def validate(self, r: SpecRequest, body: bytes) -> None:
        # The escaped path keeps %2F inside one segment (GitLab project paths).
        path = r.raw_path
        candidates = [path]
        for pre in self.prefixes:
            if path.startswith(pre + "/"):
                candidates.append(path[len(pre) :])
        # Several templates can match with the same number of literals
        # (Vault's /auth/{approle_mount_path}/login next to
        # /auth/{alicloud_mount_path}/login); the request is accepted when
        # it satisfies any of them.
        tpls: list[_PathTemplate] = []
        for c in candidates:
            tpls = _best_templates(self.templates, c)
            if tpls:
                break
        if not tpls:
            raise SpecError(f"{self._name}: no operation for path {path}")
        first: SpecError | None = None
        for tpl in tpls:
            try:
                self._validate_op(r, body, tpl)
                return
            except SpecError as e:
                if first is None:
                    first = e
        assert first is not None
        raise first

    def _validate_op(self, r: SpecRequest, body: bytes, tpl: _PathTemplate) -> None:
        """Check the request against one path template's operation."""
        ops = self.ops[tpl.raw]
        op = ops.get(r.method)
        if op is None:
            raise SpecError(f"{self._name}: {r.method} not allowed on {tpl.raw} (spec has {go_list(sorted(ops))})")
        query = r.query()
        declared: set[str] = set()
        missing_q: list[str] = []
        missing_h: list[str] = []
        body_param: dict[str, Any] | None = None
        for p in as_slice(op.get("parameters")):
            pm = _deref(self.doc, p)
            pmm = _m(pm)
            where, pname = as_string(pmm.get("in")), as_string(pmm.get("name"))
            if where == "query":
                declared.add(pname)
                if as_bool(pmm.get("required")) and pname not in query and not _is_optional(r, pname):
                    missing_q.append(pname)
            elif where == "header":
                if as_bool(pmm.get("required")) and r.header.get(pname) == "" and pname.lower() != "authorization" and not _is_optional(r, pname):
                    missing_h.append(pname)
            elif where == "body":
                body_param = pm
        if missing_q:
            raise SpecError(f"{self._name}: {r.method} {tpl.raw} lacks required query parameters {go_list(missing_q)}")
        if missing_h:
            raise SpecError(f"{self._name}: {r.method} {tpl.raw} lacks required headers {go_list(missing_h)}")
        for q in sorted(query):
            if q not in declared:
                raise SpecError(f"{self._name}: {r.method} {tpl.raw} sends undeclared query parameter {go_quote(q)}")
        what = f"{self._name}: {r.method} {tpl.raw}"
        if self.v2:
            if body_param is not None:
                if as_bool(body_param.get("required")) and len(body) == 0:
                    raise SpecError(what + ": body required")
                if len(body) > 0 and "json" in r.header.get("Content-Type"):
                    _check_json_body(body, _required_top_level(self.doc, as_map(body_param.get("schema"))), what)
            return
        rb = _deref(self.doc, op.get("requestBody"))
        if rb is None:
            return
        if as_bool(rb.get("required")) and len(body) == 0:
            raise SpecError(what + ": body required")
        content = _m(rb.get("content"))
        if len(body) > 0 and content:
            ct = r.header.get("Content-Type")
            matched = False
            for mt, media in content.items():
                if ct.startswith(mt.split(";")[0]) or mt == "*/*":
                    matched = True
                    if "json" in mt:
                        _check_json_body(body, _required_top_level(self.doc, as_map(_m(media).get("schema"))), what)
                        return
            if not matched:
                raise SpecError(f"{what}: content type {go_quote(ct)} not among {go_list(sorted(content))}")


# -- Google API discovery -------------------------------------------------------

_RESERVED_EXPANSION = re.compile(r"\{\+?([A-Za-z0-9_]+)\}")


def _discovery_template(p: str) -> str:
    return _RESERVED_EXPANSION.sub(r"{\1}", p)


class _Discovery:
    def __init__(self, name: str, doc: dict[str, Any]) -> None:
        self._name = name
        self.templates: list[_PathTemplate] = []
        # template raw -> METHOD -> method doc
        self.methods: dict[str, dict[str, dict[str, Any]]] = {}
        self.global_params: set[str] = set(_m(doc.get("parameters")))
        # servicePath, e.g. /drive/v3/
        self.base = "/" + as_string(doc.get("servicePath")).strip("/")
        if self.base == "/":
            p = go_url_path(as_string(doc.get("baseUrl")))
            if p is not None:
                self.base = "/" + p.strip("/")

        def walk(res: dict[str, Any]) -> None:
            for m in _m(res.get("methods")).values():
                md = _m(m)
                p = as_string(md.get("path"))
                if not p.startswith("/"):
                    p = self.base.rstrip("/") + "/" + p
                p = _discovery_template(p)
                if p not in self.methods:
                    self.templates.append(_PathTemplate(p))
                    self.methods[p] = {}
                self.methods[p][as_string(md.get("httpMethod")).upper()] = md
            for sub in _m(res.get("resources")).values():
                walk(_m(sub))

        walk(doc)
        if not self.templates:
            raise SpecError(f"{name}: no methods")

    def name(self) -> str:
        return self._name

    def validate(self, r: SpecRequest, body: bytes) -> None:
        tpl = _best_template(self.templates, r.raw_path)
        if tpl is None:
            raise SpecError(f"{self._name}: no method for path {r.raw_path}")
        md = self.methods[tpl.raw].get(r.method)
        if md is None:
            raise SpecError(f"{self._name}: {r.method} not allowed on {tpl.raw}")
        params = _m(md.get("parameters"))
        query = r.query()
        missing = sorted(
            n
            for n, p in params.items()
            if as_string(_m(p).get("location")) == "query" and as_bool(_m(p).get("required")) and n not in query and not _is_optional(r, n)
        )
        if missing:
            raise SpecError(f"{self._name}: {r.method} {tpl.raw} lacks required query parameters {go_list(missing)}")
        for q in sorted(query):
            if q in self.global_params:
                continue
            pm = as_map(params.get(q))
            if pm is None or as_string(pm.get("location")) != "query":
                raise SpecError(f"{self._name}: {r.method} {tpl.raw} sends undeclared query parameter {go_quote(q)}")
        if as_map(md.get("request")) is not None and len(body) == 0 and r.method != "GET":
            raise SpecError(f"{self._name}: {r.method} {tpl.raw} expects a request body")


# -- botocore service model -------------------------------------------------------


class _Botocore:
    def __init__(self, name: str, doc: dict[str, Any]) -> None:
        meta = _m(doc.get("metadata"))
        self._name = name
        self.protocol = as_string(meta.get("protocol"))  # "query" or "json"
        self.target_prefix = as_string(meta.get("targetPrefix"))
        self.ops: dict[str, dict[str, Any]] = {n: _m(op) for n, op in _m(doc.get("operations")).items()}
        self.shapes = _m(doc.get("shapes"))
        if self.protocol not in ("query", "json"):
            raise SpecError(f"{name}: unsupported protocol {go_quote(self.protocol)}")

    def name(self) -> str:
        return self._name

    def _input_shape(self, op_name: str) -> dict[str, Any] | None:
        inp = as_map(self.ops.get(op_name, {}).get("input"))
        if inp is None:
            return None
        return _m(self.shapes.get(as_string(inp.get("shape"))))

    def _required_members(self, op_name: str) -> list[str]:
        shape = self._input_shape(op_name)
        if shape is None:
            return []
        return [as_string(r) for r in as_slice(shape.get("required"))]

    def _members(self, op_name: str) -> dict[str, Any]:
        inp = _m(self.ops.get(op_name, {}).get("input"))
        return _m(_m(self.shapes.get(as_string(inp.get("shape")))).get("members"))

    def validate(self, r: SpecRequest, body: bytes) -> None:
        if r.method != "POST":
            raise SpecError(f"{self._name}: AWS calls are POST, got {r.method}")
        if self.protocol == "query":
            form, err = parse_query(body.decode("utf-8", errors="replace"))
            if err is not None:
                raise SpecError(f"{self._name}: body is not form encoded: {err}")

            def get(k: str) -> str:
                vs = form.get(k)
                return vs[0] if vs else ""

            action = get("Action")
            if action not in self.ops:
                raise SpecError(f"{self._name}: unknown Action {go_quote(action)}")
            missing = [m for m in self._required_members(action) if get(m) == "" and get(m + ".member.1") == ""]
            if missing:
                raise SpecError(f"{self._name}: {action} lacks required members {go_list(missing)}")
            # Every sent key must be a member (or a member list/struct path).
            members = self._members(action)
            for k in sorted(form):
                if k in ("Action", "Version"):
                    continue
                if k.split(".", 1)[0] not in members:
                    raise SpecError(f"{self._name}: {action} sends unknown parameter {go_quote(k)}")
        elif self.protocol == "json":
            target = r.header.get("X-Amz-Target")
            prefix, sep, op = target.partition(".")
            if not sep or prefix != self.target_prefix:
                raise SpecError(f"{self._name}: X-Amz-Target {go_quote(target)} does not start with {self.target_prefix}.")
            if op not in self.ops:
                raise SpecError(f"{self._name}: unknown operation {go_quote(op)}")
            ct = r.header.get("Content-Type")
            if not ct.startswith("application/x-amz-json-1."):
                raise SpecError(f"{self._name}: content type {go_quote(ct)}")
            try:
                m = _json_doc(body)
            except ValueError as e:
                raise SpecError(f"{self._name}: {op} body is not JSON: {e}") from None
            missing = [req for req in self._required_members(op) if req not in m]
            if missing:
                raise SpecError(f"{self._name}: {op} lacks required members {go_list(missing)}")
            members = self._members(op)
            for k in m:
                if k not in members:
                    raise SpecError(f"{self._name}: {op} sends unknown member {go_quote(k)}")


# -- several descriptions ----------------------------------------------------------


def any_spec(*specs: Spec | None) -> Spec | None:
    """A spec that accepts a request when one of several descriptions does:
    for a fake that serves several APIs (Confluence v1 and v2, the AWS
    services). A request no description accepts is rejected with every
    error. When any description is missing (None) the result is None and
    nothing is validated: a partial set would reject the requests meant for
    the absent one."""
    if any(s is None for s in specs):
        return None
    return _AnySpec([s for s in specs if s is not None])


class _AnySpec:
    def __init__(self, specs: list[Spec]) -> None:
        self.specs = specs

    def name(self) -> str:
        return "|".join(s.name() for s in self.specs)

    def validate(self, r: SpecRequest, body: bytes) -> None:
        errs: list[str] = []
        for s in self.specs:
            try:
                s.validate(r, body)
                return
            except SpecError as e:
                errs.append(str(e))
        raise SpecError("; ".join(errs))


# -- URLs ------------------------------------------------------------------------

# Characters Go's url.Parse accepts unescaped in a host name.
_HOST_OK = _ALNUM | frozenset("-_.~$&'()*+,;=:[]<>\"!")


def go_url_path(raw: str) -> str | None:
    """The unescaped path Go's url.Parse finds in raw, or None where Go's
    url.Parse fails (a brace in the host, a colon in the first segment of a
    relative reference, a bad escape)."""
    raw = raw.split("#", 1)[0]
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
        return None
    scheme, rest = "", raw
    for i, c in enumerate(raw):
        if c.isascii() and c.isalpha():
            continue
        if c.isascii() and (c.isdigit() or c in "+-."):
            if i == 0:
                break
            continue
        if c == ":":
            if i == 0:
                return None  # missing protocol scheme
            scheme, rest = raw[:i], raw[i + 1 :]
        break
    if rest.endswith("?") and rest.count("?") == 1:
        rest = rest[:-1]
    else:
        rest = rest.split("?", 1)[0]
    if not rest.startswith("/"):
        if scheme:
            return ""  # opaque
        if ":" in rest.split("/", 1)[0]:
            return None  # first path segment in URL cannot contain colon
    if rest.startswith("//") and (scheme or not rest.startswith("///")):
        authority, slash, tail = rest[2:].partition("/")
        rest = slash + tail
        host = authority.rpartition("@")[2]
        if host.startswith("["):
            end = host.find("]")
            if end < 0:
                return None
            port = host[end + 1 :]
            if port and not ((port.startswith(":") and port[1:].isdigit()) or port == ":"):
                return None
        else:
            i = host.rfind(":")
            if i >= 0 and not (host[i + 1 :] == "" or (host[i + 1 :].isascii() and host[i + 1 :].isdigit())):
                return None
            if any(c.isascii() and c not in _HOST_OK and c != "%" for c in host):
                return None
    try:
        b = bytearray()
        i = 0
        data = rest.encode()
        while i < len(data):
            if data[i] == 0x25:
                h = data[i + 1 : i + 3]
                if len(h) != 2 or not all(x in b"0123456789abcdefABCDEF" for x in h):
                    return None
                b.append(int(h, 16))
                i += 3
                continue
            b.append(data[i])
            i += 1
        return b.decode("utf-8", errors="replace")
    except ValueError:
        return None


def server_path(srv: Mapping[str, Any] | None) -> str:
    """The path part of an OpenAPI server URL, or "" when it has none.
    Server variables ({your-domain}) are replaced by their defaults first,
    since a brace in the host does not parse; a URL that still does not
    parse is split on the first slash after the scheme."""
    srv = srv or {}
    raw = as_string(srv.get("url"))
    for name, v in _m(srv.get("variables")).items():
        raw = raw.replace("{" + name + "}", as_string(_m(v).get("default")))
    path = go_url_path(raw)
    if path is None:
        rest = raw
        i = rest.find("://")
        if i >= 0:
            rest = rest[i + 3 :]
        i = rest.find("/")
        path = rest[i:] if i >= 0 else ""
    path = path.rstrip("/")
    if path in ("", "/"):
        return ""
    return path
