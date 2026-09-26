"""Checks what an identity may do in HashiCorp Vault.

hallpass authenticates with a token or an AppRole, finds the identity entity
whose alias on the configured auth mount is the user's email, collects the
ACL policies attached to the entity, its groups and the auth mount's roles
(declared in the connection), reads each policy and evaluates the requested
path and capability with Vault's own rules: the most specific matching path
wins, deny beats everything, "+" spans one segment and a trailing "*" any
suffix. Parameter constraints, wrapping requirements, unresolvable templates
and Sentinel policies answer unknown. Nothing is written.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from hallpass.authx.oauth2 import TokenError
from hallpass.authx.token import Token, TokenSource
from hallpass.core import jsonx
from hallpass.core.cache import TTL, is_panic_type
from hallpass.core.catalog import Action
from hallpass.core.context import Context
from hallpass.core.decision import (
    Code,
    Decision,
    HallpassError,
    allowed,
    denied,
    errorf,
    to_decision,
    unsupported,
    user_not_found,
    wrap_error,
)
from hallpass.core.errors import as_error, go_lower, go_quote, go_trim_space
from hallpass.core.integration import (
    CheckRequest,
    Connection,
    Deps,
    Field,
    Identity,
    Integration,
    ProbeResult,
    Settings,
    User,
    credential_field,
    url_field,
)
from hallpass.core.secret import SecretError
from hallpass.core.template import is_email
from hallpass.integrations.vault.actions import catalog_actions, match_action, parse_target
from hallpass.integrations.vault.policy import Alias, Evaluation, PolicyError, Rule, TemplateContext, evaluate, parse_policy
from hallpass.net import httpx

__all__ = ["CACHE_TTL", "Vault", "VaultConnection", "classify", "template_context_of"]

AUTH_TOKEN = "token"
AUTH_APPROLE = "approle"

# How long policies, groups, mounts and the auth accessor are kept.
CACHE_TTL = 5 * 60.0

MOUNT_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_.-]+)*/?")
NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}")
ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")

T = TypeVar("T")


class Vault(Integration):
    """The vault product."""

    def name(self) -> str:
        return "vault"

    def fields(self) -> list[Field]:
        return [
            url_field(True, "the Vault address, e.g. https://vault.example.com:8200"),
            Field(
                name="auth_mode",
                default=AUTH_TOKEN,
                enum=(AUTH_TOKEN, AUTH_APPROLE),
                description="token: credential is a Vault token; approle: credential is the secret_id, role_id names the role",
            ),
            Field(name="role_id", description="approle: the role_id"),
            Field(name="approle_mount", default="approle", description="approle: the auth mount path"),
            credential_field(True, "the token or the AppRole secret_id"),
            Field(name="namespace", description="the Vault Enterprise namespace, sent as X-Vault-Namespace"),
            Field(name="alias_mount", required=True, description="the auth mount whose aliases carry the users' emails, e.g. oidc/ or ldap/"),
            Field(
                name="token_policies",
                description=(
                    "comma-separated policies every login through alias_mount receives (the auth role's token_policies), which are not visible on the entity"
                ),
            ),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def match_action(self, name: str) -> Action | None:
        return match_action(name)

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network."""
        hc = d.http_client(s)
        base = go_trim_space(s.get("url")).rstrip("/")
        if not base.startswith("https://") and not base.startswith("http://"):
            raise ValueError("url is required and must be an http(s) URL")
        if s.secret("credential").is_zero():
            raise ValueError("credential is required")
        c = VaultConnection(
            alias_mount=go_trim_space(s.get("alias_mount")),
            namespace=go_trim_space(s.get("namespace")),
            now=d.now or time.time,
        )
        if not MOUNT_RE.fullmatch(c.alias_mount):
            raise ValueError("alias_mount is required and must be an auth mount path such as oidc/")
        c.alias_mount = c.alias_mount.removesuffix("/") + "/"
        if c.namespace != "" and not MOUNT_RE.fullmatch(c.namespace):
            raise ValueError("namespace must be a namespace path such as admin/ or team/child")
        for p in s.get("token_policies").split(","):
            p = go_trim_space(p)
            if p == "":
                continue
            if not NAME_RE.fullmatch(p) or p == "root":
                raise ValueError(f"token_policies: {go_quote(p)} is not a policy name hallpass accepts")
            c.token_policies.append(p)
        cred = s.secret("credential")
        plain = httpx.Client(http=hc, base=base + "/v1", logger=d.logger, auth=c.namespace_header)
        mode = s.get("auth_mode")
        if mode in ("", AUTH_TOKEN):

            def fetch_token(ctx: Context) -> Token:
                try:
                    t = cred.get_string()
                except SecretError as e:
                    raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the token could not be read") from e
                return Token(go_trim_space(t))

            c.tokens = TokenSource(fetch_token, now=c.now)
        elif mode == AUTH_APPROLE:
            role_id = go_trim_space(s.get("role_id"))
            if not ID_RE.fullmatch(role_id):
                raise ValueError("role_id is required in auth_mode approle")
            mount = go_trim_space(s.get("approle_mount")).strip("/")
            if mount == "":
                mount = "approle"
            if not MOUNT_RE.fullmatch(mount):
                raise ValueError("approle_mount must be a mount path")
            login_path = "/auth/" + mount + "/login"
            c.relogin = True

            def fetch_approle(ctx: Context) -> Token:
                try:
                    secret = cred.get_string()
                except SecretError as e:
                    raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the AppRole secret_id could not be read") from e
                try:
                    resp = plain.do(
                        ctx,
                        httpx.Request(method="POST", path=login_path, json={"role_id": role_id, "secret_id": go_trim_space(secret)}),
                    )
                except Exception as e:
                    st = httpx.status(e)
                    if st == 0:
                        raise  # transport: classified as such
                    raise TokenError(st, "approle_login_failed") from None
                try:
                    body = _decode_body(resp.body)
                    auth = jsonx.o(jsonx.obj(body), "auth")
                    client_token = jsonx.s(auth, "client_token")
                    lease = jsonx.i(auth, "lease_duration")
                except ValueError:
                    raise TokenError(resp.status, "approle_login_no_token") from None
                if client_token == "":
                    raise TokenError(resp.status, "approle_login_no_token")
                expiry = c.now() + lease if lease > 0 else None
                return Token(client_token, expiry)

            c.tokens = TokenSource(fetch_approle, now=c.now)
        else:
            raise ValueError(f"auth_mode {go_quote(mode)} must be token or approle")

        def auth(ctx: Context, r: httpx.PreparedRequest) -> None:
            assert c.tokens is not None
            tok = c.tokens.get(ctx)
            r.headers.set("X-Vault-Token", tok)
            c.namespace_header(ctx, r)

        c.api = httpx.Client(http=hc, base=base + "/v1", logger=d.logger, auth=auth)
        return c


# -- JSON helpers --------------------------------------------------------------


def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid character '{name[0]}' looking for beginning of value")


def _decode_body(body: bytes) -> Any:
    """Go's httpx Response.JSON: the first JSON value of the body; trailing
    data is ignored, as a streaming decoder would."""
    text = body.decode("utf-8", "replace").lstrip(" \t\r\n")
    if not text:
        raise ValueError("empty body")
    v, _ = json.JSONDecoder(parse_constant=_reject_constant).raw_decode(text)
    return v


def _member(d: dict[str, Any], key: str) -> Any:
    """The member a Go struct field named key decodes: an exact match, else
    a case-insensitive one."""
    if key in d:
        return d[key]
    lk = key.lower()
    for k, v in d.items():
        if len(k) == len(key) and "".join("k" if c == "K" else "s" if c == "ſ" else c.lower() if c.isascii() else c for c in k) == lk:
            return v
    return None


def _opt_bool(d: dict[str, Any], key: str) -> bool | None:
    """A *bool field: None when absent or null."""
    v = _member(d, key)
    if v is None:
        return None
    if not isinstance(v, bool):
        raise jsonx.DecodeError(f"json: cannot unmarshal value into field {key} of type bool")
    return v


def _str_map(d: dict[str, Any], key: str) -> dict[str, str]:
    """A map[string]string field; a null value is "" as in Go."""
    out: dict[str, str] = {}
    for k, v in jsonx.o(d, key).items():
        if v is None:
            out[k] = ""
        elif isinstance(v, str):
            out[k] = v
        else:
            raise jsonx.DecodeError(f"json: cannot unmarshal value into field {key} of type string")
    return out


@dataclass
class _EntityAlias:
    id: str
    name: str
    mount_accessor: str
    metadata: dict[str, str]


@dataclass
class _Entity:
    id: str = ""
    name: str = ""
    disabled: bool | None = None
    policies: list[str] = field(default_factory=list)
    group_ids: list[str] = field(default_factory=list)
    inherited_group_ids: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)
    aliases: list[_EntityAlias] = field(default_factory=list)


def _decode_entity(v: Any) -> _Entity:
    d = jsonx.obj(v)
    aliases = []
    for a in jsonx.arr(d, "aliases"):
        a = jsonx.obj(a)
        aliases.append(_EntityAlias(jsonx.s(a, "id"), jsonx.s(a, "name"), jsonx.s(a, "mount_accessor"), _str_map(a, "metadata")))
    return _Entity(
        id=jsonx.s(d, "id"),
        name=jsonx.s(d, "name"),
        disabled=_opt_bool(d, "disabled"),
        policies=jsonx.strs(d, "policies"),
        group_ids=jsonx.strs(d, "group_ids"),
        inherited_group_ids=jsonx.strs(d, "inherited_group_ids"),
        metadata=_str_map(d, "metadata"),
        aliases=aliases,
    )


@dataclass(frozen=True)
class _Group:
    id: str = ""
    name: str = ""
    type: str = ""
    policies: tuple[str, ...] = ()


def _decode_group(v: Any) -> _Group:
    d = jsonx.obj(v)
    return _Group(jsonx.s(d, "id"), jsonx.s(d, "name"), jsonx.s(d, "type"), tuple(jsonx.strs(d, "policies")))


# -- errors ------------------------------------------------------------------


class _MissingPolicy(Exception):
    """The policy does not exist (Go's errMissingPolicy)."""

    def __init__(self) -> None:
        super().__init__("policy does not exist")


def classify(err: BaseException, what: str, not_found: Callable[[], BaseException] | None = None) -> BaseException:
    """Map an API error. not_found builds the error for a 404, which Vault
    also answers when the token may not see the path."""
    if as_error(err, HallpassError) is not None:
        return err
    te = as_error(err, TokenError)
    if te is not None:
        if te.status in (400, 403):
            return wrap_error(Code.CREDENTIAL_REJECTED, err, f"Vault rejected the AppRole login (HTTP {te.status})")
        if te.status == 429:
            return wrap_error(Code.UPSTREAM_RATE_LIMIT, err, "Vault rate limited the AppRole login")
        return wrap_error(Code.UPSTREAM_ERROR, err, f"the AppRole login failed (HTTP {te.status})")
    st = httpx.status(err)
    if st == 403:
        return wrap_error(Code.CREDENTIAL_REJECTED, err, f"Vault refused to {what} (permission denied): hallpass's token lacks the capability")
    if st == 404:
        if not_found is not None:
            return not_found()
        return wrap_error(Code.UPSTREAM_ERROR, err, f"Vault has no {what} endpoint (HTTP 404)")
    if st == 400:
        return wrap_error(Code.INVALID_REQUEST, err, f"Vault rejected the request to {what} (HTTP 400)")
    if st == 412:
        return wrap_error(Code.UPSTREAM_ERROR, err, "Vault answered 412 (eventual consistency); retry")
    if st in (501, 503):
        return wrap_error(Code.UPSTREAM_ERROR, err, f"Vault is sealed, not initialised or under maintenance (HTTP {st})")
    out = httpx.classify(err)
    assert out is not None
    return out


def _decision_of(e: Exception) -> Decision:
    """Go's integration.ToDecision for an error a helper returned; a crash
    in hallpass's own code keeps propagating."""
    if is_panic_type(e):
        raise e
    return to_decision(e)


# -- the connection ------------------------------------------------------------


class VaultConnection(Connection):
    """One Vault (namespace)."""

    def __init__(self, alias_mount: str, namespace: str, now: Callable[[], float]) -> None:
        self.api: httpx.Client | None = None
        self.tokens: TokenSource | None = None
        self.alias_mount = alias_mount
        self.namespace = namespace
        self.token_policies: list[str] = []
        # Set in approle mode, where a 403 may mean an expired token;
        # denied_token is the token a 403 already triggered a login for.
        self.relogin = False
        self._mu = threading.Lock()
        self._denied_token = ""
        self.now = now
        # Each policy's text; templates are resolved per identity when it
        # is parsed for a check.
        self.policies: TTL[str, str] = TTL(0)
        self.groups: TTL[str, _Group] = TTL(0)
        # The sys/auth and sys/mounts listings under their paths.
        self.misc: TTL[str, dict[str, Any]] = TTL(0)
        self.policies.set_clock(now)
        self.groups.set_clock(now)
        self.misc.set_clock(now)

    def _first_denial(self, ctx: Context) -> bool:
        """Whether the current token has not yet been denied; a token denied
        twice is a token that lacks the capability, not an expired one, and
        a new login would only spend a secret_id use."""
        assert self.tokens is not None
        try:
            tok = self.tokens.get(ctx)
        except Exception:  # noqa: BLE001 - Go: an error means no second try
            return False
        with self._mu:
            if self._denied_token == tok:
                return False
            self._denied_token = tok
            return True

    def namespace_header(self, ctx: Context, r: httpx.PreparedRequest) -> None:
        if self.namespace != "":
            r.headers.set("X-Vault-Namespace", self.namespace)

    # -- transport --

    def _data(self, ctx: Context, method: str, path: str, body: Any, decode: Callable[[Any], T]) -> tuple[bool, T | None]:
        """One request, decoding the response's data object. The first value
        is set when Vault answered with no content."""
        assert self.api is not None and self.tokens is not None
        req = httpx.Request(method=method, path=path)
        if body is not None:
            req.json = body
            req.idempotent = True
        try:
            resp = self.api.do(ctx, req)
        except Exception as e:
            if not (httpx.status(e) == 403 and self.relogin and self._first_denial(ctx)):
                raise
            # An AppRole token that expired or was revoked answers
            # permission denied like a missing capability does: log in
            # again, once per token, and retry.
            self.tokens.invalidate()
            resp = self.api.do(ctx, req)
        if resp.status == 204 or go_trim_space(resp.body.decode("utf-8", "replace")) == "":
            return True, None
        try:
            env = _decode_body(resp.body)
            if env is not None and not isinstance(env, dict):
                raise jsonx.DecodeError(f"json: cannot unmarshal {type(env).__name__} into Go value of type struct")
        except ValueError as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, "Vault's response was not JSON") from e
        data = _member(env, "data") if env is not None else None
        if data is None:
            # Some endpoints answer without the data envelope.
            try:
                return False, decode(env)
            except ValueError as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "Vault's response carried no data") from e
        try:
            return False, decode(data)
        except ValueError as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, "Vault's data could not be decoded") from e

    def _listing(self, ctx: Context, path: str) -> dict[str, Any]:
        """sys/auth or sys/mounts, cached."""

        def fill(ctx: Context) -> tuple[dict[str, Any], float]:
            try:
                _, out = self._data(ctx, "GET", path, None, jsonx.obj)
            except Exception as e:  # noqa: BLE001 - classified and raised
                raise classify(e, "read " + path)
            return out or {}, CACHE_TTL

        return self.misc.do(ctx, path, fill)

    # -- identity --

    def _accessor(self, ctx: Context) -> str:
        """The alias mount's accessor from sys/auth."""
        mounts = self._listing(ctx, "/sys/auth")
        if self.alias_mount not in mounts:
            raise errorf(Code.INVALID_REQUEST, f"alias_mount {self.alias_mount} is not an enabled auth method")
        try:
            acc = jsonx.s(jsonx.obj(mounts[self.alias_mount]), "accessor")
        except ValueError:
            acc = ""
        if acc == "":
            raise errorf(Code.UPSTREAM_ERROR, f"sys/auth reports no accessor for {self.alias_mount}")
        return acc

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Find the entity whose alias on the alias mount is the email, then
        its groups. The identity's groups are group ids; attributes carry
        what policy templates may need."""
        email = go_lower(go_trim_space(u.email))
        if not is_email(email):
            raise errorf(Code.INVALID_REQUEST, f"user email {go_quote(email)} is not an address")
        acc = self._accessor(ctx)
        try:
            none, found_id = self._data(
                ctx,
                "POST",
                "/identity/lookup/entity",
                {"alias_name": email, "alias_mount_accessor": acc},
                lambda v: jsonx.s(jsonx.obj(v), "id"),
            )
        except Exception as e:  # noqa: BLE001 - classified and raised
            raise classify(e, "look up the entity")
        # UNVERIFIED: the lookup answers 204 when nothing matches; an empty
        # data object is taken as no match too.
        if none or not found_id:
            raise user_not_found(f"no Vault entity has an alias {email} on {self.alias_mount}")
        if not ID_RE.fullmatch(found_id):
            raise errorf(Code.UPSTREAM_ERROR, "Vault returned an entity id of an unexpected shape")
        # The lookup response carries most of the entity, but not disabled;
        # the read does, and a disabled entity must be denied.
        try:
            _, e = self._data(ctx, "GET", "/identity/entity/id/" + found_id, None, _decode_entity)
        except Exception as err:  # noqa: BLE001 - classified and raised
            raise classify(
                err,
                "read the entity",
                lambda: errorf(Code.UPSTREAM_ERROR, f"entity {found_id} vanished between lookup and read"),
            )
        if e is None:
            e = _Entity()
        attrs: dict[str, str] = {"entity_name": e.name, "disabled": "unknown"}
        if e.disabled is not None:
            attrs["disabled"] = "true" if e.disabled else "false"
        for k, v in e.metadata.items():
            attrs["meta:" + k] = v
        for a in e.aliases:
            attrs["alias:" + a.mount_accessor + ":id"] = a.id
            attrs["alias:" + a.mount_accessor + ":name"] = a.name
            for k, v in a.metadata.items():
                attrs["alias:" + a.mount_accessor + ":meta:" + k] = v
        policies: set[str] = set(e.policies)
        groups: list[str] = []
        seen: set[str] = set()
        for gid in [*e.group_ids, *e.inherited_group_ids]:
            if gid == "" or gid in seen or not ID_RE.fullmatch(gid):
                continue
            seen.add(gid)
            g = self._group(ctx, gid)
            groups.append(gid)
            attrs["group:" + gid] = g.name
            policies.update(g.policies)
        groups.sort()
        attrs["policies"] = ",".join(sorted(policies))
        return Identity(id=found_id, display=email, attrs=attrs, groups=tuple(groups))

    def _group(self, ctx: Context, gid: str) -> _Group:
        """One identity group, cached."""

        def fill(ctx: Context) -> tuple[_Group, float]:
            try:
                _, g = self._data(ctx, "GET", "/identity/group/id/" + gid, None, _decode_group)
            except Exception as e:  # noqa: BLE001 - classified and raised
                raise classify(
                    e,
                    "read group " + gid,
                    lambda: errorf(Code.UPSTREAM_ERROR, f"group {gid} is a member of the entity but cannot be read"),
                )
            return g or _Group(), CACHE_TTL

        return self.groups.do(ctx, gid, fill)

    # -- policies --

    def _policy(self, ctx: Context, name: str, tc: TemplateContext) -> tuple[list[Rule], bool]:
        """Read and parse one ACL policy, cached. A policy Vault does not
        have contributes no rules (a token may name a missing policy)."""
        if not NAME_RE.fullmatch(name):
            raise errorf(Code.UPSTREAM_ERROR, f"policy name {go_quote(name)} has an unexpected shape")

        def decode(v: Any) -> str:
            d = jsonx.obj(v)
            policy, rules = jsonx.s(d, "policy"), jsonx.s(d, "rules")
            # UNVERIFIED: the policy text sits under data.policy; the docs'
            # sample shows it at the top level, which _data also reads.
            return policy or rules

        def fill(ctx: Context) -> tuple[str, float]:
            try:
                none, text = self._data(ctx, "GET", "/sys/policies/acl/" + name, None, decode)
            except Exception as e:  # noqa: BLE001 - classified and raised
                raise classify(e, "read policy " + name, _MissingPolicy)
            if none:
                raise _MissingPolicy()
            text = text or ""
            # Parsed once without templates to validate; templates are
            # resolved per identity below.
            try:
                parse_policy(name, text, None)
            except PolicyError as e:
                raise wrap_error(Code.UNSUPPORTED, e, f"policy {name} uses syntax hallpass does not parse") from e
            return text, CACHE_TTL

        try:
            src = self.policies.do(ctx, name, fill)
        except _MissingPolicy:
            return [], False
        try:
            rules = parse_policy(name, src, tc)
        except PolicyError as e:
            raise wrap_error(Code.UNSUPPORTED, e, f"policy {name} uses syntax hallpass does not parse") from e
        return rules, True

    # -- checks --

    def _kv_mount(self, ctx: Context, path: str) -> tuple[str, str, int]:
        """The secrets engine a kv: path lives in, by the longest mount prefix
        in sys/mounts: the mount (without the slash), the key under it and
        the KV version. Mounts may span several segments."""
        mounts = self._listing(ctx, "/sys/mounts")
        mount = ""
        for m in mounts:
            if (path + "/").startswith(m) and len(m) > len(mount) + 1:
                mount = m.removesuffix("/")
        if mount == "" or len(path) <= len(mount) + 1:
            raise errorf(
                Code.RESOURCE_NOT_VISIBLE,
                f"no secrets engine is mounted above {path}, or the path names a mount without a key (or hallpass cannot list mounts)",
            )
        key = path[len(mount) + 1 :]
        if mount + "/" not in mounts:
            raise wrap_error(Code.UPSTREAM_ERROR, ValueError("unexpected end of JSON input"), f"sys/mounts entry for {mount} could not be decoded")
        try:
            m = jsonx.obj(mounts[mount + "/"])
            typ = jsonx.s(m, "type")
            version = jsonx.s(jsonx.o(m, "options"), "version")
        except ValueError as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, f"sys/mounts entry for {mount} could not be decoded") from e
        if typ not in ("kv", "generic"):
            raise errorf(Code.UNSUPPORTED, f"the engine at {mount}/ is {typ}, not kv; use path: with raw: capabilities")
        if version == "2":
            return mount, key, 2
        return mount, key, 1

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        t = parse_target(r.action_name, r.resource)
        ident = r.identity
        who = ident.display
        if ident.attr("disabled") == "true":
            return denied(f"entity {ident.attr('entity_name')} ({who}) is disabled")
        # The API path the request goes to.
        api_path = t.path
        if t.kind == "kv":
            try:
                mount, key, version = self._kv_mount(ctx, t.path)
            except Exception as e:  # noqa: BLE001 - Go: integration.ToDecision(err)
                return _decision_of(e)
            if version == 2 and t.action.kv2 != "":
                api_path = mount + "/" + t.action.kv2 + "/" + key
            elif version == 1 and t.action.name in ("secret.destroy", "secret.metadata"):
                return unsupported(f"{t.action.name} is a KV v2 question and {mount}/ is a KV v1 mount")
        # Vault evaluates a LIST against the path with and without its
        # trailing slash and lets the more specific rule win; both forms are
        # evaluated and an explicit deny on either wins.
        match_path = api_path
        if t.action.list:
            match_path += "/"
        # The policies: entity, groups, the auth role's, and default.
        # UNVERIFIED: default is attached to every token unless the auth
        # method excludes it; it is assumed attached.
        names = {"default"}
        for p in ident.attr("policies").split(","):
            if p != "":
                names.add(p)
        names.update(self.token_policies)
        if "root" in names:
            # Vault refuses root next to other policies and never issues it
            # through auth methods; a root name on an entity is a
            # misconfiguration hallpass does not turn into allow.
            return unsupported(f"{who} carries the root policy, which hallpass does not evaluate (Vault refuses root alongside other policies)")
        tc = template_context_of(ident)
        rules: list[Rule] = []
        read: list[str] = []
        for name in sorted(names):
            try:
                rs, ok = self._policy(ctx, name, tc)
            except Exception as e:  # noqa: BLE001 - Go: integration.ToDecision(err)
                return _decision_of(e)
            if ok:
                read.append(name)
                rules.extend(rs)
        need = "+".join(t.action.need)
        ev = evaluate(rules, match_path, t.action.need)
        if t.action.list:
            ev = _combine_list(ev, evaluate(rules, api_path, t.action.need))
        if len(t.action.need) == 2:
            # A write is create or update depending on whether the secret
            # exists; both must agree for a definite answer.
            a, b = evaluate(rules, match_path, t.action.need[:1]), evaluate(rules, match_path, t.action.need[1:])
            if a.outcome == b.outcome:
                ev = a
                if b.outcome == "deny" and a.pattern != "":
                    ev.reason = f"policy path {go_quote(a.pattern)} grants neither create nor update"
            elif a.outcome == "unknown":
                ev = a
            elif b.outcome == "unknown":
                ev = b
            else:
                ev = Evaluation(
                    outcome="unknown",
                    pattern=a.pattern,
                    reason=(
                        f"policy path {go_quote(a.pattern)} grants {_granted(a, b)} but not {_denied(a, b)}, "
                        f"so the write succeeds only if the secret {_exists(a)}"
                    ),
                )
        if ev.outcome == "allow":
            return allowed(f"policy {', '.join(ev.policies)} grants {need} on {go_quote(ev.pattern)}, covering {api_path} ({who})")
        if ev.outcome == "deny":
            if ev.pattern == "":
                return denied(f"no path in {who}'s policies ({', '.join(read)}) matches {match_path}; {need} is denied")
            return denied(f"{need} for {who}: {ev.reason} (policies {', '.join(ev.policies)})")
        return unsupported(f"{need} for {who} on {api_path}: {ev.reason}")

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """Look the token up and resolve the alias mount's accessor."""

        def decode(v: Any) -> tuple[str, list[str], str]:
            d = jsonx.obj(v)
            return jsonx.s(d, "display_name"), jsonx.strs(d, "policies"), jsonx.s(d, "entity_id")

        try:
            _, me = self._data(ctx, "GET", "/auth/token/lookup-self", None, decode)
        except Exception as e:  # noqa: BLE001 - classified and raised
            raise classify(e, "look up its own token")
        display, policies, _ = me or ("", [], "")
        acc = self._accessor(ctx)
        summary = f"authenticated as {display or 'a token'} with policies {', '.join(policies)}; alias mount {self.alias_mount} has accessor {acc}"
        warnings: list[str] = []
        for p in policies:
            if p == "root":
                warnings.append("hallpass's token holds the root policy; a token with read on identity/*, sys/policies/acl/*, sys/auth and sys/mounts suffices")
        if not self.token_policies:
            warnings.append("token_policies is empty: policies the auth role attaches at login are not visible on entities and are not evaluated")
        warnings.append("Sentinel policies, parameter constraints and wrapping requirements are not evaluated")
        return ProbeResult(summary=summary, warnings=tuple(warnings))


def _combine_list(a: Evaluation, b: Evaluation) -> Evaluation:
    """Merge the evaluations of a LIST path with and without its trailing
    slash: unknown wins, then an explicit deny (a matching stanza that
    denies), then an allow; two misses stay a miss."""
    if a.outcome == "unknown":
        return a
    if b.outcome == "unknown":
        return b
    if a.outcome == "deny" and a.pattern != "":
        return a
    if b.outcome == "deny" and b.pattern != "":
        return b
    if a.outcome == "allow":
        return a
    if b.outcome == "allow":
        return b
    return a


# granted, denied and exists word the mixed create/update answer.
def _granted(a: Evaluation, b: Evaluation) -> str:
    return "create" if a.outcome == "allow" else "update"


def _denied(a: Evaluation, b: Evaluation) -> str:
    return "update" if a.outcome == "allow" else "create"


def _exists(a: Evaluation) -> str:
    return "does not exist yet" if a.outcome == "allow" else "already exists"


def template_context_of(ident: Identity) -> TemplateContext:
    """Rebuild the template context from identity attributes."""
    tc = TemplateContext(entity_id=ident.id, entity_name=ident.attr("entity_name"))
    for k, v in (ident.attrs or {}).items():
        if k.startswith("meta:"):
            tc.metadata[k[len("meta:") :]] = v
        elif k.startswith("group:"):
            gid = k[len("group:") :]
            tc.group_names[gid] = v
            tc.group_ids[v] = gid
        elif k.startswith("alias:"):
            rest = k[len("alias:") :]
            acc, sep, fld = rest.partition(":")
            if not sep:
                continue
            a = tc.aliases.get(acc)
            if a is None:
                a = Alias()
                tc.aliases[acc] = a
            if fld == "id":
                a.id = v
            elif fld == "name":
                a.name = v
            elif fld.startswith("meta:"):
                a.metadata[fld[len("meta:") :]] = v
    return tc
