"""Checks permissions in one Databricks workspace.

hallpass authenticates as a service principal (OAuth M2M) or with a personal
access token, finds the user through the workspace SCIM API, and asks the
workspace itself: the Unity Catalog effective-permissions endpoint for
catalogs, schemas, tables, volumes, functions and models (which folds in
privileges inherited down the hierarchy), and the Permissions API for
clusters, jobs, warehouses, notebooks and the other workspace objects (whose
ACLs carry inherited entries). Grants to the user's groups count, workspace
admins hold CAN_MANAGE on every object, and the owner of a securable holds
every privilege on it. Nothing is written.
"""

from __future__ import annotations

import base64
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, TypeVar

from hallpass.authx.oauth2 import TokenRequest, classify_token_error, fetch_token
from hallpass.authx.token import Token, TokenSource
from hallpass.core import jsonx
from hallpass.core.cache import TTL
from hallpass.core.catalog import Action
from hallpass.core.context import Context
from hallpass.core.decision import (
    Code,
    Decision,
    HallpassError,
    allowed,
    denied,
    errorf,
    unknown_decision,
    unsupported,
    user_ambiguous,
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
    validate_https_url,
)
from hallpass.core.secret import SecretError
from hallpass.core.template import is_email
from hallpass.integrations.databricks.actions import (
    PRIV_ALL_PRIVILEGES,
    HeldPrivileges,
    Ref,
    catalog_actions,
    covers,
    match_action,
    parse_ref,
    satisfies_level,
    satisfies_privileges,
)
from hallpass.net import httpx

__all__ = ["SCIM_ME", "SCIM_USERS", "SCOPE_ALL_APIS", "Databricks", "DatabricksConnection", "equal_fold", "validate_client_id"]

MODE_OAUTH = "oauth"
MODE_TOKEN = "token"

SCOPE_ALL_APIS = "all-apis"
ADMINS_GROUP = "admins"

SCIM_USERS = "/api/2.0/preview/scim/v2/Users"
SCIM_ME = "/api/2.0/preview/scim/v2/Me"

# How long hallpass's own SCIM record is kept.
SELF_TTL = 10 * 60.0

CLIENT_ID_RE = re.compile(r"[A-Za-z0-9._-]{8,128}")
# Finds error_code in a Databricks error body snippet (Go's \s is ASCII
# whitespace). The message is never used.
ERROR_CODE_RE = re.compile(r'"error_code"[\t\n\f\r ]*:[\t\n\f\r ]*"([A-Z_]+)"')

T = TypeVar("T")


def validate_client_id(v: str) -> None:
    if v == "" or CLIENT_ID_RE.fullmatch(v):
        return
    raise ValueError("must be a service principal application id")


class Databricks(Integration):
    """The databricks product."""

    def name(self) -> str:
        return "databricks"

    def fields(self) -> list[Field]:
        return [
            url_field(True, "workspace URL, e.g. https://adb-1234567890123456.7.azuredatabricks.net or https://dbc-a1b2c3d4-e5f6.cloud.databricks.com"),
            Field(
                name="auth_mode",
                default=MODE_OAUTH,
                enum=(MODE_OAUTH, MODE_TOKEN),
                description="oauth: service principal with client_id and an OAuth secret (credential); token: a personal access token (credential)",
            ),
            Field(name="client_id", validate=validate_client_id, description="the service principal's application id, auth_mode oauth"),
            credential_field(True, "the service principal's OAuth secret (auth_mode oauth) or the personal access token (auth_mode token)"),
            Field(name="token_url", validate=validate_https_url, description="OAuth token endpoint; default {url}/oidc/v1/token"),
            Field(
                name="admins_manage_all",
                default="true",
                enum=("true", "false"),
                description=(
                    "true: members of the workspace admins group are allowed every workspace-object action, "
                    "as Databricks grants them CAN_MANAGE on every object"
                ),
            ),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def match_action(self, name: str) -> Action | None:
        return match_action(name)

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network; the secret is read at
        call time so a rotated file takes effect."""
        hc = d.http_client(s)
        base = s.get("url").rstrip("/")
        if base == "":
            raise ValueError("url is required")
        c = DatabricksConnection(
            settings=s,
            base=base,
            mode=s.get("auth_mode"),
            client_id=s.get("client_id"),
            token_url=s.get("token_url").rstrip("/"),
            admins_rule=s.bool("admins_manage_all", True),
            now=d.now if d.now is not None else time.time,
        )
        if c.mode == "":
            c.mode = MODE_OAUTH
        if s.secret("credential").is_zero():
            raise ValueError("credential is required")
        if c.mode == MODE_OAUTH:
            bad = False
            try:
                validate_client_id(c.client_id)
            except ValueError:
                bad = True
            if bad or c.client_id == "":
                raise ValueError("client_id is required in auth_mode oauth and must be a service principal application id")
            if c.token_url == "":
                c.token_url = base + "/oidc/v1/token"
        elif c.mode != MODE_TOKEN:
            raise ValueError(f"auth_mode {go_quote(c.mode)} must be oauth or token")
        c.self_cache.set_clock(c.now)
        # hallpass's own principal name is not what a fresh check is about.
        c.self_cache.set_fresh_max_age(SELF_TTL)
        c.plain = httpx.Client(http=hc, logger=d.logger)
        c.tokens = TokenSource(c.mint, now=c.now)
        c.api = httpx.Client(http=hc, base=base, logger=d.logger, auth=httpx.bearer_auth(c.bearer))
        return c


# -- helpers -------------------------------------------------------------------


def _fold(c: str) -> str:
    """The simple case folding of one rune (CaseFolding C+S)."""
    f = c.casefold()
    if len(f) == 1:
        return f
    lo = c.lower()
    return lo if len(lo) == 1 else c


def equal_fold(a: str, b: str) -> bool:
    """Go's strings.EqualFold: equal under simple Unicode case folding."""
    if len(a) != len(b):
        return False
    return all(x == y or _fold(x) == _fold(y) for x, y in zip(a, b, strict=True))


def _error_code(err: BaseException) -> str:
    """error_code from a Databricks error body snippet."""
    se = as_error(err, httpx.StatusError)
    if se is None:
        return ""
    m = ERROR_CODE_RE.search(se.snippet)
    return m.group(1) if m else ""


def _code_or(code: str, default: str) -> str:
    return default if code == "" else code


def classify(err: BaseException, what: str) -> HallpassError:
    """An API error as a HallpassError. 404 is left to the caller, who knows
    whether it means the object or the user."""
    st = httpx.status(err)
    if st == 401:
        return wrap_error(Code.CREDENTIAL_REJECTED, err, "the workspace rejected hallpass's credential")
    if st == 403:
        return wrap_error(
            Code.CREDENTIAL_REJECTED,
            err,
            f"the workspace refused to {what} ({_code_or(_error_code(err), 'PERMISSION_DENIED')}): hallpass's principal needs CAN_MANAGE "
            "on the object, or MANAGE, ownership or metastore admin for Unity Catalog grants",
        )
    if st == 400:
        return wrap_error(Code.INVALID_REQUEST, err, f"the workspace rejected the request to {what} ({_code_or(_error_code(err), 'BAD_REQUEST')})")
    if st == 404:
        return wrap_error(Code.UPSTREAM_ERROR, err, f"the workspace has no endpoint to {what}: check url ({_code_or(_error_code(err), 'NOT_FOUND')})")
    out = httpx.classify(err)
    assert out is not None
    return out


def _opt_bool(d: dict[str, Any], key: str) -> bool | None:
    """A *bool field: None when absent or null."""
    v = d.get(key)
    if v is None:
        for k, x in d.items():
            if k.lower() == key.lower():
                v = x
                break
    if v is None:
        return None
    if not isinstance(v, bool):
        raise jsonx.DecodeError(f"json: cannot unmarshal value into field {key} of type bool")
    return v


@dataclass(frozen=True)
class _SCIMGroup:
    display: str
    value: str


@dataclass(frozen=True)
class ScimUser:
    """The subset of a SCIM user hallpass reads."""

    id: str = ""
    user_name: str = ""
    # None when absent, so an absent field is not mistaken for false.
    active: bool | None = None
    groups: tuple[_SCIMGroup, ...] = ()

    def group_names(self) -> tuple[str, ...]:
        return tuple(sorted(g.display for g in self.groups if g.display != ""))

    def is_admin(self) -> bool:
        return any(g.display == ADMINS_GROUP for g in self.groups)


def _decode_scim_user(v: Any) -> ScimUser:
    d = jsonx.obj(v)
    groups = []
    for g in jsonx.arr(d, "groups"):
        g = jsonx.obj(g)
        groups.append(_SCIMGroup(jsonx.s(g, "display"), jsonx.s(g, "value")))
    return ScimUser(jsonx.s(d, "id"), jsonx.s(d, "userName"), _opt_bool(d, "active"), tuple(groups))


SCIM_ATTRIBUTES = "id,userName,active,groups"

# The Unity Catalog metadata endpoint of each securable type.
UC_COLLECTIONS = {"catalog": "catalogs", "schema": "schemas", "table": "tables", "volume": "volumes", "function": "functions", "model": "models"}


def _principal_matches(principal: str, user: str, groups: tuple[str, ...]) -> bool:
    """Whether an ACL or grant principal is the user or one of the user's
    groups."""
    if equal_fold(principal, user):
        return True
    return principal in groups


@dataclass(frozen=True)
class _EffectiveGrant:
    """One privilege the user holds and where it came from."""

    privilege: str
    principal: str
    frm: str


@dataclass
class _GrantListing:
    """What one effective-permissions read yields for the user."""

    held: HeldPrivileges = field(default_factory=HeldPrivileges)
    grants: list[_EffectiveGrant] = field(default_factory=list)
    # Some principal other than hallpass itself appears in the listing:
    # proof that hallpass sees more than its own grants.
    others: bool = False


def _describe_grants(grants: list[_EffectiveGrant], user: str) -> str:
    """Where the user's privileges come from, briefly."""
    seen: set[str] = set()
    parts: list[str] = []
    for g in grants:
        mine = equal_fold(g.principal, user)
        if mine and g.frm == "":
            s = "granted directly"
        elif mine:
            s = "inherited from " + g.frm
        elif g.frm == "":
            s = "via group " + g.principal
        else:
            s = "via group " + g.principal + " on " + g.frm
        if s not in seen:
            seen.add(s)
            parts.append(s)
    if len(parts) > 3:
        parts = [*parts[:3], "..."]
    return "; ".join(parts)


# -- the connection ------------------------------------------------------------


class DatabricksConnection(Connection):
    """One workspace."""

    def __init__(self, settings: Settings, base: str, mode: str, client_id: str, token_url: str, admins_rule: bool, now: Callable[[], float]) -> None:
        self.settings = settings
        self.base = base
        self.mode = mode
        self.client_id = client_id
        self.token_url = token_url
        self.admins_rule = admins_rule
        self.now = now
        self.plain: httpx.Client | None = None  # the token endpoint
        self.api: httpx.Client | None = None  # the workspace APIs
        self.tokens: TokenSource | None = None
        # hallpass's own principal name (a service principal's application
        # id, or a user's email), read from SCIM /Me and kept for SELF_TTL
        # under the empty key.
        self.self_cache: TTL[tuple[()], str] = TTL(1)

    # -- authentication --

    def bearer(self, ctx: Context) -> str:
        """The Authorization value: the cached OAuth token or the PAT."""
        if self.mode == MODE_TOKEN:
            try:
                t = self.settings.secret("credential").get_string()
            except SecretError as e:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the access token could not be read") from e
            return go_trim_space(t)
        assert self.tokens is not None
        try:
            return self.tokens.get(ctx)
        except Exception as e:  # noqa: BLE001 - classified and raised
            raise classify_token_error(e)

    def mint(self, ctx: Context) -> Token:
        """The client credentials grant: the client id and secret travel in
        an HTTP Basic header, as Databricks documents."""
        try:
            secret = self.settings.secret("credential").get_string()
        except SecretError as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the OAuth secret could not be read") from e
        basic = base64.b64encode((self.client_id + ":" + go_trim_space(secret)).encode("utf-8", "surrogateescape")).decode()
        assert self.plain is not None
        return fetch_token(
            ctx,
            self.plain,
            TokenRequest(
                url=self.token_url,
                form={"grant_type": "client_credentials", "scope": SCOPE_ALL_APIS},
                header={"Authorization": "Basic " + basic},
                now=self.now,
            ),
        )

    # -- API transport --

    def _get_json(self, ctx: Context, path: str, q: Mapping[str, str | list[str]] | None, decode: Callable[[Any], T]) -> T:
        """One GET with JSON decoding. In oauth mode a 401 drops the cached
        token and retries once with a fresh one. A 404 comes back as the raw
        httpx error so the caller can name what is missing."""
        assert self.api is not None and self.tokens is not None
        req = httpx.Request(method="GET", path=path, query=q)
        try:
            resp = self.api.do(ctx, req)
        except Exception as e:
            if not (httpx.status(e) == 401 and self.mode == MODE_OAUTH):
                raise
            self.tokens.invalidate()
            resp = self.api.do(ctx, req)
        try:
            return decode(resp.json())
        except ValueError as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, "the workspace returned an unreadable response") from e

    # -- identity --

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """The workspace user whose userName is the email."""
        email = go_lower(go_trim_space(u.email))
        if not is_email(email):
            raise errorf(Code.INVALID_REQUEST, f"user email {go_quote(email)} is not an address")
        # is_email admits no quote or backslash, so the filter cannot be
        # broken out of.
        q = {"filter": 'userName eq "' + email + '"', "attributes": SCIM_ATTRIBUTES}
        try:
            resources = self._get_json(ctx, SCIM_USERS, q, lambda v: [_decode_scim_user(r) for r in jsonx.arr(jsonx.obj(v), "Resources")])
        except Exception as e:  # noqa: BLE001 - classified and raised
            raise classify(e, "search users")
        matches = [r for r in resources if equal_fold(r.user_name, email)]
        if not matches:
            raise user_not_found(f"no workspace user with email {email}")
        if len(matches) > 1:
            raise user_ambiguous(f"{len(matches)} workspace users match {email}")
        m = matches[0]
        active = "unknown"
        if m.active is not None:
            active = "true" if m.active else "false"
        return Identity(
            id=go_lower(m.user_name),
            display=m.user_name,
            attrs={"id": m.id, "active": active, "admin": "true" if m.is_admin() else "false"},
            groups=m.group_names(),
        )

    def _me(self, ctx: Context) -> ScimUser:
        """hallpass's own SCIM record."""
        try:
            return self._get_json(ctx, SCIM_ME, {"attributes": SCIM_ATTRIBUTES}, _decode_scim_user)
        except Exception as e:  # noqa: BLE001 - classified and raised
            raise classify(e, "read its own identity")

    def _self_name(self, ctx: Context) -> str:
        """hallpass's own principal name as it appears in grants, cached for
        SELF_TTL. It is needed to tell an empty grant listing from one Unity
        Catalog has filtered down to hallpass's own grants."""

        def fill(ctx: Context) -> tuple[str, float]:
            me = self._me(ctx)
            if me.user_name == "":
                raise errorf(Code.UPSTREAM_ERROR, "the workspace did not report hallpass's own principal name")
            return go_lower(me.user_name), SELF_TTL

        return self.self_cache.do(ctx, (), fill)

    # -- checks --

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        q = parse_ref(r.action_name, r.resource)
        user = go_lower(r.identity.id)
        if not is_email(user):
            raise errorf(Code.INVALID_REQUEST, "identity is not a workspace user")
        active = r.identity.attr("active")
        if active == "false":
            return denied(f"{user} is deactivated in the workspace")
        if active != "true":
            return unsupported(f"the workspace did not report whether {user} is active")
        if q.uc:
            return self._check_unity_catalog(ctx, q, user, r.identity, r.resource.raw)
        return self._check_workspace_object(ctx, q, user, r.identity, r.resource.raw)

    def _read_grants(self, ctx: Context, q: Ref, user: str, groups: tuple[str, ...], me: str) -> _GrantListing:
        """Every page of the securable's effective permissions, keeping the
        privileges of the user and of the user's groups."""
        out = _GrantListing()
        path = "/api/2.1/unity-catalog/effective-permissions/" + httpx.path_escape(q.securable) + "/" + httpx.path_escape(q.full_name)
        # max_results=0 asks for the server's page size; every page is followed.
        query: dict[str, str | list[str]] = {"max_results": "0"}
        n = 0
        while True:
            if n >= httpx.MAX_PAGES:
                raise errorf(Code.UPSTREAM_ERROR, f"too many pages of grants on {q.securable} {q.full_name}")
            assignments, next_token = self._get_json(ctx, path, query, _decode_grants_page)
            for principal, privileges in assignments:
                if not equal_fold(principal, me):
                    out.others = True
                if not _principal_matches(principal, user, groups):
                    continue
                for privilege, from_type, from_name in privileges:
                    frm, scope = "", q.securable
                    if from_type != "":
                        scope = go_lower(from_type)
                        frm = scope + " " + from_name
                    if privilege == PRIV_ALL_PRIVILEGES:
                        out.held.all_on.append(scope)
                    else:
                        out.held.named.add(privilege)
                    out.grants.append(_EffectiveGrant(privilege, principal, frm))
            if next_token == "":
                return out
            query = {"max_results": "0", "page_token": next_token}
            n += 1

    def _check_unity_catalog(self, ctx: Context, q: Ref, user: str, ident: Identity, raw: str) -> Decision:
        """Read the securable's effective permissions, union the privileges
        granted to the user and to the user's groups, and fall back to
        ownership when they do not cover the action."""
        me = self._self_name(ctx)
        what = q.securable + " " + q.full_name
        try:
            listing = self._read_grants(ctx, q, user, ident.groups, me)
        except Exception as e:  # noqa: BLE001 - Go: a 404 is decided on, everything else classified
            if httpx.status(e) == 404:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"{what} does not exist or hallpass cannot see it")
            raise classify(e, "read the grants on " + what)
        need = ", ".join(q.privileges) + " on " + raw
        ok, _ = satisfies_privileges(listing.held, q.privileges)
        if ok:
            return allowed(f"{user} holds {need} ({_describe_grants(listing.grants, user)})")
        # UNVERIFIED: whether effective-permissions already lists the owner's
        # implicit privileges; the owner is looked up separately so an owner
        # is never denied.
        try:
            owner = self._owner(ctx, q)
        except Exception as e:  # noqa: BLE001 - Go: a 404 is decided on, everything else classified
            if httpx.status(e) == 404:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"{what} does not exist or hallpass cannot see it")
            raise classify(e, "read " + what)
        if owner != "" and _principal_matches(owner, user, ident.groups):
            # Ownership stands for every privilege on the securable itself,
            # MANAGE included, not for USE_CATALOG or USE_SCHEMA on its parents.
            held = HeldPrivileges(named=set(listing.held.named), all_on=list(listing.held.all_on))
            for p in q.privileges:
                if covers(q.securable, p, True):
                    held.named.add(p)
            ok, missing = satisfies_privileges(held, q.privileges)
            if ok:
                return allowed(f"{user} owns {what} (owner {owner}), which carries {', '.join(q.privileges)}")
            return denied(f"{user} owns {what} but lacks {', '.join(missing)} on its parents")
        if not listing.others:
            # Unity Catalog shows a principal without MANAGE or ownership only
            # its own grants, with a 200. A listing with nobody but hallpass
            # in it is either that or a securable nobody has grants on;
            # hallpass cannot tell, so it does not deny.
            return unknown_decision(
                Code.RESOURCE_NOT_VISIBLE,
                f"the grants on {what} list no principal but hallpass itself: either nobody else holds any, or hallpass may only see its own; "
                "give hallpass MANAGE on the catalog to be sure",
            )
        _, missing = satisfies_privileges(listing.held, q.privileges)
        return denied(f"{user} lacks {', '.join(missing)} on {raw}")

    def _owner(self, ctx: Context, q: Ref) -> str:
        """The securable's owner: a user email or a group name."""
        return self._get_json(
            ctx,
            "/api/2.1/unity-catalog/" + UC_COLLECTIONS.get(q.securable, "") + "/" + httpx.path_escape(q.full_name),
            None,
            lambda v: jsonx.s(jsonx.obj(v), "owner"),
        )

    def _check_workspace_object(self, ctx: Context, q: Ref, user: str, ident: Identity, raw: str) -> Decision:
        """Read the object's ACL and look for a level, held by the user or one
        of the user's groups, that implies the one needed."""
        path = "/api/2.0/permissions/" + q.object + "/" + httpx.path_escape(q.id)
        try:
            entries = self._get_json(ctx, path, None, _decode_acl)
        except Exception as e:  # noqa: BLE001 - Go: a 404 is decided on, everything else classified
            if httpx.status(e) == 404:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"{q.object} {q.id} does not exist or hallpass cannot see it")
            raise classify(e, "read the permissions of " + q.object + " " + q.id)
        held: list[str] = []
        via: dict[str, str] = {}
        for user_name, group_name, levels in entries:
            principal = user_name or group_name
            if principal == "" or not _principal_matches(principal, user, ident.groups):
                continue
            for level in levels:
                held.append(level)
                via.setdefault(level, principal)
        what = q.level + " on " + raw
        ok, by = satisfies_level(held, q.level, q.chains)
        if ok:
            how = "granted directly"
            if not equal_fold(via.get(by, ""), user):
                how = "via group " + via.get(by, "")
            if by == q.level:
                return allowed(f"{user} holds {what} ({how})")
            return allowed(f"{user} holds {by}, which implies {what} ({how})")
        if self.admins_rule and ident.attr("admin") == "true" and q.level != "IS_OWNER":
            return allowed(f"{user} is a workspace admin, which carries CAN_MANAGE on every object, so {what}")
        if not held:
            return denied(f"{user} has no permission on {raw}")
        return denied(f"{user} holds only {', '.join(sorted(set(held)))} on {raw}, not {q.level}")

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """Read hallpass's own SCIM record and report whether it is a
        workspace admin, which decides how much of the workspace it can read."""
        me = self._me(ctx)
        who = me.user_name or "principal " + me.id
        admin = me.is_admin()
        warnings: list[str] = []
        if not admin:
            warnings.append(
                "hallpass's principal is not a workspace admin: workspace objects it lacks CAN_MANAGE on and Unity Catalog securables "
                "it does not own or MANAGE answer unknown"
            )
        else:
            warnings.append(
                "hallpass's principal is a workspace admin, which can also change the workspace; Databricks has no read-only admin role, "
                "so keep the credential tightly held"
            )
        if not self.admins_rule:
            warnings.append("admins_manage_all is false: workspace admins are judged by the object ACL alone, which may omit their implicit CAN_MANAGE")
        return ProbeResult(summary=f"authenticated as {who} in {self.base} (workspace admin: {'true' if admin else 'false'})", warnings=tuple(warnings))


def _decode_grants_page(v: Any) -> tuple[list[tuple[str, list[tuple[str, str, str]]]], str]:
    d = jsonx.obj(v)
    out = []
    for a in jsonx.arr(d, "privilege_assignments"):
        a = jsonx.obj(a)
        privs = []
        for p in jsonx.arr(a, "privileges"):
            p = jsonx.obj(p)
            privs.append((jsonx.s(p, "privilege"), jsonx.s(p, "inherited_from_type"), jsonx.s(p, "inherited_from_name")))
        out.append((jsonx.s(a, "principal"), privs))
    return out, jsonx.s(d, "next_page_token")


def _decode_acl(v: Any) -> list[tuple[str, str, list[str]]]:
    d = jsonx.obj(v)
    jsonx.s(d, "object_id")
    out = []
    for e in jsonx.arr(d, "access_control_list"):
        e = jsonx.obj(e)
        jsonx.s(e, "service_principal_name")
        levels = []
        for p in jsonx.arr(e, "all_permissions"):
            p = jsonx.obj(p)
            jsonx.b(p, "inherited")
            levels.append(jsonx.s(p, "permission_level"))
        out.append((jsonx.s(e, "user_name"), jsonx.s(e, "group_name"), levels))
    return out
