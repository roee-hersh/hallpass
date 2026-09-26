"""Checks Azure role-based access control: may this user perform this
resource provider operation at this scope.

hallpass authenticates as an app registration, resolves the user to an
Entra object id (through a microsoft365 connection or its own Graph call),
lists the role assignments and deny assignments that apply to the user at
the scope, including inherited ones and ones through groups, and evaluates
the role definitions' actions and notActions the way Azure Resource
Manager does. Deny assignments win; assignments with an ABAC condition
answer unknown rather than allowed or denied. Nothing is written.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from hallpass.authx.oauth2 import TokenError, classify_token_error, client_credentials
from hallpass.authx.token import TokenSource
from hallpass.authx.util import go_json_loads
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
    connection_ref_field,
    credential_field,
)
from hallpass.core.jsonx import _get as _json_member
from hallpass.core.template import is_email
from hallpass.integrations.azure.actions import GUID_RE, Target, catalog_actions, equal_fold, match_action, parse_target
from hallpass.net import httpx

__all__ = [
    "API_VERSION",
    "DEFAULT_ARM",
    "DEFAULT_AUTHORITY",
    "DEFAULT_GRAPH",
    "Azure",
    "AzureConnection",
    "Permission",
    "covers",
    "error_code",
    "match_operation",
]

DEFAULT_ARM = "https://management.azure.com"
DEFAULT_GRAPH = "https://graph.microsoft.com"
DEFAULT_AUTHORITY = "https://login.microsoftonline.com"
API_VERSION = "2022-04-01"

# How long a role definition is kept.
ROLE_TTL = 300.0

_TENANT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,254}")

T = TypeVar("T")


class Azure(Integration):
    """The azure product."""

    def name(self) -> str:
        return "azure"

    def fields(self) -> list[Field]:
        return [
            Field(name="tenant_id", required=True, description="the Entra tenant id (GUID) or domain"),
            Field(name="client_id", required=True, description="the app registration's application (client) id"),
            credential_field(True, "the app registration's client secret"),
            connection_ref_field(
                "microsoft365_connection",
                "microsoft365",
                False,
                "resolve users through this microsoft365 connection instead of Graph with hallpass's own app registration",
            ),
            Field(name="url", default=DEFAULT_ARM, description="the Azure Resource Manager endpoint"),
            Field(name="graph_url", default=DEFAULT_GRAPH, description="the Microsoft Graph endpoint, when users are resolved here"),
            Field(name="authority_url", default=DEFAULT_AUTHORITY, description="the Entra token authority"),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def match_action(self, name: str) -> Action | None:
        return match_action(name)

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network."""
        hc = d.http_client(s)
        if s.secret("credential").is_zero():
            raise ValueError("credential is required")
        tenant, client_id = go_trim_space(s.get("tenant_id")), go_trim_space(s.get("client_id"))
        if not _TENANT_RE.fullmatch(tenant):
            raise ValueError("tenant_id must be a GUID or a domain")
        if not GUID_RE.fullmatch(client_id):
            raise ValueError("client_id must be a GUID")

        def base(key: str, default: str) -> str:
            v = go_trim_space(s.get(key)).rstrip("/")
            if v == "":
                v = default
            if not v.startswith("https://") and not v.startswith("http://"):
                raise ValueError(f"{key} must be an http(s) URL")
            return v

        arm = base("url", DEFAULT_ARM)
        graph = base("graph_url", DEFAULT_GRAPH)
        authority = base("authority_url", DEFAULT_AUTHORITY)
        c = AzureConnection(now=d.now)
        cred = s.secret("credential")
        token_url = authority + "/" + httpx.path_escape(tenant) + "/oauth2/v2.0/token"
        plain = httpx.Client(http=hc, logger=d.logger)

        def secret(ctx: Context) -> str:
            return cred.get_string()

        def source(scope: str) -> TokenSource:
            return TokenSource(client_credentials(plain, token_url, client_id, secret, scope), now=c.now)

        c.arm_tokens = source(arm + "/.default")
        c.arm = httpx.Client(http=hc, base=arm, logger=d.logger, auth=httpx.bearer_auth(c.arm_tokens.get))
        ref = s.get("microsoft365_connection")
        if ref != "":
            try:
                c.identity = d.connection(ref)
            except Exception as e:
                if is_panic_type(e):
                    raise
                raise ValueError(f"microsoft365_connection: {e}") from e
        else:
            c.graph_tokens = source(graph + "/.default")
            c.graph = httpx.Client(http=hc, base=graph, logger=d.logger, auth=httpx.bearer_auth(c.graph_tokens.get))
        return c


# -- transport ---------------------------------------------------------------


def error_code(err: BaseException) -> str:
    """error.code from a status error's snippet."""
    se = as_error(err, httpx.StatusError)
    if se is None:
        return ""
    snippet = se.snippet
    try:
        code = jsonx.s(jsonx.o(jsonx.obj(go_json_loads(snippet)), "error"), "code")
    except (ValueError, RecursionError):
        code = ""
    if code != "":
        return code
    i = snippet.find('"code"')
    if i < 0:
        return ""
    rest = snippet[i + len('"code"') :].lstrip(" :")
    if not rest.startswith('"'):
        return ""
    rest = rest[1:]
    j = rest.find('"')
    if j >= 0:
        return rest[:j]
    return ""


def _classify_token(err: BaseException) -> HallpassError:
    te = as_error(err, TokenError)
    if te is not None:
        if te.status == 429:
            return wrap_error(Code.UPSTREAM_RATE_LIMIT, err, "the token endpoint rate limited hallpass")
        if te.status >= 500:
            return wrap_error(Code.UPSTREAM_ERROR, err, f"the token endpoint failed (HTTP {te.status})")
    return classify_token_error(err)


def _or_empty(s: str, default: str) -> str:
    return default if s == "" else s


def _bad_constant(name: str) -> Any:
    raise ValueError(f"invalid character '{name[0]}' looking for beginning of value")


def _decode_body(body: bytes) -> Any:
    """httpx.Response.JSON: the first JSON value of the body (a streaming
    decoder ignores what follows it); no NaN or Infinity."""
    text = body.decode("utf-8", "replace")
    stripped = text.lstrip(" \t\r\n")
    if not stripped:
        raise ValueError("empty body")
    v, _ = json.JSONDecoder(parse_constant=_bad_constant).raw_decode(stripped)
    return v


# -- decoding (Go's typed structs: a wrong type anywhere is an error) --------


@dataclass(frozen=True)
class Permission:
    actions: tuple[str, ...] = ()
    not_actions: tuple[str, ...] = ()
    data_actions: tuple[str, ...] = ()
    not_data_actions: tuple[str, ...] = ()
    condition: str = ""

    def grants(self, op: str, data: bool) -> bool:
        """Whether the permission grants op: an action matches and no
        notAction subtracts it."""
        allow, deny = (self.data_actions, self.not_data_actions) if data else (self.actions, self.not_actions)
        if not any(match_operation(a, op) for a in allow):
            return False
        return not any(match_operation(n, op) for n in deny)


def _permission(v: Any) -> Permission:
    d = jsonx.obj(v)
    return Permission(
        actions=tuple(jsonx.strs(d, "actions")),
        not_actions=tuple(jsonx.strs(d, "notActions")),
        data_actions=tuple(jsonx.strs(d, "dataActions")),
        not_data_actions=tuple(jsonx.strs(d, "notDataActions")),
        condition=jsonx.s(d, "condition"),
    )


def _permissions(d: dict[str, Any]) -> list[Permission]:
    return [_permission(p) for p in jsonx.arr(d, "permissions")]


@dataclass(frozen=True)
class RoleDefinition:
    id: str = ""
    role_name: str = ""
    type: str = ""
    permissions: tuple[Permission, ...] = ()


def _role_definition(v: Any) -> RoleDefinition:
    d = jsonx.obj(v)
    props = jsonx.o(d, "properties")
    return RoleDefinition(
        id=jsonx.s(d, "id"),
        role_name=jsonx.s(props, "roleName"),
        type=jsonx.s(props, "type"),
        permissions=tuple(_permissions(props)),
    )


@dataclass(frozen=True)
class RoleAssignment:
    id: str = ""
    scope: str = ""
    role_definition_id: str = ""
    principal_id: str = ""
    principal_type: str = ""
    condition: str = ""


def _role_assignment(v: Any) -> RoleAssignment:
    d = jsonx.obj(v)
    props = jsonx.o(d, "properties")
    return RoleAssignment(
        id=jsonx.s(d, "id"),
        scope=jsonx.s(props, "scope"),
        role_definition_id=jsonx.s(props, "roleDefinitionId"),
        principal_id=jsonx.s(props, "principalId"),
        principal_type=jsonx.s(props, "principalType"),
        condition=jsonx.s(props, "condition"),
    )


@dataclass(frozen=True)
class Principal:
    id: str = ""
    type: str = ""


def _principals(d: dict[str, Any], key: str) -> list[Principal]:
    out = []
    for p in jsonx.arr(d, key):
        m = jsonx.obj(p)
        out.append(Principal(id=jsonx.s(m, "id"), type=jsonx.s(m, "type")))
    return out


@dataclass
class DenyAssignment:
    id: str = ""
    name: str = ""
    scope: str = ""
    do_not_apply_to_child_scopes: bool = False
    permissions: list[Permission] = field(default_factory=list)
    principals: list[Principal] = field(default_factory=list)
    exclude_principals: list[Principal] = field(default_factory=list)
    condition: str = ""


def _deny_assignment(v: Any) -> DenyAssignment:
    d = jsonx.obj(v)
    props = jsonx.o(d, "properties")
    return DenyAssignment(
        id=jsonx.s(d, "id"),
        name=jsonx.s(props, "denyAssignmentName"),
        scope=jsonx.s(props, "scope"),
        do_not_apply_to_child_scopes=jsonx.b(props, "doNotApplyToChildScopes"),
        permissions=_permissions(props),
        principals=_principals(props, "principals"),
        exclude_principals=_principals(props, "excludePrincipals"),
        condition=jsonx.s(props, "condition"),
    )


@dataclass(frozen=True)
class GraphUser:
    id: str = ""
    user_principal_name: str = ""
    mail: str = ""
    account_enabled: bool | None = None


def _graph_users(v: Any) -> list[GraphUser]:
    out = []
    for u in jsonx.arr(jsonx.obj(v), "value"):
        d = jsonx.obj(u)
        enabled = jsonx.b(d, "accountEnabled")  # validates the type
        out.append(
            GraphUser(
                id=jsonx.s(d, "id"),
                user_principal_name=jsonx.s(d, "userPrincipalName"),
                mail=jsonx.s(d, "mail"),
                # *bool: null or absent is "not reported".
                account_enabled=None if _json_member(d, "accountEnabled") is None else enabled,
            )
        )
    return out


def _listing(v: Any) -> tuple[list[Any], str]:
    d = jsonx.obj(v)
    return jsonx.arr(d, "value"), jsonx.s(d, "nextLink")


def _odata_string(s: str) -> str:
    """A string literal for $filter: ' is doubled."""
    return "'" + s.replace("'", "''") + "'"


# -- evaluation --------------------------------------------------------------


def match_operation(pattern: str, op: str) -> bool:
    """Whether pattern (with * wildcards) matches op.
    UNVERIFIED: the documentation's examples mix case (microsoft.web/sites/
    restart/Action) and show * spanning slashes (*/read, Microsoft.Compute/*),
    so operations compare case-insensitively and * spans any characters."""
    pattern, op = go_lower(pattern), go_lower(op)
    parts = pattern.split("*")
    if len(parts) == 1:
        return pattern == op
    if not op.startswith(parts[0]):
        return False
    op = op[len(parts[0]) :]
    for p in parts[1:-1]:
        j = op.find(p)
        if j < 0:
            return False
        op = op[j + len(p) :]
    return op.endswith(parts[-1])


def covers(assigned: str, target: str, exact: bool) -> tuple[bool, bool]:
    """Whether an assignment at assigned applies to the target scope: the
    same scope or an ancestor. Management groups and the tenant root are
    ancestors of every subscription; which management group holds a
    subscription is not read, so any management-group assignment ARM
    returned for a subscription-or-lower target is taken as inherited.
    exact restricts to the same scope (doNotApplyToChildScopes). Returns
    (applies, uncertain)."""
    if go_trim_space(assigned) == "":
        # An assignment without a scope is malformed; it neither applies
        # nor can be ruled out.
        return False, True
    a, t = go_lower(assigned.rstrip("/")), go_lower(target.rstrip("/"))
    if a == t:
        return True, False
    if exact:
        return False, False
    if a == "":
        return True, False  # the tenant root, "/"

    def is_mg(s: str) -> bool:
        return s.startswith("/providers/microsoft.management/managementgroups/")

    if is_mg(a) and t.startswith("/subscriptions/"):
        return True, False
    if is_mg(a) and is_mg(t):
        # A different management group: an ancestor or a descendant; the
        # hierarchy is not read.
        return False, True
    return t.startswith(a + "/"), False


@dataclass
class _Grant:
    """What the role assignments say."""

    # role, scope and via describe the first unconditional grant.
    role: str = ""
    scope: str = ""
    via: str = ""
    # Roles that grant only under a condition, or at a management group of
    # unknown relation.
    conditional: str = ""
    uncertain: str = ""
    # The assignments at or above the scope.
    covering: int = 0


class AzureConnection(Connection):
    """One tenant's Azure Resource Manager."""

    def __init__(self, now: Callable[[], float]) -> None:
        self.now = now
        self.roles: TTL[str, RoleDefinition] = TTL(0)
        self.roles.set_clock(now)
        self.arm: httpx.Client
        self.graph: httpx.Client | None = None
        self.arm_tokens: TokenSource
        self.graph_tokens: TokenSource | None = None
        # The microsoft365 connection that resolves users, when configured;
        # graph is used otherwise.
        self.identity: Connection | None = None

    # -- transport --

    def _get_json(
        self,
        ctx: Context,
        client: httpx.Client,
        tokens: TokenSource,
        path: str,
        q: dict[str, str] | None,
        decode: Callable[[Any], T],
        not_found: Callable[[], HallpassError] | None,
    ) -> T:
        """One GET against client, retried once after a 401 with a fresh
        token. not_found builds the error for a 404."""
        remedy = "it needs Reader (Microsoft.Authorization/*/read) at or above the scope"
        if client is self.graph:
            remedy = "it needs the Graph application permission User.Read.All, or set microsoft365_connection"
        req = httpx.Request(path=path, query=q)

        def attempt() -> tuple[httpx.Response | None, Exception | None]:
            try:
                return client.do(ctx, req), None
            except Exception as e:
                if is_panic_type(e):
                    raise
                return None, e

        resp, err = attempt()
        if err is not None and httpx.status(err) == 401:
            tokens.invalidate()
            resp, err = attempt()
        if err is not None:
            if as_error(err, TokenError) is not None:
                raise _classify_token(err) from err
            st = httpx.status(err)
            if st == 404:
                if not_found is not None:
                    raise not_found() from err
            elif st == 401:
                raise wrap_error(Code.CREDENTIAL_REJECTED, err, "the token was rejected (HTTP 401)") from err
            elif st == 403:
                # AuthorizationFailed on a scope: the app registration holds
                # no Reader there, so the scope is invisible to hallpass.
                if not_found is not None and error_code(err) == "AuthorizationFailed":
                    raise not_found() from err
                raise wrap_error(
                    Code.CREDENTIAL_REJECTED,
                    err,
                    f"the app registration may not read this (HTTP 403, {_or_empty(error_code(err), 'no code')}); {remedy}",
                ) from err
            elif st == 400:
                raise wrap_error(Code.INVALID_REQUEST, err, f"the request was rejected (HTTP 400, {_or_empty(error_code(err), 'no code')})") from err
            out = httpx.classify(err)
            assert out is not None
            raise out from err
        assert resp is not None
        try:
            return decode(_decode_body(resp.body))
        except (ValueError, RecursionError) as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, "the response was not JSON") from e

    def _list_arm(self, ctx: Context, path: str, filter: str, not_found: Callable[[], HallpassError] | None) -> list[Any]:
        """Page through an ARM collection at path with the filter, following
        nextLink while it stays under the ARM endpoint."""
        items: list[Any] = []
        q: dict[str, str] | None = {"api-version": API_VERSION, "$filter": filter}
        nxt = path
        page = 0
        while nxt != "":
            if page >= httpx.MAX_PAGES:
                raise errorf(Code.UPSTREAM_ERROR, f"the listing at {path} has more pages than hallpass follows")
            value, nxt = self._get_json(ctx, self.arm, self.arm_tokens, nxt, q, _listing, not_found)
            items.extend(value)
            q = None
            if nxt != "" and not self.arm.within(nxt):
                raise errorf(Code.UPSTREAM_ERROR, "the listing sent a next link outside the ARM endpoint")
            page += 1
        return items

    # -- identity --

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """The user's Entra object id, through the microsoft365 connection
        when configured, else by mail or UPN in Graph."""
        if self.identity is not None:
            ident = self.identity.resolve_identity(ctx, u)
            if not GUID_RE.fullmatch(ident.id):
                raise errorf(Code.UPSTREAM_ERROR, "the microsoft365 connection returned an identity that is not an object id")
            return ident
        email = go_lower(go_trim_space(u.email))
        if not is_email(email):
            raise errorf(Code.INVALID_REQUEST, f"user email {go_quote(email)} is not an address")
        lit = _odata_string(email)
        q = {
            "$filter": "mail eq " + lit + " or userPrincipalName eq " + lit,
            "$select": "id,userPrincipalName,mail,accountEnabled",
        }
        assert self.graph is not None and self.graph_tokens is not None
        users = self._get_json(ctx, self.graph, self.graph_tokens, "/v1.0/users", q, _graph_users, None)
        matches = [usr for usr in users if equal_fold(usr.mail, email) or equal_fold(usr.user_principal_name, email)]
        if not matches:
            raise user_not_found(f"no Entra user has mail or UPN {email}")
        if len(matches) > 1:
            raise user_ambiguous(f"{len(matches)} Entra users have mail or UPN {email}")
        usr = matches[0]
        if not GUID_RE.fullmatch(usr.id):
            raise errorf(Code.UPSTREAM_ERROR, "Graph returned a user id that is not an object id")
        enabled = "unknown"
        if usr.account_enabled is not None:
            enabled = "true" if usr.account_enabled else "false"
        return Identity(
            id=go_lower(usr.id),
            display=email,
            attrs={"upn": usr.user_principal_name, "mail": usr.mail, "account_enabled": enabled},
        )

    # -- RBAC data --

    _ROLE_DEFINITION_ID_RE = re.compile(r"(/[A-Za-z0-9_.()-]+)*/providers/Microsoft\.Authorization/roleDefinitions/[0-9a-fA-F-]{36}")

    def _role_definition(self, ctx: Context, scope: str, rid: str) -> RoleDefinition:
        """The role definition an assignment names, read by its GUID at the
        target scope (built-in definitions are readable at every scope,
        custom ones at the scopes they are assignable to), cached for ROLE_TTL."""
        if not self._ROLE_DEFINITION_ID_RE.fullmatch(rid):
            raise errorf(Code.UPSTREAM_ERROR, "a role assignment names a role definition id of an unexpected shape")
        guid = go_lower(rid[rid.rfind("/") + 1 :])

        def fill(ctx: Context) -> tuple[RoleDefinition, float]:
            path = scope + "/providers/Microsoft.Authorization/roleDefinitions/" + guid

            def not_found() -> HallpassError:
                return errorf(Code.UPSTREAM_ERROR, f"role definition {guid} is assigned but cannot be read at {scope}")

            d = self._get_json(ctx, self.arm, self.arm_tokens, path, {"api-version": API_VERSION}, _role_definition, not_found)
            return d, ROLE_TTL

        return self.roles.do(ctx, guid, fill)

    # -- evaluation --

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """The role assignments decide whether anything grants the
        operation; when something does, the deny assignments are read and
        may block it."""
        t = parse_target(r.action_name, r.resource)
        ident = r.identity
        who = ident.display
        enabled = ident.attr("account_enabled")
        if enabled == "false":
            return denied(f"{who}'s account is disabled")
        if enabled != "true":
            return unsupported(f"whether {who}'s account is enabled was not reported")
        oid = go_lower(ident.id)
        if not GUID_RE.fullmatch(oid):
            raise errorf(Code.UPSTREAM_ERROR, "the identity carries no object id")
        flt = "assignedTo('" + oid + "')"
        op = t.action.operation

        def not_visible() -> HallpassError:
            return errorf(Code.RESOURCE_NOT_VISIBLE, f"{t} does not exist or hallpass cannot read its assignments (it needs Reader there)")

        grant = self._role_grant(ctx, t, oid, flt, not_visible)
        if grant.role == "" and grant.conditional == "" and grant.uncertain == "":
            if grant.covering == 0:
                return denied(f"{who} has no role assignment at or above {t}")
            return denied(f"none of {who}'s {grant.covering} role assignment(s) at or above {t} grants {op}")

        # Something grants, or might: a deny wins over all of it.
        blocked, uncertain_deny = self._denied(ctx, t, oid, flt, not_visible)
        if blocked is not None:
            return denied(f"deny assignment {go_quote(blocked.name)} at {blocked.scope} blocks {op} for {who}")
        if grant.role != "":
            if uncertain_deny != "":
                return unsupported(
                    f"role {go_quote(grant.role)} grants {op} to {who} at {grant.scope}, but deny assignment {go_quote(uncertain_deny)} "
                    "may block it (a condition, an excluded group or a scope hallpass cannot place)"
                )
            return allowed(f"role {go_quote(grant.role)} assigned {grant.via} at {grant.scope} grants {op} to {who}")
        if grant.conditional != "":
            return unsupported(f"role {go_quote(grant.conditional)} grants {op} to {who} only under an ABAC condition hallpass does not evaluate")
        return unsupported(f"role {go_quote(grant.uncertain)} grants {op} to {who} at a management group whose place above {t} hallpass cannot tell")

    def _role_grant(self, ctx: Context, t: Target, oid: str, flt: str, not_found: Callable[[], HallpassError]) -> _Grant:
        """List the user's role assignments and evaluate the covering ones
        against the operation."""
        g = _Grant()
        raw = self._list_arm(ctx, t.scope + "/providers/Microsoft.Authorization/roleAssignments", flt, not_found)
        for item in raw:
            try:
                a = _role_assignment(item)
            except ValueError as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "a role assignment could not be decoded") from e
            applies, uncertain = covers(a.scope, t.scope, False)
            if not applies and not uncertain:
                continue
            g.covering += 1
            d = self._role_definition(ctx, t.scope, a.role_definition_id)
            if not any(p.grants(t.action.operation, t.action.data) for p in d.permissions):
                continue
            name = _or_empty(d.role_name, d.id)
            if uncertain:
                if g.uncertain == "":
                    g.uncertain = name
            elif a.condition != "":
                if g.conditional == "":
                    g.conditional = name
            else:
                if g.role != "":
                    continue
                g.role, g.scope, g.via = name, a.scope, "directly"
                if not equal_fold(a.principal_id, oid):
                    g.via = "through " + go_lower(_or_empty(a.principal_type, "group")) + " " + a.principal_id
        return g

    def _denied(self, ctx: Context, t: Target, oid: str, flt: str, not_found: Callable[[], HallpassError]) -> tuple[DenyAssignment | None, str]:
        """The deny assignments that apply to the user at the scope: the
        first that certainly blocks the operation, else the name of one
        that might (a condition, an excluded group, an unplaceable scope)."""
        raw = self._list_arm(ctx, t.scope + "/providers/Microsoft.Authorization/denyAssignments", flt, not_found)
        uncertain_name = ""
        for item in raw:
            try:
                d = _deny_assignment(item)
            except ValueError as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "a deny assignment could not be decoded") from e
            applies, uncertain = covers(d.scope, t.scope, d.do_not_apply_to_child_scopes)
            if not applies and not uncertain:
                continue
            matched, conditional = False, d.condition != ""
            for p in d.permissions:
                if p.grants(t.action.operation, t.action.data):
                    matched = True
                    if p.condition != "":
                        conditional = True
            if not matched:
                continue
            # UNVERIFIED: whether assignedTo() already leaves out denies whose
            # excludePrincipals name the user; applying them again is safe.
            excluded = exclude_unknown = False
            for pr in d.exclude_principals:
                if equal_fold(pr.id, oid):
                    excluded = True
                elif equal_fold(pr.type, "User") or equal_fold(pr.type, "ServicePrincipal"):
                    pass  # another principal, not this user
                else:
                    exclude_unknown = True  # a group: whether it holds the user is not read
            if excluded:
                continue
            d.name = _or_empty(d.name, "unnamed")
            if uncertain or exclude_unknown or conditional:
                if uncertain_name == "":
                    uncertain_name = d.name
                continue
            return d, ""
        return None, uncertain_name

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """Fetch an ARM token and list role definitions at the tenant root
        (UNVERIFIED: the form az role definition list uses; the
        specification file has no path for it), and a Graph user page when
        identity is local."""
        defs = self._list_arm(ctx, "/providers/Microsoft.Authorization/roleDefinitions", "type eq 'BuiltInRole'", None)
        summary = f"authenticated to Azure Resource Manager; {len(defs)} built-in role definitions visible"
        if self.identity is None:
            assert self.graph is not None and self.graph_tokens is not None
            self._get_json(ctx, self.graph, self.graph_tokens, "/v1.0/users", {"$top": "1", "$select": "id"}, _graph_users, None)
            summary += "; Graph user listing works"
        return ProbeResult(
            summary=summary,
            warnings=(
                "role and deny assignments are visible only where the app registration holds Reader (Microsoft.Authorization/*/read); "
                "scopes it cannot read answer resource_not_visible",
                "assignments with ABAC conditions and deny assignments excluding groups answer unknown",
            ),
        )
