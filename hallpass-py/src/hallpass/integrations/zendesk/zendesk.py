"""Checks what a team member may do in one Zendesk Support account.

hallpass authenticates as an administrator (an API token or an OAuth
token), finds the user by email and reads the role, the custom role's
configuration on Enterprise plans or the ticket restriction on other plans,
and the groups the agent belongs to. Ticket questions read the ticket (its
group, assignee, requester, organization and status) and apply the agent's
ticket access. Administrators may do everything, end users only see and
comment on their own tickets, light agents only see and comment privately.
Nothing is written.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

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
from hallpass.core.errors import go_lower, go_quote, go_trim_space
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
from hallpass.integrations.zendesk.actions import Target, catalog_actions, parse_target
from hallpass.net import httpx

__all__ = ["AUTH_OAUTH", "AUTH_TOKEN", "Zendesk", "ZendeskConnection"]

AUTH_TOKEN = "token"
AUTH_OAUTH = "oauth"

ROLE_ADMIN = "admin"
ROLE_AGENT = "agent"
ROLE_END_USER = "end-user"

# role_type 1.
ROLE_TYPE_LIGHT_AGENT = 1

# How long the custom role list is kept.
ROLES_TTL = 5 * 60.0


class Zendesk(Integration):
    """The zendesk product."""

    def name(self) -> str:
        return "zendesk"

    def fields(self) -> list[Field]:
        return [
            url_field(True, "the account URL, e.g. https://acme.zendesk.com"),
            Field(
                name="auth_mode",
                default=AUTH_TOKEN,
                enum=(AUTH_TOKEN, AUTH_OAUTH),
                description="token: an API token with username (HTTP Basic email/token); oauth: an OAuth access token (Bearer)",
            ),
            Field(name="username", description="auth_mode token: the email of the administrator the API token acts as"),
            credential_field(True, "the API token or OAuth access token"),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network."""
        hc = d.http_client(s)
        base = s.get("url").rstrip("/")
        if base == "":
            raise ValueError("url is required")
        if s.secret("credential").is_zero():
            raise ValueError("credential is required")
        cred = s.secret("credential")

        def token(ctx: Context) -> str:
            try:
                t = cred.get_string()
            except SecretError as e:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the token could not be read") from e
            return go_trim_space(t)

        client = httpx.Client(http=hc, base=base, logger=d.logger)
        mode = s.get("auth_mode")
        if mode in ("", AUTH_TOKEN):
            user = go_trim_space(s.get("username"))
            if not is_email(user):
                raise ValueError("username is required in auth_mode token and must be the administrator's email")
            client.auth = httpx.basic_auth(user + "/token", token)
        elif mode == AUTH_OAUTH:
            client.auth = httpx.bearer_auth(token)
        else:
            raise ValueError(f"auth_mode {go_quote(mode)} must be token or oauth")
        return ZendeskConnection(client, d.now)


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


def _opt_b(d: dict[str, Any], key: str) -> bool | None:
    """A *bool field: None for a missing key or null."""
    return None if d.get(key) is None else jsonx.b(d, key)


def _opt_i(d: dict[str, Any], key: str) -> int | None:
    """A *int / *int64 field."""
    return None if d.get(key) is None else jsonx.i(d, key)


def _opt_s(d: dict[str, Any], key: str) -> str | None:
    """A *string field."""
    return None if d.get(key) is None else jsonx.s(d, key)


def _ints(d: dict[str, Any], key: str) -> list[int]:
    """A []int64 field; a null element is 0."""
    out = []
    for x in jsonx.arr(d, key):
        out.append(0 if x is None else jsonx.i({key: x}, key))
    return out


def _go_bool(b: bool) -> str:
    return "true" if b else "false"


def classify(err: BaseException, what: str) -> HallpassError:
    """Map an API error to an integration error. 404 is left to the
    caller."""
    st = httpx.status(err)
    if st == 401:
        return wrap_error(Code.CREDENTIAL_REJECTED, err, "Zendesk rejected hallpass's credential")
    if st == 403:
        return wrap_error(Code.CREDENTIAL_REJECTED, err, f"Zendesk refused to {what} (HTTP 403): hallpass's user lacks the permission; use an administrator")
    if st in (400, 422):
        return wrap_error(Code.INVALID_REQUEST, err, f"Zendesk rejected the request to {what} (HTTP {st})")
    he = httpx.classify(err)
    assert he is not None
    return he


def _read_error(err: BaseException, what: Target) -> Decision:
    """Answer for a failed read of a named resource: 404 and 403 both mean
    hallpass cannot see it (Zendesk answers 403 for a ticket outside its
    user's ticket access), anything else is classified (raised)."""
    st = httpx.status(err)
    if st == 404:
        return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"{what} does not exist or hallpass cannot see it")
    if st == 403:
        # UNVERIFIED: whether a ticket outside the credential's own ticket
        # access answers 403 or 404; both are "not visible".
        return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"hallpass's Zendesk user may not see {what} (HTTP 403); use an administrator")
    raise classify(err, "read " + str(what)) from err


@dataclass(frozen=True)
class _ZDUser:
    """The subset of a user hallpass reads."""

    id: int = 0
    email: str = ""
    role: str = ""
    role_type: int | None = None
    custom_role_id: int | None = None
    active: bool | None = None
    suspended: bool | None = None
    ticket_restriction: str | None = None
    only_private_comments: bool | None = None
    organization_id: int | None = None


def _zd_user(v: Any) -> _ZDUser:
    u = jsonx.obj(v)
    return _ZDUser(
        id=jsonx.i(u, "id"),
        email=jsonx.s(u, "email"),
        role=jsonx.s(u, "role"),
        role_type=_opt_i(u, "role_type"),
        custom_role_id=_opt_i(u, "custom_role_id"),
        active=_opt_b(u, "active"),
        suspended=_opt_b(u, "suspended"),
        ticket_restriction=_opt_s(u, "ticket_restriction"),
        only_private_comments=_opt_b(u, "only_private_comments"),
        organization_id=_opt_i(u, "organization_id"),
    )


def _bool_attr(b: bool | None) -> str:
    return "unknown" if b is None else _go_bool(b)


@dataclass(frozen=True)
class _RoleConfig:
    ticket_access: str = ""
    ticket_editing: bool | None = None
    ticket_deletion: bool | None = None
    ticket_merge: bool | None = None
    ticket_comment_access: str = ""
    modify_closed_tickets: bool | None = None
    macro_access: str = ""
    view_access: str = ""
    organization_editing: bool | None = None
    end_user_profile_access: str = ""
    manage_business_rules: bool | None = None
    light_agent: bool | None = None


@dataclass(frozen=True)
class _CustomRole:
    """The subset of a custom role's configuration hallpass reads."""

    id: int = 0
    name: str = ""
    role_type: int | None = None
    configuration: _RoleConfig = field(default_factory=_RoleConfig)


def _custom_role(v: Any) -> _CustomRole:
    r = jsonx.obj(v)
    c = jsonx.o(r, "configuration")
    cfg = _RoleConfig(
        ticket_access=jsonx.s(c, "ticket_access"),
        ticket_editing=_opt_b(c, "ticket_editing"),
        ticket_deletion=_opt_b(c, "ticket_deletion"),
        ticket_merge=_opt_b(c, "ticket_merge"),
        ticket_comment_access=jsonx.s(c, "ticket_comment_access"),
        modify_closed_tickets=_opt_b(c, "modify_closed_tickets"),
        macro_access=jsonx.s(c, "macro_access"),
        view_access=jsonx.s(c, "view_access"),
        organization_editing=_opt_b(c, "organization_editing"),
        end_user_profile_access=jsonx.s(c, "end_user_profile_access"),
        manage_business_rules=_opt_b(c, "manage_business_rules"),
        light_agent=_opt_b(c, "light_agent"),
    )
    return _CustomRole(id=jsonx.i(r, "id"), name=jsonx.s(r, "name"), role_type=_opt_i(r, "role_type"), configuration=cfg)


@dataclass
class _Grants:
    """What the user may do, from the role, the custom role or the
    per-agent ticket restriction."""

    admin: bool = False
    end_user: bool = False
    light: bool = False
    # all, within-groups, within-groups-and-public-groups,
    # within-organization or assigned-only (agents), or requested (end users).
    ticket_access: str = ""
    # The remaining fields are optional: None means the plan does not expose
    # the setting, so the answer is unknown.
    ticket_editing: bool | None = None
    ticket_deletion: bool | None = None
    ticket_merge: bool | None = None
    public_comments: bool | None = None
    modify_closed: bool | None = None
    macro_full: bool | None = None
    view_full: bool | None = None
    org_editing: bool | None = None
    business_rules: bool | None = None
    # edit, edit-within-org, full, readonly or "" (unknown).
    end_user_profile: str = ""
    role_name: str = ""


@dataclass(frozen=True)
class _Ticket:
    """The subset of a ticket hallpass reads."""

    id: int = 0
    status: str = ""
    group_id: int | None = None
    assignee_id: int | None = None
    requester_id: int | None = None
    organization_id: int | None = None
    collaborators: tuple[int, ...] = ()


def _zd_ticket(v: Any) -> _Ticket:
    t = jsonx.obj(v)
    return _Ticket(
        id=jsonx.i(t, "id"),
        status=jsonx.s(t, "status"),
        group_id=_opt_i(t, "group_id"),
        assignee_id=_opt_i(t, "assignee_id"),
        requester_id=_opt_i(t, "requester_id"),
        organization_id=_opt_i(t, "organization_id"),
        collaborators=tuple(_ints(t, "collaborator_ids")),
    )


def _id_of(p: int | None) -> str:
    if p is None or p == 0:
        return ""
    return str(p)


def _or_empty(s: str, default: str) -> str:
    return default if s == "" else s


def _unknown_setting(who: str, what: str, g: _Grants) -> Decision:
    """The answer for a setting the plan does not expose."""
    return unsupported(f"whether {who} ({g.role_name}) may {what} is an account setting Zendesk does not expose on plans without custom roles")


class ZendeskConnection(Connection):
    """One Zendesk account."""

    def __init__(self, api: httpx.Client, now: Callable[[], float] | None = None) -> None:
        self.api = api
        # The account's custom roles under one key for ROLES_TTL.
        self.roles: TTL[str, dict[int, _CustomRole]] = TTL(1)
        if now is not None:
            self.roles.set_clock(now)

    def _get(self, ctx: Context, path: str, q: dict[str, str] | None = None) -> dict[str, Any]:
        _, v = self.api.get_json(ctx, path, q)
        return jsonx.obj(v)

    # -- identity --

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Find the user with the email. The search syntax matches more than
        exact addresses, so the address is compared exactly."""
        email = go_lower(go_trim_space(u.email))
        if not is_email(email):
            raise errorf(Code.INVALID_REQUEST, f"user email {go_quote(email)} is not an address")
        # is_email admits no space or quote, so the search term is one email clause.
        try:
            body = self._get(ctx, "/api/v2/users/search", {"query": "email:" + email})
            users = [_zd_user(x) for x in jsonx.arr(body, "users")]
        except Exception as e:
            raise classify(e, "search users") from e
        matches = [usr for usr in users if equal_fold(usr.email, email)]
        loose = [usr for usr in users if not equal_fold(usr.email, email)]
        # The search also finds users whose secondary email identity is the
        # address; their primary email differs, so their identities decide.
        if not matches:
            for usr in loose:
                try:
                    ok = self._has_email_identity(ctx, usr.id, email)
                except Exception as e:
                    raise classify(e, "list a user's identities") from e
                if ok:
                    matches.append(usr)
        if len(matches) == 0:
            raise user_not_found(f"no Zendesk user has email {email}")
        if len(matches) > 1:
            raise user_ambiguous(f"{len(matches)} Zendesk users have email {email}")
        usr = matches[0]
        if usr.id == 0 or usr.role == "":
            raise errorf(Code.UPSTREAM_ERROR, f"the user record for {email} carries no id or role")
        attrs = {"role": usr.role, "active": _bool_attr(usr.active), "suspended": _bool_attr(usr.suspended)}
        if usr.role_type is not None:
            attrs["role_type"] = str(usr.role_type)
        if usr.custom_role_id is not None and usr.custom_role_id != 0:
            attrs["custom_role_id"] = str(usr.custom_role_id)
        if usr.ticket_restriction is not None:
            attrs["ticket_restriction"] = usr.ticket_restriction
        if usr.only_private_comments is not None:
            attrs["only_private_comments"] = _go_bool(usr.only_private_comments)
        if usr.organization_id is not None and usr.organization_id != 0:
            attrs["organization_id"] = str(usr.organization_id)
        groups: tuple[str, ...] = ()
        # Administrators see every ticket, so only agents' groups matter.
        if usr.role == ROLE_AGENT:
            try:
                groups = tuple(self._group_memberships(ctx, usr.id))
            except Exception as e:
                raise classify(e, "list the agent's groups") from e
        return Identity(id=str(usr.id), display=email, attrs=attrs, groups=groups)

    def _has_email_identity(self, ctx: Context, user_id: int, email: str) -> bool:
        """Whether one of the user's identities is the email address,
        following next_page links that stay under the API base."""
        found = False

        def page(resp: httpx.Response) -> httpx.Request | None:
            nonlocal found
            try:
                p = jsonx.obj(resp.json())
                ids = [(jsonx.s(i, "type"), jsonx.s(i, "value")) for i in (jsonx.obj(x) for x in jsonx.arr(p, "identities"))]
                nxt = jsonx.s(p, "next_page")
            except ValueError as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "Zendesk returned an unreadable page") from e
            for typ, value in ids:
                if typ == "email" and equal_fold(value, email):
                    found = True
                    return None
            return self._next_page(nxt)

        self.api.paginate(ctx, httpx.Request(path="/api/v2/users/" + str(user_id) + "/identities"), page)
        return found

    def _next_page(self, link: str) -> httpx.Request | None:
        """A body-carried next_page link as the next request, or a refusal of
        one that leaves the API (the credential would travel with it)."""
        if link == "":
            return None
        if not self.api.within(link):
            raise errorf(Code.UPSTREAM_ERROR, "Zendesk sent a next page outside its API")
        return httpx.Request(path=link)

    def _group_memberships(self, ctx: Context, user_id: int) -> list[str]:
        """The ids of the groups the agent belongs to, following next_page
        links that stay under the API base."""
        out: list[str] = []

        def page(resp: httpx.Response) -> httpx.Request | None:
            try:
                p = jsonx.obj(resp.json())
                gids = [jsonx.i(jsonx.obj(m), "group_id") for m in jsonx.arr(p, "group_memberships")]
                nxt = jsonx.s(p, "next_page")
            except ValueError as e:
                raise wrap_error(Code.UPSTREAM_ERROR, e, "Zendesk returned an unreadable page") from e
            out.extend(str(g) for g in gids if g != 0)
            return self._next_page(nxt)

        self.api.paginate(ctx, httpx.Request(path="/api/v2/users/" + str(user_id) + "/group_memberships"), page)
        return out

    # -- roles --

    def _custom_roles(self, ctx: Context, refresh: bool) -> dict[int, _CustomRole]:
        """The account's custom roles, cached for ROLES_TTL with concurrent
        first callers sharing one fetch. The list is readable by any agent;
        a single role is not. With refresh the cache is bypassed, for a role
        id created after the last fetch."""
        if refresh:
            self.roles.delete("roles")

        def fill(ctx: Context) -> tuple[dict[int, _CustomRole], float]:
            body = self._get(ctx, "/api/v2/custom_roles")
            roles = {}
            for x in jsonx.arr(body, "custom_roles"):
                r = _custom_role(x)
                roles[r.id] = r
            return roles, ROLES_TTL

        return self.roles.do(ctx, "roles", fill)

    def _grants_for(self, ctx: Context, ident: Identity) -> _Grants:
        """The user's grants."""
        g = _Grants()
        role = ident.attr("role")
        if role == ROLE_ADMIN:
            g.admin, g.role_name = True, "administrator"
            return g
        if role == ROLE_END_USER:
            g.end_user, g.role_name, g.ticket_access = True, "end user", "requested"
            return g
        if role != ROLE_AGENT:
            raise errorf(Code.UNSUPPORTED, f"{ident.display} has role {go_quote(role)}, which hallpass does not know")
        g.role_name = "agent"
        if ident.attr("role_type") == str(ROLE_TYPE_LIGHT_AGENT):
            g.light = True
        crid = ident.attr("custom_role_id")
        if crid != "":
            rid = int(crid)
            cr: _CustomRole | None = None
            for refresh in (False, True):
                try:
                    roles = self._custom_roles(ctx, refresh)
                except Exception as e:
                    raise classify(e, "list the custom roles") from e
                cr = roles.get(rid)
                if cr is not None:
                    break
                if refresh:
                    raise errorf(Code.RESOURCE_NOT_VISIBLE, f"custom role {crid} of {ident.display} is not among the account's custom roles")
            assert cr is not None
            cfg = cr.configuration
            g.role_name = "custom role " + cr.name
            if cfg.light_agent:
                g.light = True
            g.ticket_access = cfg.ticket_access
            g.ticket_editing, g.ticket_deletion, g.ticket_merge, g.modify_closed = (
                cfg.ticket_editing,
                cfg.ticket_deletion,
                cfg.ticket_merge,
                cfg.modify_closed_tickets,
            )
            if cfg.ticket_comment_access != "":
                g.public_comments = cfg.ticket_comment_access == "public"
            if cfg.macro_access != "":
                g.macro_full = cfg.macro_access == "full"
            if cfg.view_access != "":
                g.view_full = cfg.view_access == "full"
            g.org_editing, g.business_rules = cfg.organization_editing, cfg.manage_business_rules
            g.end_user_profile = cfg.end_user_profile_access
            return g
        # Plans without custom roles: the profile's ticket restriction.
        # UNVERIFIED: whether role_type is null or 0 for a plain agent, and
        # whether a light agent's ticket_restriction is null when the profile
        # shows all tickets; both readings are accepted.
        rt = ident.attr("role_type")
        if rt not in ("", "0") and not g.light:
            raise errorf(
                Code.UNSUPPORTED, f"{ident.display} is an agent of role type {rt} (chat agent or contributor), whose permissions hallpass does not model"
            )
        tr = ident.attr("ticket_restriction")
        access = {"": "all", "groups": "within-groups", "organization": "within-organization", "assigned": "assigned-only", "requested": "requested"}.get(tr)
        if access is None:
            raise errorf(Code.UNSUPPORTED, f"{ident.display} has ticket restriction {go_quote(tr)}, which hallpass does not know")
        g.ticket_access = access
        if g.light:
            g.ticket_editing, g.public_comments = False, False
        else:
            g.ticket_editing = True
            v = ident.attr("only_private_comments")
            if v != "":
                g.public_comments = v == "false"
        # An agent with access to all tickets may edit end-user profiles.
        if g.ticket_access == "all" and not g.light:
            g.end_user_profile = "full"
        else:
            g.end_user_profile = "readonly"
        return g

    # -- checks --

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """Answer one question."""
        t = parse_target(r.action_name, r.resource)
        who = r.identity.display
        if r.identity.attr("active") == "false":
            return denied(f"{who} is deleted in Zendesk")
        if r.identity.attr("suspended") == "true":
            return denied(f"{who} is suspended in Zendesk")
        g = self._grants_for(ctx, r.identity)
        res = t.action.resource
        if res == "account":
            return self._check_account(t, g, who)
        if res == "organization":
            return self._check_organization(ctx, t, g, who)
        if res == "user":
            return self._check_user(ctx, t, g, r.identity)
        return self._check_ticket(ctx, t, g, r.identity)

    def _check_account(self, t: Target, g: _Grants, who: str) -> Decision:
        if t.action.name == "account.admin":
            if g.admin:
                return allowed(f"{who} is an administrator")
            return denied(f"{who} is an {g.role_name}, not an administrator")
        if g.admin:
            return allowed(f"{who} is an administrator, who may {t.action.desc}")
        if g.end_user:
            return denied(f"{who} is an end user")
        setting: bool | None = None
        if t.action.name == "macro.manage":
            setting = g.macro_full
        elif t.action.name == "view.manage":
            setting = g.view_full
        elif t.action.name == "business_rules.manage":
            setting = g.business_rules
        if setting is None:
            return _unknown_setting(who, t.action.desc, g)
        if setting:
            return allowed(f"{who} ({g.role_name}) may {t.action.desc}")
        return denied(f"{who} ({g.role_name}) may not {t.action.desc}")

    def _check_organization(self, ctx: Context, t: Target, g: _Grants, who: str) -> Decision:
        try:
            self.api.get_json(ctx, "/api/v2/organizations/" + t.id, decode=False)
        except Exception as e:  # noqa: BLE001 - Go: every error is decided on (404) or classified
            return _read_error(e, t)
        if g.admin:
            return allowed(f"{who} is an administrator, who may {t.action.desc}")
        if g.end_user:
            return denied(f"{who} is an end user")
        if g.org_editing is None:
            return _unknown_setting(who, t.action.desc, g)
        if g.org_editing:
            return allowed(f"{who} ({g.role_name}) may {t.action.desc}")
        return denied(f"{who} ({g.role_name}) may not {t.action.desc}")

    def _check_user(self, ctx: Context, t: Target, g: _Grants, ident: Identity) -> Decision:
        """user.edit: end-user profiles per the role's end_user_profile_access;
        other team members only for administrators."""
        who = ident.display
        try:
            user = _zd_user(jsonx.o(self._get(ctx, "/api/v2/users/" + t.id), "user"))
        except Exception as e:  # noqa: BLE001 - Go: every error is decided on (404) or classified
            return _read_error(e, t)
        if g.admin:
            return allowed(f"{who} is an administrator, who may edit any profile")
        if user.role != ROLE_END_USER:
            if t.id == ident.id:
                return allowed(f"{who} may edit their own profile")
            return denied(f"{t} is a team member ({user.role}) and only administrators edit other team members")
        if g.end_user:
            if t.id == ident.id:
                return allowed(f"{who} may edit their own profile")
            return denied(f"{who} is an end user and may edit their own profile only")
        p = g.end_user_profile
        if p in ("full", "edit"):
            return allowed(f"{who} ({g.role_name}) may edit end-user profiles")
        if p == "edit-within-org":
            mine = ident.attr("organization_id")
            theirs = _id_of(user.organization_id)
            if mine != "" and mine == theirs:
                return allowed(f"{who} ({g.role_name}) may edit end users of their own organization, and {t} is one")
            return denied(f"{who} ({g.role_name}) may edit end users of their own organization only, and {t} is not one")
        if p == "readonly":
            return denied(f"{who} ({g.role_name}) may only view end-user profiles")
        return _unknown_setting(who, t.action.desc, g)

    def _check_ticket(self, ctx: Context, t: Target, g: _Grants, ident: Identity) -> Decision:
        """The ticket questions: first whether the user can see the ticket at
        all under the role's ticket access, then the action."""
        who = ident.display
        try:
            tk = _zd_ticket(jsonx.o(self._get(ctx, "/api/v2/tickets/" + t.id), "ticket"))
        except Exception as e:  # noqa: BLE001 - Go: every error is decided on (404) or classified
            return _read_error(e, t)
        name = t.action.name
        # Closed tickets take no updates from anyone: no comment, no merge, no
        # property change; a follow-up ticket is created instead. Deletion
        # stays possible. Custom roles may carry modify_closed_tickets for
        # property changes. UNVERIFIED: whether administrators may modify
        # closed tickets without that setting; they are denied here.
        if tk.status == "closed" and name not in ("ticket.view", "ticket.delete"):
            if name == "ticket.edit" and g.modify_closed:
                access = self._can_see(ctx, g, ident, tk)
                if access.code != Code.ALLOWED:
                    return access
                return allowed(f"{who} ({g.role_name}) may modify closed tickets and can see {t} ({access.text})")
            return denied(f"{t} is closed; closed tickets take no comments, merges or property changes")
        if g.admin:
            return allowed(f"{who} is an administrator, who may {t.action.desc}")
        # Access to the ticket.
        access = self._can_see(ctx, g, ident, tk)
        if access.code != Code.ALLOWED:
            return access
        requester = _id_of(tk.requester_id) == ident.id
        if name == "ticket.view":
            return access
        if name == "ticket.edit":
            if g.end_user:
                return denied(f"{who} is an end user and cannot change ticket properties")
            if g.light:
                if requester:
                    return allowed(f"{who} is a light agent but requested {t}, so may edit it")
                return denied(f"{who} is a light agent and cannot change ticket properties")
            if g.ticket_editing is None:
                return _unknown_setting(who, t.action.desc, g)
            if g.ticket_editing:
                return allowed(f"{who} ({g.role_name}) may {t.action.desc} and can see {t} ({access.text})")
            return denied(f"{who} ({g.role_name}) may not change ticket properties")
        if name == "ticket.comment_public":
            if g.end_user:
                return allowed(f"{who} may comment on {t}: {access.text}")
            if g.light:
                return denied(f"{who} is a light agent, whose comments are private")
            if g.public_comments is None:
                return _unknown_setting(who, t.action.desc, g)
            if g.public_comments:
                return allowed(f"{who} ({g.role_name}) may comment publicly and can see {t} ({access.text})")
            return denied(f"{who} ({g.role_name}) may only comment privately")
        if name in ("ticket.merge", "ticket.delete"):
            if g.end_user or g.light:
                return denied(f"{who} ({g.role_name}) may not {t.action.desc}")
            setting = g.ticket_deletion if name == "ticket.delete" else g.ticket_merge
            if setting is None:
                return _unknown_setting(who, t.action.desc, g)
            if setting:
                return allowed(f"{who} ({g.role_name}) may {t.action.desc} and can see {t} ({access.text})")
            return denied(f"{who} ({g.role_name}) may not {t.action.desc}")
        raise errorf(Code.INVALID_REQUEST, f"unknown action {go_quote(name)}")

    def _can_see(self, ctx: Context, g: _Grants, ident: Identity, tk: _Ticket) -> Decision:
        """Whether the role's ticket access covers the ticket. The text says
        why, for the action's own text."""
        who = ident.display
        group, assignee, requester, org = _id_of(tk.group_id), _id_of(tk.assignee_id), _id_of(tk.requester_id), _id_of(tk.organization_id)
        in_group = group != "" and group in ident.groups
        access = g.ticket_access
        if access == "all":
            return allowed("access to all tickets")
        if access in ("within-groups", "within-groups-and-public-groups"):
            if in_group:
                return allowed(f"the ticket is in group {group}, one of {who}'s groups")
            if assignee == ident.id or requester == ident.id:
                return allowed(f"the ticket is assigned to or requested by {who}")
            if access == "within-groups-and-public-groups" and group != "":
                try:
                    public = self._group_is_public(ctx, group)
                except Exception as e:
                    if httpx.status(e) == 404:
                        return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"group {group} of the ticket does not exist or hallpass cannot see it")
                    raise classify(e, "read group " + group) from e
                if public:
                    return allowed(f"the ticket is in public group {group}")
            if group == "":
                return unsupported(
                    f"the ticket is in no group and {who} ({g.role_name}) sees tickets of their groups; "
                    "whether unassigned tickets are visible depends on views hallpass does not read"
                )
            return denied(f"{who} ({g.role_name}) sees tickets of their groups only and the ticket is in group {group}")
        if access == "within-organization":
            mine = ident.attr("organization_id")
            if mine != "" and mine == org:
                return allowed(f"the ticket belongs to {who}'s organization {org}")
            if assignee == ident.id or requester == ident.id:
                return allowed(f"the ticket is assigned to or requested by {who}")
            # UNVERIFIED: an agent with several organization memberships may
            # see tickets of all of them; only the default organization is
            # compared here, so such an agent may be denied wrongly.
            return denied(f"{who} ({g.role_name}) sees tickets of their organization only and the ticket belongs to organization {_or_empty(org, 'none')}")
        if access == "assigned-only":
            if assignee == ident.id:
                return allowed(f"the ticket is assigned to {who}")
            return denied(f"{who} ({g.role_name}) sees assigned tickets only and the ticket is assigned to {_or_empty(assignee, 'nobody')}")
        if access == "requested":
            if requester == ident.id:
                return allowed(f"{who} requested the ticket")
            for cc in tk.collaborators:
                if str(cc) == ident.id:
                    return allowed(f"{who} is a collaborator on the ticket")
            return denied(f"{who} did not request the ticket and is not a collaborator on it")
        return unsupported(f"{who} has ticket access {go_quote(access)}, which hallpass does not know")

    def _group_is_public(self, ctx: Context, group: str) -> bool:
        """A group's is_public flag."""
        body = self._get(ctx, "/api/v2/groups/" + group)
        return _opt_b(jsonx.o(body, "group"), "is_public") is True

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """Read the credential's own user and report its role."""
        try:
            user = _zd_user(jsonx.o(self._get(ctx, "/api/v2/users/me"), "user"))
        except Exception as e:
            raise classify(e, "read its own user") from e
        if user.id == 0:
            raise errorf(Code.CREDENTIAL_REJECTED, "Zendesk answered the credential with an anonymous user; the token is not valid")
        warnings = []
        if user.role != ROLE_ADMIN:
            warnings.append("hallpass's user is not an administrator: tickets and users outside its own access answer unknown")
        warnings.append("an API token acts with the full permissions of its user; keep it tightly held")
        return ProbeResult(summary=f"authenticated as {user.email} ({user.role}) at {self.api.base}", warnings=tuple(warnings))
