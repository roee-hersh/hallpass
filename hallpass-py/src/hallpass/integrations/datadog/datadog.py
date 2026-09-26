"""Checks what a user may do in one Datadog organization.

hallpass authenticates with an API key and a scoped application key, finds
the user by email, reads the permissions of the user's roles, and for a
monitor, dashboard, SLO or notebook reads the asset's restriction policy
(and the legacy restricted_roles and author fields): a user may change such
an asset only when a role carries the write permission and the asset's
restrictions, if any, name the user, one of the user's roles or teams, or
the whole org. Nothing is written.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
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
from hallpass.integrations.datadog.actions import ASSET_TYPES, Target, catalog_actions, match_action, parse_target
from hallpass.net import httpx

__all__ = ["DEFAULT_URL", "Datadog", "DatadogConnection"]

DEFAULT_URL = "https://api.datadoghq.com"
PAGE_SIZE = 100
# How long a role's permission list is kept.
PERMISSIONS_TTL = 5 * 60.0
# Bounds a team membership scan.
MAX_TEAM_PAGES = 50

UUID_RE = re.compile(r"[0-9a-fA-F-]{8,64}")


def _uuid_ok(s: str) -> bool:
    return UUID_RE.fullmatch(s) is not None


class Datadog(Integration):
    """The datadog product."""

    def name(self) -> str:
        return "datadog"

    def fields(self) -> list[Field]:
        return [
            url_field(
                False,
                "API URL of the site; default https://api.datadoghq.com (EU https://api.datadoghq.eu, US3 https://api.us3.datadoghq.com, "
                "US5 https://api.us5.datadoghq.com, AP1 https://api.ap1.datadoghq.com)",
            ),
            Field(name="api_key", required=True, secret=True, description="the organization's API key (DD-API-KEY)"),
            credential_field(
                True, "an application key (DD-APPLICATION-KEY) scoped to user_access_read, teams_read and the *_read scope of each asset type asked about"
            ),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def match_action(self, name: str) -> Action | None:
        return match_action(name)

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network."""
        hc = d.http_client(s)
        if s.secret("credential").is_zero() or s.secret("api_key").is_zero():
            raise ValueError("api_key and credential are required")
        base = s.get("url").rstrip("/")
        if base == "":
            base = DEFAULT_URL
        api_key, app_key = s.secret("api_key"), s.secret("credential")

        def auth(ctx: Context, r: httpx.PreparedRequest) -> None:
            try:
                a = api_key.get_string()
            except SecretError as e:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the API key could not be read") from e
            try:
                k = app_key.get_string()
            except SecretError as e:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the application key could not be read") from e
            r.headers.set("DD-API-KEY", go_trim_space(a))
            r.headers.set("DD-APPLICATION-KEY", go_trim_space(k))

        return DatadogConnection(httpx.Client(http=hc, base=base, auth=auth, logger=d.logger), d.now)


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


def classify(err: BaseException, what: str) -> HallpassError:
    """Map an API error to an integration error. 404 is left to the
    caller, who knows what is missing."""
    st = httpx.status(err)
    if st == 401:
        return wrap_error(Code.CREDENTIAL_REJECTED, err, "Datadog rejected hallpass's API or application key")
    if st == 403:
        return wrap_error(
            Code.CREDENTIAL_REJECTED,
            err,
            f"Datadog refused to {what} (HTTP 403): the API key or application key is invalid, or the application key lacks the scope",
        )
    if st == 400:
        return wrap_error(Code.INVALID_REQUEST, err, f"Datadog rejected the request to {what} (HTTP 400)")
    he = httpx.classify(err)
    assert he is not None
    return he


@dataclass(frozen=True)
class _DDUser:
    """The subset of a v2 user hallpass reads."""

    id: str
    email: str
    handle: str
    status: str
    disabled: bool | None
    roles: tuple[str, ...]


def _dd_user(v: Any) -> _DDUser:
    u = jsonx.obj(v)
    attrs = jsonx.o(u, "attributes")
    disabled = None if attrs.get("disabled") is None else jsonx.b(attrs, "disabled")
    roles = tuple(jsonx.s(jsonx.obj(r), "id") for r in jsonx.arr(jsonx.o(jsonx.o(u, "relationships"), "roles"), "data"))
    return _DDUser(jsonx.s(u, "id"), jsonx.s(attrs, "email"), jsonx.s(attrs, "handle"), jsonx.s(attrs, "status"), disabled, roles)


@dataclass(frozen=True)
class _AssetInfo:
    """What the legacy asset endpoints say about restrictions."""

    restricted_roles: tuple[str, ...] = ()
    author: str = ""


@dataclass(frozen=True)
class _Binding:
    """One relation of a restriction policy."""

    relation: str
    principals: tuple[str, ...]


def relation_rank(rel: str) -> int:
    """Orders the relations a policy may grant."""
    if rel == "viewer":
        return 1
    if rel == "editor":
        return 2
    # Type-specific relations above editor (manager, runner, ...) are not
    # modelled; they are ranked with editor so a manager may also edit.
    if rel != "":
        return 2
    return 0


def _author_is(author: str, ident: Identity) -> bool:
    """Match a dashboard's author_handle or a creator email against the
    identity."""
    author = go_lower(author)
    return author == ident.attr("handle") or author == go_lower(ident.display)


class DatadogConnection(Connection):
    """One Datadog organization."""

    def __init__(self, api: httpx.Client, now: Callable[[], float] = time.time) -> None:
        self.api = api
        self.now = now
        # Each role's permission names, kept for PERMISSIONS_TTL.
        self.perms: TTL[str, frozenset[str]] = TTL(0)
        self.perms.set_clock(now)

    def _get(self, ctx: Context, path: str, q: dict[str, str] | None = None) -> dict[str, Any]:
        _, v = self.api.get_json(ctx, path, q)
        return jsonx.obj(v)

    # -- identity --

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Find the user with the email. Datadog's filter is a substring
        match on name, handle and email, so the address is compared exactly;
        disabled users are included so they can be denied."""
        email = go_lower(go_trim_space(u.email))
        if not is_email(email):
            raise errorf(Code.INVALID_REQUEST, f"user email {go_quote(email)} is not an address")
        matches: list[_DDUser] = []
        page_no = 0
        while True:
            if page_no >= httpx.MAX_PAGES:
                raise errorf(Code.UPSTREAM_ERROR, f"too many users match {email}")
            q = {"filter": email, "filter[status]": "Active,Pending,Disabled", "page[size]": str(PAGE_SIZE), "page[number]": str(page_no)}
            try:
                page = self._get(ctx, "/api/v2/users", q)
                data = [_dd_user(x) for x in jsonx.arr(page, "data")]
                pg = jsonx.o(jsonx.o(page, "meta"), "page")
                total = None if pg.get("total_filtered_count") is None else jsonx.i(pg, "total_filtered_count")
            except Exception as e:
                raise classify(e, "search users") from e
            for usr in data:
                if equal_fold(usr.email, email):
                    matches.append(usr)
            seen = page_no * PAGE_SIZE + len(data)
            if len(data) == 0 or (total is not None and seen >= total):
                break
            page_no += 1
        if len(matches) == 0:
            raise user_not_found(f"no Datadog user has email {email}")
        if len(matches) > 1:
            raise user_ambiguous(f"{len(matches)} Datadog users have email {email}")
        usr = matches[0]
        if usr.id == "":
            raise errorf(Code.UPSTREAM_ERROR, f"the user record for {email} carries no id")
        disabled = "unknown" if usr.disabled is None else ("true" if usr.disabled else "false")
        return Identity(
            id=usr.id,
            display=email,
            attrs={"handle": go_lower(usr.handle), "disabled": disabled, "status": usr.status},
            groups=tuple(r for r in usr.roles if r != ""),
        )

    def _role_permissions(self, ctx: Context, role: str) -> frozenset[str]:
        """A role's permission names, cached for PERMISSIONS_TTL. The set is
        shared with every caller the entry serves."""
        if not _uuid_ok(role):
            raise errorf(Code.UPSTREAM_ERROR, f"role id {go_quote(role)} is not an id")

        def fill(ctx: Context) -> tuple[frozenset[str], float]:
            body = self._get(ctx, "/api/v2/roles/" + httpx.path_escape(role) + "/permissions")
            names = set()
            for p in jsonx.arr(body, "data"):
                n = jsonx.s(jsonx.o(jsonx.obj(p), "attributes"), "name")
                if n != "":
                    names.add(n)
            return frozenset(names), PERMISSIONS_TTL

        return self.perms.do(ctx, role, fill)

    # -- checks --

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """Answer one question."""
        t = parse_target(r.action_name, r.resource)
        who = r.identity.display
        dis = r.identity.attr("disabled")
        if dis == "true":
            return denied(f"{who} is disabled in Datadog")
        if dis != "false":
            return unsupported(f"Datadog did not report whether {who} is disabled")
        if r.identity.attr("status") == "Pending":
            return denied(f"{who} was invited to Datadog but has not accepted, so cannot act")
        # The permission: any role of the user carrying it.
        granted_by = ""
        for role in r.identity.groups:
            try:
                names = self._role_permissions(ctx, role)
            except Exception as e:
                if httpx.status(e) == 404:
                    return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"role {role} of {who} does not exist or hallpass cannot see it")
                raise classify(e, "read the permissions of role " + role) from e
            if t.permission() in names:
                granted_by = role
                break
        if t.typ == "org":
            if granted_by != "":
                return allowed(f"a role of {who} carries {t.permission()}")
            return denied(f"no role of {who} carries {t.permission()}")
        # The asset exists, and its legacy restrictions.
        try:
            asset = self._read_asset(ctx, t)
        except Exception as e:
            if httpx.status(e) == 404:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"{t} does not exist or hallpass cannot see it")
            raise classify(e, "read " + str(t)) from e
        if granted_by == "":
            return denied(f"no role of {who} carries {t.permission()}, which {t.action.desc} needs")
        # The restriction policy, then the legacy fields.
        try:
            policy = self._restriction_policy(ctx, t)
        except Exception as e:
            raise classify(e, "read the restriction policy of " + str(t)) from e
        if policy:
            return self._apply_policy(ctx, t, r.identity, policy)
        if t.relation() == "editor" and asset.restricted_roles:
            for role in asset.restricted_roles:
                if role in r.identity.groups:
                    return allowed(f"a role of {who} carries {t.permission()} and {t} is restricted to roles that include it")
            if asset.author != "" and _author_is(asset.author, r.identity):
                return allowed(f"a role of {who} carries {t.permission()} and {who} is the author of {t}, which its restricted roles cannot exclude")
            return denied(f"{t} is restricted to {len(asset.restricted_roles)} role(s) that {who} does not hold")
        return allowed(f"a role of {who} carries {t.permission()} and {t} carries no restriction")

    def _read_asset(self, ctx: Context, t: Target) -> _AssetInfo:
        """Read the asset, proving it exists, and its legacy
        restricted_roles and author where the type has them."""
        if t.typ == "monitor":
            body = self._get(ctx, "/api/v1/monitor/" + httpx.path_escape(t.id))
            roles = jsonx.strs(body, "restricted_roles")
            creator = jsonx.o(body, "creator")
            jsonx.s(creator, "email"), jsonx.s(creator, "handle")
            # UNVERIFIED: whether a monitor's creator keeps edit rights under
            # restricted_roles as a dashboard's author does; the monitor
            # documentation speaks of roles only, so the creator is not exempt.
            return _AssetInfo(tuple(roles))
        if t.typ == "dashboard":
            body = self._get(ctx, "/api/v1/dashboard/" + httpx.path_escape(t.id))
            return _AssetInfo(tuple(jsonx.strs(body, "restricted_roles")), jsonx.s(body, "author_handle"))
        if t.typ == "slo":
            self.api.get_json(ctx, "/api/v1/slo/" + httpx.path_escape(t.id), decode=False)
        elif t.typ == "notebook":
            self.api.get_json(ctx, "/api/v1/notebooks/" + httpx.path_escape(t.id), decode=False)
        return _AssetInfo()

    def _restriction_policy(self, ctx: Context, t: Target) -> list[_Binding]:
        """The asset's restriction policy bindings; an asset without a
        policy has none."""
        pid = ASSET_TYPES[t.typ].policy_type + ":" + t.id
        try:
            body = self._get(ctx, "/api/v2/restriction_policy/" + httpx.path_escape(pid))
        except Exception as e:
            if httpx.status(e) == 404:
                return []
            raise
        attrs = jsonx.o(jsonx.o(body, "data"), "attributes")
        out = []
        for b in jsonx.arr(attrs, "bindings"):
            b = jsonx.obj(b)
            out.append(_Binding(jsonx.s(b, "relation"), tuple(jsonx.strs(b, "principals"))))
        return out

    def _apply_policy(self, ctx: Context, t: Target, ident: Identity, policy: list[_Binding]) -> Decision:
        """Decide from a restriction policy: the user, one of the user's
        roles or teams, or the whole org must be bound to the relation
        needed or a higher one."""
        need = relation_rank(t.relation())
        if need == relation_rank("viewer") and not any(b.relation == "viewer" for b in policy):
            # UNVERIFIED: a policy that only restricts editing is taken to
            # leave viewing to the permission, as the UI writes an explicit
            # viewer binding for the org when it restricts an asset.
            return allowed(f"a role of {ident.display} carries {t.permission()} and the restriction policy of {t} restricts editing only")
        teams: list[str] = []
        for b in policy:
            if relation_rank(b.relation) < need:
                continue
            for p in b.principals:
                kind, sep, pid = p.partition(":")
                if not sep:
                    continue
                if kind == "org":
                    return allowed(
                        f"the restriction policy of {t} grants {b.relation} to the whole org, and a role of {ident.display} carries {t.permission()}"
                    )
                if kind == "user":
                    if pid == ident.id:
                        return allowed(f"the restriction policy of {t} grants {b.relation} to {ident.display}, whose role carries {t.permission()}")
                elif kind == "role":
                    if pid in ident.groups:
                        return allowed(f"the restriction policy of {t} grants {b.relation} to a role of {ident.display}, which carries {t.permission()}")
                elif kind == "team" and _uuid_ok(pid) and pid not in teams:
                    teams.append(pid)
        for team in teams:
            try:
                member = self._team_member(ctx, team, ident.id, ident.display)
            except Exception as e:
                if httpx.status(e) == 404:
                    return unknown_decision(
                        Code.RESOURCE_NOT_VISIBLE, f"team {team} named by the restriction policy of {t} does not exist or hallpass cannot see it"
                    )
                raise classify(e, "read the members of team " + team) from e
            if member:
                return allowed(
                    f"the restriction policy of {t} grants {t.relation()} to team {team}, of which {ident.display} is a member, "
                    f"and a role carries {t.permission()}"
                )
        return denied(f"the restriction policy of {t} grants {t.relation()} to none of {ident.display}'s roles, teams or user")

    def _team_member(self, ctx: Context, team: str, user_id: str, keyword: str) -> bool:
        """Whether the user is a member of the team."""
        for page_no in range(MAX_TEAM_PAGES):
            # The keyword narrows the list to the user's email or name; the
            # id is still compared exactly.
            q = {"page[size]": str(PAGE_SIZE), "page[number]": str(page_no), "filter[keyword]": keyword}
            page = self._get(ctx, "/api/v2/team/" + httpx.path_escape(team) + "/memberships", q)
            data = jsonx.arr(page, "data")
            ids = [jsonx.s(jsonx.o(jsonx.o(jsonx.o(jsonx.obj(m), "relationships"), "user"), "data"), "id") for m in data]
            if user_id in ids:
                return True
            if len(data) == 0:
                return False
        raise errorf(Code.UPSTREAM_ERROR, f"team {team} has too many members to read")

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """Validate the keys and read one user, which needs
        user_access_read."""
        try:
            valid = jsonx.b(self._get(ctx, "/api/v1/validate"), "valid")
        except Exception as e:
            raise classify(e, "validate the API key") from e
        if not valid:
            raise errorf(Code.CREDENTIAL_REJECTED, "Datadog reports the API key as invalid")
        try:
            users = self._get(ctx, "/api/v2/users", {"page[size]": "1"})
            for x in jsonx.arr(users, "data"):
                _dd_user(x)
        except Exception as e:
            raise classify(e, "list users (needs user_access_read)") from e
        return ProbeResult(
            summary=f"API key valid and application key reads users at {self.api.base}",
            warnings=(
                "the application key also needs teams_read and the *_read scope of each asset type asked about (monitors_read, dashboards_read, "
                "slos_read, notebooks_read); an asset it cannot read answers unknown",
                "an unscoped application key carries every permission of its creator; scope it",
            ),
        )
