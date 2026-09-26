"""What a member may do in one Linear workspace (Go: linear/linear.go).

hallpass authenticates with a personal API key or an OAuth token, finds the
user by email and reads the workspace role (owner, admin, member, guest,
app), whether the account is active, and the teams the user belongs to and
owns. Team, issue and project questions read the object and apply Linear's
visibility rules: members see every public team, guests only the teams they
joined, private teams only their members. Nothing is written.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from hallpass.core import jsonx
from hallpass.core.catalog import Action
from hallpass.core.context import Context
from hallpass.core.decision import (
    Code,
    Decision,
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
)
from hallpass.core.secret import Secret, SecretError
from hallpass.core.template import is_email
from hallpass.integrations.linear.actions import UUID_RE, Target, catalog_actions, go_upper, invalid, parse_target
from hallpass.net import httpx

DEFAULT_URL = "https://api.linear.app/graphql"

AUTH_API_KEY = "api_key"
AUTH_OAUTH = "oauth"

# The page size for membership listings.
PAGE_SIZE = 100

T = TypeVar("T")


class Linear(Integration):
    """The linear product."""

    def name(self) -> str:
        return "linear"

    def fields(self) -> list[Field]:
        return [
            Field(name="url", default=DEFAULT_URL, description="the GraphQL endpoint"),
            Field(
                name="auth_mode",
                default=AUTH_API_KEY,
                enum=(AUTH_API_KEY, AUTH_OAUTH),
                description="api_key: a personal API key (sent bare); oauth: an OAuth access token (sent as Bearer)",
            ),
            credential_field(True, "the API key or OAuth access token; read scope suffices"),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network."""
        hc = d.http_client(s)
        u = go_trim_space(s.get("url"))
        if u == "":
            u = DEFAULT_URL
        if not u.startswith("https://") and not u.startswith("http://"):
            raise ValueError("url must be an http(s) URL")
        if s.secret("credential").is_zero():
            raise ValueError("credential is required")
        cred = s.secret("credential")
        mode = s.get("auth_mode")
        if mode in ("", AUTH_API_KEY):
            prefix = ""
        elif mode == AUTH_OAUTH:
            prefix = "Bearer "
        else:
            raise ValueError(f"auth_mode {go_quote(mode)} must be api_key or oauth")
        c = LinearConnection(u)
        c.api = httpx.Client(http=hc, base=u, logger=d.logger, auth=_auth(cred, prefix))
        return c


def _auth(cred: Secret, prefix: str) -> httpx.AuthFunc:
    def auth(ctx: Context, r: httpx.PreparedRequest) -> None:
        try:
            t = cred.get_string()
        except SecretError as e:
            raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the credential could not be read") from e
        t = go_trim_space(t)
        if t == "":
            raise errorf(Code.CREDENTIAL_REJECTED, "the credential is empty")
        # A token stored with its own "Bearer " scheme is sent as is. Go
        # compares the first len(prefix) bytes case-insensitively; the prefix
        # is ASCII, so an ASCII comparison of those bytes is the same.
        h = t
        if prefix != "":
            tb = t.encode("utf-8", "surrogateescape")
            pb = prefix.encode()
            if not (len(tb) > len(pb) and tb[: len(pb)].lower() == pb.lower()):
                h = prefix + t
        r.headers.set("Authorization", h)

    return auth


def go_equal_fold(a: str, b: str) -> bool:
    """Go's strings.EqualFold: equal under simple Unicode case folding, rune
    for rune (so "ß" is not "ss", and U+0131 matches only itself)."""
    if a.isascii() and b.isascii():
        return a.lower() == b.lower()
    if len(a) != len(b):
        return False
    return all(x == y or _fold(x) == _fold(y) for x, y in zip(a, b, strict=True))


def _fold(c: str) -> str:
    f = c.casefold()
    if len(f) == 1:
        return f
    f = c.lower()
    return f if len(f) == 1 else c


class NotFoundError(Exception):
    """A lookup Linear answered with an entity-not-found error; callers turn
    it into resource_not_visible (Go: errNotFound)."""

    def __init__(self) -> None:
        super().__init__("entity not found")


# -- decoding (Go decodes into typed structs: a wrong type is an error) -------


def _opt_str(d: dict[str, Any], key: str) -> str | None:
    """A *string field: None for a missing key or null."""
    if jsonx._get(d, key) is None:
        return None
    return jsonx.s(d, key)


def _opt_bool(d: dict[str, Any], key: str) -> bool | None:
    """A *bool field: None for a missing key or null."""
    if jsonx._get(d, key) is None:
        return None
    return jsonx.b(d, key)


@dataclass(frozen=True)
class GqlUser:
    id: str = ""
    email: str = ""
    name: str = ""
    active: bool = False
    admin: bool = False
    owner: bool = False
    guest: bool = False
    app: bool = False
    disable_reason: str | None = None


def decode_user(v: Any) -> GqlUser:
    d = jsonx.obj(v, "user")
    return GqlUser(
        id=jsonx.s(d, "id"),
        email=jsonx.s(d, "email"),
        name=jsonx.s(d, "name"),
        active=jsonx.b(d, "active"),
        admin=jsonx.b(d, "admin"),
        owner=jsonx.b(d, "owner"),
        guest=jsonx.b(d, "guest"),
        app=jsonx.b(d, "app"),
        disable_reason=_opt_str(d, "disableReason"),
    )


@dataclass(frozen=True)
class GqlTeam:
    id: str = ""
    key: str = ""
    name: str = ""
    visibility: str = ""
    archived_at: str | None = None


def decode_team(v: Any) -> GqlTeam:
    d = jsonx.obj(v, "team")
    return GqlTeam(
        id=jsonx.s(d, "id"),
        key=jsonx.s(d, "key"),
        name=jsonx.s(d, "name"),
        visibility=jsonx.s(d, "visibility"),
        archived_at=_opt_str(d, "archivedAt"),
    )


@dataclass
class GqlError:
    """One entry of a GraphQL errors array."""

    message: str = ""
    type: str = ""
    user_error: bool = False


def decode_gql_error(v: Any) -> GqlError:
    d = jsonx.obj(v, "error")
    ext = jsonx.o(d, "extensions")
    return GqlError(message=jsonx.s(d, "message"), type=jsonx.s(ext, "type"), user_error=jsonx.b(ext, "userError"))


USERS_QUERY = """query($email: String!) {
  users(filter: { email: { eqIgnoreCase: $email } }, includeDisabled: true, first: 50) {
    nodes { id email name active admin owner guest app disableReason }
  }
}"""

MEMBERSHIPS_QUERY = """query($id: String!, $first: Int!, $after: String) {
  user(id: $id) {
    teamMemberships(first: $first, after: $after) {
      nodes { owner team { id key } }
      pageInfo { hasNextPage endCursor }
    }
  }
}"""

TEAMS_QUERY = """query($filter: TeamFilter!) {
  teams(filter: $filter, first: 2, includeArchived: true) {
    nodes { id key name visibility archivedAt }
  }
}"""

ISSUE_QUERY = """query($id: String!) {
  issue(id: $id) {
    id identifier trashed archivedAt
    team { id key name visibility archivedAt }
  }
}"""

PROJECT_QUERY = """query($id: String!) {
  project(id: $id) {
    id name slugId trashed archivedAt
    teams(first: 50) { nodes { id key name visibility archivedAt } }
  }
}"""

VIEWER_QUERY = "{ viewer { id email admin owner app } organization { id name urlKey } }"


@dataclass
class _Memberships:
    teams: list[tuple[bool, str, str]] = field(default_factory=list)  # (owner, team id, team key)
    has_next_page: bool = False
    end_cursor: str | None = None


def _decode_memberships(data: dict[str, Any]) -> _Memberships:
    m = jsonx.o(jsonx.o(data, "user"), "teamMemberships")
    out = _Memberships()
    for n in jsonx.arr(m, "nodes"):
        n = jsonx.obj(n, "node")
        team = jsonx.o(n, "team")
        out.teams.append((jsonx.b(n, "owner"), jsonx.s(team, "id"), jsonx.s(team, "key")))
    pi = jsonx.o(m, "pageInfo")
    out.has_next_page = jsonx.b(pi, "hasNextPage")
    out.end_cursor = _opt_str(pi, "endCursor")
    return out


@dataclass(frozen=True)
class _Issue:
    id: str = ""
    identifier: str = ""
    trashed: bool | None = None
    archived_at: str | None = None
    team: GqlTeam = field(default_factory=GqlTeam)


def _decode_issue(data: dict[str, Any]) -> _Issue:
    d = jsonx.o(data, "issue")
    return _Issue(
        id=jsonx.s(d, "id"),
        identifier=jsonx.s(d, "identifier"),
        trashed=_opt_bool(d, "trashed"),
        archived_at=_opt_str(d, "archivedAt"),
        team=decode_team(jsonx.o(d, "team")),
    )


@dataclass(frozen=True)
class _Project:
    id: str = ""
    trashed: bool | None = None
    teams: tuple[GqlTeam, ...] = ()


def _decode_project(data: dict[str, Any]) -> _Project:
    d = jsonx.o(data, "project")
    return _Project(
        id=jsonx.s(d, "id"),
        trashed=_opt_bool(d, "trashed"),
        teams=tuple(decode_team(t) for t in jsonx.arr(jsonx.o(d, "teams"), "nodes")),
    )


class LinearConnection(Connection):
    """One Linear workspace."""

    def __init__(self, url: str) -> None:
        self.api: httpx.Client = httpx.Client()
        self.url = url

    # -- GraphQL transport --

    def query(self, ctx: Context, q: str, variables: dict[str, Any] | None, decode: Callable[[dict[str, Any]], T]) -> T:
        """Run one GraphQL query and decode data with decode. Linear reports
        most failures as HTTP 200 or 400 with an errors array, and rate
        limits as HTTP 400 with the type "ratelimited"."""
        try:
            resp = self.api.do(
                ctx,
                httpx.Request(method="POST", path=self.url, json={"query": q, "variables": variables}, idempotent=True, accept_4xx=True),
            )
        except Exception as e:
            he = httpx.classify(e)
            if he is e:
                raise
            raise he  # wrap_error already carries e as the cause
        if resp.status == 401:
            raise errorf(Code.CREDENTIAL_REJECTED, "Linear rejected hallpass's credential (HTTP 401)")
        if resp.status == 403:
            raise errorf(Code.CREDENTIAL_REJECTED, "Linear refused the request (HTTP 403): the credential lacks the read scope")
        if resp.status == 429:
            raise errorf(Code.UPSTREAM_RATE_LIMIT, "Linear rate limit exhausted (HTTP 429)")
        if resp.status not in (200, 400):
            raise errorf(Code.UPSTREAM_ERROR, f"Linear answered HTTP {resp.status}")
        try:
            env = jsonx.obj(resp.json(), "response")
            errors = [decode_gql_error(e) for e in jsonx.arr(env, "errors")]
        except ValueError as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, f"Linear's response was not JSON (HTTP {resp.status})") from e
        for e in errors:
            t = go_lower(e.type)
            if t in ("ratelimited", "usage limit exceeded"):
                raise errorf(Code.UPSTREAM_RATE_LIMIT, "Linear rate limit exhausted")
            if t == "authentication error":
                raise errorf(Code.CREDENTIAL_REJECTED, "Linear rejected hallpass's credential")
            if t in ("forbidden", "feature not accessible"):
                raise errorf(
                    Code.CREDENTIAL_REJECTED,
                    f"Linear refused the query ({e.type}): the credential lacks the read scope or the plan lacks the feature",
                )
            # UNVERIFIED: the shape of the not-found error; Linear's SDK maps
            # "Entity not found" messages, type "invalid input", to a user error.
            if "not found" in go_lower(e.message):
                raise NotFoundError()
        if errors:
            t = errors[0].type or "error"
            if resp.status == 400 and "RATELIMITED" in go_upper(resp.body.decode("utf-8", "replace")):
                raise errorf(Code.UPSTREAM_RATE_LIMIT, "Linear rate limit exhausted")
            raise errorf(Code.UPSTREAM_ERROR, f"Linear's GraphQL query failed ({t})")
        if resp.status != 200:
            raise errorf(Code.UPSTREAM_ERROR, f"Linear answered HTTP {resp.status} without errors")
        data = jsonx._get(env, "data")  # the case-insensitive member lookup
        if data is None:
            raise errorf(Code.UPSTREAM_ERROR, "Linear's response carried no data")
        try:
            return decode(jsonx.obj(data, "data"))
        except ValueError as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, "Linear's data could not be decoded") from e

    # -- identity --

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Find the user with the email and list the teams they belong to;
        the identity's groups are team ids and the attribute owned_teams the
        ids of teams the user owns."""
        email = go_lower(go_trim_space(u.email))
        if not is_email(email):
            raise errorf(Code.INVALID_REQUEST, f"user email {go_quote(email)} is not an address")
        try:
            nodes = self.query(ctx, USERS_QUERY, {"email": email}, lambda d: [decode_user(n) for n in jsonx.arr(jsonx.o(d, "users"), "nodes")])
        except NotFoundError as err:
            raise self.lookup_err(err, "search users") from None
        matches = [usr for usr in nodes if go_equal_fold(usr.email, email)]
        if not matches:
            raise user_not_found(f"no Linear user has email {email}")
        if len(matches) > 1:
            raise user_ambiguous(f"{len(matches)} Linear users have email {email}")
        usr = matches[0]
        if not UUID_RE.fullmatch(usr.id):
            raise errorf(Code.UPSTREAM_ERROR, "Linear returned a user id that is not an id")
        attrs = {
            "active": _go_bool(usr.active),
            "admin": _go_bool(usr.admin),
            "owner": _go_bool(usr.owner),
            "guest": _go_bool(usr.guest),
            "app": _go_bool(usr.app),
        }
        if usr.disable_reason:
            attrs["disable_reason"] = usr.disable_reason
        groups: list[str] = []
        owned: list[str] = []
        after: str | None = None
        page = 0
        while True:
            if page >= httpx.MAX_PAGES:
                raise errorf(Code.UPSTREAM_ERROR, f"{email} belongs to more teams than hallpass pages through")
            try:
                m = self.query(ctx, MEMBERSHIPS_QUERY, {"id": usr.id, "first": PAGE_SIZE, "after": after}, _decode_memberships)
            except NotFoundError as err:
                raise self.lookup_err(err, "list the user's teams") from None
            for is_owner, team_id, _key in m.teams:
                if team_id == "":
                    continue
                groups.append(team_id)
                if is_owner:
                    owned.append(team_id)
            if not m.has_next_page or not m.end_cursor:
                break
            after = m.end_cursor
            page += 1
        if owned:
            attrs["owned_teams"] = ",".join(owned)
        return Identity(id=usr.id, display=email, attrs=attrs, groups=tuple(groups))

    def lookup_err(self, err: BaseException, what: str) -> BaseException:
        """Classify an error from an identity query, where not-found is an
        upstream inconsistency rather than a resource question."""
        if isinstance(err, NotFoundError):
            return errorf(Code.UPSTREAM_ERROR, f"Linear could not {what}: the record vanished between queries")
        return err

    # -- checks --

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """Answer one question."""
        t = parse_target(r.action_name, r.resource)
        ident = r.identity
        who = ident.display
        if ident.attr("active") != "true":
            reason = ident.attr("disable_reason") or "deactivated"
            return denied(f"{who} is not an active Linear user ({reason})")
        if t.action.resource == "workspace":
            return check_workspace(t, ident)
        if ident.attr("app") == "true":
            return unsupported(f"{who} is an app user, whose team access hallpass does not model")
        res = t.action.resource
        if res == "team":
            team = self.team(ctx, t)
            if team is None:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"{t} does not exist or hallpass cannot see it")
            return check_team(t, team, ident)
        if res == "issue":
            try:
                issue = self.query(ctx, ISSUE_QUERY, {"id": t.id}, _decode_issue)
            except NotFoundError:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"{t} does not exist or hallpass cannot see it")
            if issue.id == "":
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"{t} does not exist or hallpass cannot see it")
            if issue.team.id == "":
                raise errorf(Code.UPSTREAM_ERROR, f"Linear returned {t} without its team")
            if issue.trashed:
                return unsupported(f"{t} is in the trash; hallpass does not model access to trashed issues")
            d = team_access(issue.team, ident)
            if d.code != Code.ALLOWED:
                return d
            return allowed(f"{who} may {t.action.desc}: {d.text}")
        if res == "project":
            try:
                project = self.query(ctx, PROJECT_QUERY, {"id": t.id}, _decode_project)
            except NotFoundError:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"{t} does not exist or hallpass cannot see it")
            if project.id == "":
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"{t} does not exist or hallpass cannot see it")
            if project.trashed:
                return unsupported(f"{t} is in the trash; hallpass does not model access to trashed projects")
            return check_project(t, list(project.teams), ident)
        raise invalid(f"unknown action {go_quote(t.action.name)}")

    def team(self, ctx: Context, t: Target) -> GqlTeam | None:
        """Read a team by key or id; None when there is none."""
        flt: dict[str, Any] = {"key": {"eq": t.id}}
        if t.by_id:
            flt = {"id": {"eq": t.id}}
        try:
            nodes = self.query(ctx, TEAMS_QUERY, {"filter": flt}, lambda d: [decode_team(n) for n in jsonx.arr(jsonx.o(d, "teams"), "nodes")])
        except NotFoundError:
            return None
        if len(nodes) == 0:
            return None
        if len(nodes) == 1:
            return nodes[0]
        raise errorf(Code.UPSTREAM_ERROR, f"Linear returned {len(nodes)} teams for {t}")

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """Read the credential's own user and the workspace."""

        def decode(d: dict[str, Any]) -> tuple[GqlUser, str, str]:
            org = jsonx.o(d, "organization")
            return decode_user(jsonx.o(d, "viewer")), jsonx.s(org, "name"), jsonx.s(org, "urlKey")

        try:
            viewer, _name, url_key = self.query(ctx, VIEWER_QUERY, None, decode)
        except NotFoundError as err:
            raise self.lookup_err(err, "read its own user") from None
        if viewer.id == "":
            raise errorf(Code.CREDENTIAL_REJECTED, "Linear answered without a viewer; the credential is not valid")
        warnings = []
        if not viewer.admin and not viewer.owner:
            warnings.append("hallpass's user is not a workspace administrator: private teams it has not joined answer unknown")
        warnings.append("a personal API key acts with the full permissions of its user; keep it tightly held")
        return ProbeResult(summary=f"authenticated as {viewer.email} in workspace {url_key}", warnings=tuple(warnings))


def _go_bool(b: bool) -> str:
    """fmt.Sprint of a bool."""
    return "true" if b else "false"


def check_workspace(t: Target, ident: Identity) -> Decision:
    who = ident.display
    if t.action.name == "workspace.owner":
        if ident.attr("owner") == "true":
            return allowed(f"{who} is a workspace owner")
        return denied(f"{who} is not a workspace owner")
    if t.action.name == "workspace.admin":
        if ident.attr("owner") == "true":
            return allowed(f"{who} is a workspace owner")
        if ident.attr("admin") == "true":
            return allowed(f"{who} is a workspace administrator")
        return denied(f"{who} is neither a workspace administrator nor an owner")
    if ident.attr("app") == "true":
        return denied(f"{who} is an app user, not a member")
    if ident.attr("guest") == "true":
        return denied(f"{who} is a guest, limited to the teams they joined")
    return allowed(f"{who} is a full member of the workspace")


def team_access(team: GqlTeam, ident: Identity) -> Decision:
    """Whether the user can see the team and its issues. The text names the
    reason for the action's own text."""
    who = ident.display
    label = team.key or team.id
    if team.archived_at:
        return unsupported(f"team {label} is archived; hallpass does not model access to archived teams")
    member = contains(ident.groups, team.id)
    vis = team.visibility
    if vis == "public":
        if member:
            return allowed(f"{who} is a member of public team {label}")
        if ident.attr("guest") == "true":
            return denied(f"{who} is a guest and not a member of team {label}")
        return allowed(f"team {label} is public and {who} is a workspace member")
    if vis == "private":
        if member:
            return allowed(f"{who} is a member of private team {label}")
        if ident.attr("admin") == "true" or ident.attr("owner") == "true":
            # UNVERIFIED: whether workspace administrators see the issues of
            # private teams they have not joined.
            return unsupported(
                f"team {label} is private and {who} is a workspace administrator but not a member; "
                "whether administrators see private team content is not something hallpass can read"
            )
        return denied(f"team {label} is private and {who} is not a member")
    if vis == "restricted":
        if member:
            return allowed(f"{who} is a member of restricted team {label}")
        # UNVERIFIED: a restricted team sits inside a private team's
        # boundary; members of the parent may see it.
        return unsupported(f"team {label} is restricted (inside a private team) and {who} is not a member; hallpass does not read the private boundary")
    return unsupported(f"team {label} has visibility {go_quote(vis)}, which hallpass does not know")


def check_team(t: Target, team: GqlTeam, ident: Identity) -> Decision:
    who = ident.display
    member = contains(ident.groups, team.id)
    if team.archived_at:
        return unsupported(f"team {team.key} is archived; hallpass does not model access to archived teams")
    if t.action.name == "team.view":
        return team_access(team, ident)
    if t.action.name == "team.member":
        if member:
            return allowed(f"{who} is a member of team {team.key}")
        return denied(f"{who} is not a member of team {team.key}")
    # team.admin
    if ident.attr("owner") == "true" or ident.attr("admin") == "true":
        return allowed(f"{who} is a workspace administrator, who may manage any team")
    if contains(ident.attr("owned_teams").split(","), team.id):
        return allowed(f"{who} is an owner of team {team.key}")
    if not member:
        return denied(f"{who} is not a member of team {team.key}")
    # UNVERIFIED: team owners choose whether all members or only owners
    # manage team settings; the setting is not exposed in the API.
    return unsupported(f"{who} is a member but not an owner of team {team.key}; whether members may manage its settings is a team setting hallpass cannot read")


def check_project(t: Target, teams: list[GqlTeam], ident: Identity) -> Decision:
    """Allow when any of the project's teams is visible to the user, deny
    when all are denied, unknown otherwise."""
    who = ident.display
    if not teams:
        return unsupported(f"{t} belongs to no team; hallpass cannot tell who sees it")
    unknown: Decision | None = None
    n_denied = 0
    for team in teams:
        d = team_access(team, ident)
        if d.code == Code.ALLOWED:
            return allowed(f"{who} may see {t}: {d.text}")
        if d.code == Code.DENIED:
            n_denied += 1
        elif unknown is None:
            unknown = d
    if unknown is not None:
        return unknown
    return denied(f"{who} cannot see any of the {n_denied} team(s) of {t}")


def contains(xs: list[str] | tuple[str, ...], x: str) -> bool:
    return x != "" and x in xs


__all__ = [
    "AUTH_API_KEY",
    "AUTH_OAUTH",
    "DEFAULT_URL",
    "Linear",
    "LinearConnection",
    "NotFoundError",
]
