"""Checks what a user may do in one PagerDuty account.

hallpass authenticates with a read-only General Access REST API key, finds
the user by email, reads the user's base role and, when the object asked
about belongs to teams, the user's role on each of those teams. Base roles
set account-wide access (owner and admin everything, user every
configuration change and incident action, limited_user incident actions and
overrides, observer and restricted_access nothing, the two stakeholder
roles nothing); a team role adds access to the team's incidents, services,
escalation policies and schedules. Nothing is written.
"""

from __future__ import annotations

import re
from typing import Any

from hallpass.core import jsonx
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
)
from hallpass.core.secret import SecretError
from hallpass.core.template import is_email
from hallpass.integrations.pagerduty.actions import (
    ROLE_ADMIN,
    ROLE_LIMITED_USER,
    ROLE_OBSERVER,
    ROLE_OWNER,
    ROLE_READ_ONLY,
    ROLE_READ_ONLY_LTD,
    ROLE_RESTRICTED,
    ROLE_USER,
    TEAM_ROLE_MANAGER,
    TEAM_ROLE_OBSERVER,
    TEAM_ROLE_RESPONDER,
    Need,
    Target,
    catalog_actions,
    parse_target,
)
from hallpass.net import httpx

__all__ = ["ACCEPT", "DEFAULT_URL", "PagerDuty", "PagerDutyConnection"]

DEFAULT_URL = "https://api.pagerduty.com"
ACCEPT = "application/vnd.pagerduty+json;version=2"
PAGE_SIZE = 100

# Finds the numeric code of a PagerDuty error body snippet (Go's \s and \d
# are ASCII only).
_ERROR_CODE_RE = re.compile(r'"code"[\t\n\f\r ]*:[\t\n\f\r ]*([0-9]+)')


class PagerDuty(Integration):
    """The pagerduty product."""

    def name(self) -> str:
        return "pagerduty"

    def fields(self) -> list[Field]:
        return [
            url_field(False, "API URL; default https://api.pagerduty.com, EU accounts https://api.eu.pagerduty.com"),
            credential_field(True, "a read-only General Access REST API key"),
        ]

    def actions(self) -> list[Action]:
        return catalog_actions()

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        """Build a connection. It touches no network."""
        hc = d.http_client(s)
        if s.secret("credential").is_zero():
            raise ValueError("credential is required")
        base = s.get("url").rstrip("/")
        if base == "":
            base = DEFAULT_URL
        cred = s.secret("credential")

        def auth(ctx: Context, r: httpx.PreparedRequest) -> None:
            try:
                t = cred.get_string()
            except SecretError as e:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the API key could not be read") from e
            r.headers.set("Authorization", "Token token=" + go_trim_space(t))
            r.headers.set("Accept", ACCEPT)
            # The API description declares Content-Type on every call, reads
            # included.
            r.headers.set("Content-Type", "application/json")

        return PagerDutyConnection(httpx.Client(http=hc, base=base, auth=auth, logger=d.logger))


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


def _refs(d: dict[str, Any], key: str) -> list[str]:
    """The ids of a []reference field."""
    out = []
    for r in jsonx.arr(d, key):
        r = jsonx.obj(r)
        jsonx.s(r, "type"), jsonx.s(r, "summary")
        out.append(jsonx.s(r, "id"))
    return out


def _error_code(err: BaseException) -> str:
    se = as_error(err, httpx.StatusError)
    if se is None:
        return ""
    m = _ERROR_CODE_RE.search(se.snippet)
    return m.group(1) if m else ""


def _code_or(code: str, default: str) -> str:
    return default if code == "" else code


def classify(err: BaseException, what: str) -> HallpassError:
    """Map an API error to an integration error. 404 is left to the
    caller, who knows what is missing."""
    st = httpx.status(err)
    if st == 401:
        return wrap_error(Code.CREDENTIAL_REJECTED, err, "PagerDuty rejected hallpass's API key")
    if st == 403:
        return wrap_error(
            Code.CREDENTIAL_REJECTED, err, f"PagerDuty refused to {what} (error {_code_or(_error_code(err), '2010')}): the API key may not read it"
        )
    if st == 402:
        return wrap_error(Code.UNSUPPORTED, err, f"the account lacks the ability to {what} (HTTP 402)")
    if st == 400:
        return wrap_error(Code.INVALID_REQUEST, err, f"PagerDuty rejected the request to {what} (error {_code_or(_error_code(err), '2001')})")
    he = httpx.classify(err)
    assert he is not None
    return he


def _team_role_rank(r: str) -> int:
    if r == TEAM_ROLE_MANAGER:
        return 3
    if r == TEAM_ROLE_RESPONDER:
        return 2
    if r == TEAM_ROLE_OBSERVER:
        return 1
    return 0


_ROLE_NAMES = {
    ROLE_OWNER: "Account Owner",
    ROLE_ADMIN: "Global Admin",
    ROLE_USER: "Manager",
    ROLE_LIMITED_USER: "Responder",
    ROLE_OBSERVER: "Observer",
    ROLE_RESTRICTED: "Restricted Access user",
    ROLE_READ_ONLY: "Full Stakeholder",
    ROLE_READ_ONLY_LTD: "Limited Stakeholder",
}


def role_name(role: str) -> str:
    """The web UI's name for an API base role."""
    return _ROLE_NAMES.get(role, role)


def _decision_for(err: BaseException, t: Target) -> Decision:
    """An object lookup error as a decision: a 404 is an object hallpass
    cannot see, everything else is classified (raised)."""
    if httpx.status(err) == 404:
        return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"{t} does not exist or hallpass cannot see it")
    raise classify(err, "read " + str(t)) from err


class PagerDutyConnection(Connection):
    """One PagerDuty account."""

    def __init__(self, api: httpx.Client) -> None:
        self.api = api

    def _get(self, ctx: Context, path: str, q: dict[str, str] | None = None) -> dict[str, Any]:
        """GET path and decode the body as an object (Go: getJSON into a
        struct)."""
        _, v = self.api.get_json(ctx, path, q)
        return jsonx.obj(v)

    # -- identity --

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Find the user with the email. The search is by name and email on
        PagerDuty's side, so the address is compared exactly."""
        email = go_lower(go_trim_space(u.email))
        if not is_email(email):
            raise errorf(Code.INVALID_REQUEST, f"user email {go_quote(email)} is not an address")
        matches: list[dict[str, Any]] = []
        offset = 0
        n = 0
        while True:
            if n >= httpx.MAX_PAGES:
                raise errorf(Code.UPSTREAM_ERROR, f"too many users match {email}")
            q = {"query": email, "limit": str(PAGE_SIZE), "offset": str(offset), "include[]": "teams"}
            try:
                page = self._get(ctx, "/users", q)
                users = [jsonx.obj(x) for x in jsonx.arr(page, "users")]
                for usr in users:
                    # Decode every field Go's struct reads, so a wrong type
                    # fails the lookup as Go's decoder would.
                    jsonx.s(usr, "id"), jsonx.s(usr, "name"), jsonx.s(usr, "role")
                    _refs(usr, "teams")
                more = jsonx.b(page, "more")
            except Exception as e:
                raise classify(e, "search users") from e
            for usr in users:
                if equal_fold(jsonx.s(usr, "email"), email):
                    matches.append(usr)
            # The server may page smaller than asked; advance by what it sent.
            if not more or len(users) == 0:
                break
            offset += len(users)
            n += 1
        if len(matches) == 0:
            raise user_not_found(f"no PagerDuty user has email {email}")
        if len(matches) > 1:
            raise user_ambiguous(f"{len(matches)} PagerDuty users have email {email}")
        usr = matches[0]
        uid, role = jsonx.s(usr, "id"), jsonx.s(usr, "role")
        if uid == "" or role == "":
            raise errorf(Code.UPSTREAM_ERROR, f"the user record for {email} carries no id or role")
        groups = tuple(t for t in _refs(usr, "teams") if t != "")
        return Identity(id=uid, display=email, attrs={"role": role}, groups=groups)

    # -- checks --

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """Answer one question."""
        t = parse_target(r.action_name, r.resource)
        role = r.identity.attr("role")
        if role not in _ROLE_NAMES:
            return unsupported(f"{r.identity.display} has base role {go_quote(role)}, which hallpass does not know")
        who = r.identity.display
        need = t.action.need
        if need == Need.ACCOUNT_ADMIN:
            if role in (ROLE_OWNER, ROLE_ADMIN):
                return allowed(f"{who} is a {role_name(role)}")
            return denied(f"{who} is a {role_name(role)}, not an account owner or global admin")
        # The object is read first, whatever the role: a deleted or invisible
        # id is unknown, never an allow.
        try:
            teams = self._object_teams(ctx, t)
        except Exception as e:  # noqa: BLE001 - Go: every error is decided on (404) or classified
            return _decision_for(e, t)
        if need == Need.TEAM_MEMBER:
            if t.id in r.identity.groups:
                return allowed(f"{who} is a member of {t}")
            return denied(f"{who} is not a member of {t}")
        # Stakeholders never act.
        if role in (ROLE_READ_ONLY, ROLE_READ_ONLY_LTD):
            return denied(f"{who} is a {role_name(role)}, a read-only role")
        # Account-wide grants of the base role.
        if role in (ROLE_OWNER, ROLE_ADMIN):
            return allowed(f"{who} is a {role_name(role)}, which may {t.action.desc} anywhere")
        if role == ROLE_USER:
            return allowed(f"{who} has the Manager base role, which may {t.action.desc} anywhere")
        if role == ROLE_LIMITED_USER and need == Need.RESPOND:
            return allowed(f"{who} has the Responder base role, which may {t.action.desc} anywhere")
        # Everything else depends on a team role on the object's teams. The
        # user record lists the user's teams, so only those are read.
        mine = [team for team in teams if team in r.identity.groups]
        if len(teams) == 0 or len(mine) == 0:
            if role == ROLE_LIMITED_USER and need == Need.MAINTENANCE:
                return unsupported(
                    f"{who} has the Responder base role and no team role on {t}; whether a Responder may set maintenance windows account-wide is not documented"
                )
            if len(teams) == 0:
                return denied(f"{who} has the {role_name(role)} base role and {t} belongs to no team that could grant more")
            return denied(f"{who} has the {role_name(role)} base role and is on none of the teams of {t}")
        best = ""
        for team in mine:
            try:
                tr = self._team_role(ctx, team, r.identity.id)
            except Exception as e:
                if httpx.status(e) == 404:
                    return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"team {team} of {t} does not exist or hallpass cannot see it")
                raise classify(e, "read the members of team " + team) from e
            if _team_role_rank(tr) > _team_role_rank(best):
                best = tr
            if best == TEAM_ROLE_MANAGER:
                break
        if need in (Need.RESPOND, Need.MAINTENANCE):
            if best in (TEAM_ROLE_RESPONDER, TEAM_ROLE_MANAGER):
                return allowed(f"{who} is a team {best} on a team of {t}, which may {t.action.desc}")
            if role == ROLE_LIMITED_USER and need == Need.MAINTENANCE:
                return unsupported(
                    f"{who} has the Responder base role and no responder or manager team role on the teams of {t}; "
                    "whether a Responder may set maintenance windows account-wide is not documented"
                )
        elif need == Need.MANAGE:
            if best == TEAM_ROLE_MANAGER:
                return allowed(f"{who} is a team manager on a team of {t}, which may {t.action.desc}")
        if best == "":
            return denied(f"{who} has the {role_name(role)} base role and no team role on the teams of {t}")
        return denied(f"{who} has the {role_name(role)} base role and is a team {best} on the teams of {t}, which may not {t.action.desc}")

    def _object_teams(self, ctx: Context, t: Target) -> list[str]:
        """The teams the object belongs to. For an incident they are the
        incident's own teams and its service's."""
        seen: set[str] = set()
        out: list[str] = []

        def add(ids: list[str]) -> None:
            for i in ids:
                if i != "" and i not in seen:
                    seen.add(i)
                    out.append(i)

        res = t.action.resource
        if res == "incident":
            body = self._get(ctx, "/incidents/" + httpx.path_escape(t.id), {"include[]": "services"})
            inc = jsonx.o(body, "incident")
            svc = jsonx.o(inc, "service")
            inc_teams, svc_teams = _refs(inc, "teams"), _refs(svc, "teams")
            svc_id, svc_type = jsonx.s(svc, "id"), jsonx.s(svc, "type")
            add(inc_teams)
            add(svc_teams)
            if svc_id != "" and svc_type != "service":
                # The service came as a reference, not expanded; read it.
                sb = self._get(ctx, "/services/" + httpx.path_escape(svc_id))
                add(_refs(jsonx.o(sb, "service"), "teams"))
        elif res == "service":
            body = self._get(ctx, "/services/" + httpx.path_escape(t.id))
            add(_refs(jsonx.o(body, "service"), "teams"))
        elif res == "escalation_policy":
            body = self._get(ctx, "/escalation_policies/" + httpx.path_escape(t.id))
            add(_refs(jsonx.o(body, "escalation_policy"), "teams"))
        elif res == "schedule":
            body = self._get(ctx, "/schedules/" + httpx.path_escape(t.id))
            add(_refs(jsonx.o(body, "schedule"), "teams"))
        elif res == "team":
            # exists: the object is read without keeping it.
            self._get(ctx, "/teams/" + httpx.path_escape(t.id))
            out = [t.id]
        return out

    def _team_role(self, ctx: Context, team: str, user_id: str) -> str:
        """The user's role on a team: manager, responder, observer or ""
        for a non-member."""
        offset = 0
        n = 0
        while True:
            if n >= httpx.MAX_PAGES:
                raise errorf(Code.UPSTREAM_ERROR, f"team {team} has too many members to read")
            q = {"limit": str(PAGE_SIZE), "offset": str(offset)}
            page = self._get(ctx, "/teams/" + httpx.path_escape(team) + "/members", q)
            members = []
            for m in jsonx.arr(page, "members"):
                m = jsonx.obj(m)
                u = jsonx.o(m, "user")
                jsonx.s(u, "type"), jsonx.s(u, "summary")
                members.append((jsonx.s(u, "id"), jsonx.s(m, "role")))
            more = jsonx.b(page, "more")
            for uid, role in members:
                if uid == user_id:
                    return role
            if not more or len(members) == 0:
                return ""
            offset += len(members)
            n += 1

    # -- probe --

    def probe(self, ctx: Context) -> ProbeResult:
        """Verify the key and report the account abilities that matter."""
        try:
            abilities = jsonx.strs(self._get(ctx, "/abilities"), "abilities")
        except Exception as e:
            raise classify(e, "list the account abilities") from e
        try:
            users = self._get(ctx, "/users", {"limit": "1"})
            for usr in jsonx.arr(users, "users"):
                usr = jsonx.obj(usr)
                for k in ("id", "name", "email", "role"):
                    jsonx.s(usr, k)
                _refs(usr, "teams")
        except Exception as e:
            raise classify(e, "list users") from e
        has = set(abilities)
        warnings: list[str] = []
        if "teams" not in has:
            warnings.append(
                "the account lacks the teams ability: objects belong to no team, "
                "so observer and restricted_access users are denied everything but their base role allows"
            )
        if "advanced_permissions" not in has and "permissions_teams" not in has:
            warnings.append("no advanced permissions ability was reported: team roles may not be in effect on this plan (see docs)")
        warnings.append('hallpass cannot tell a read-only key from a full one; create the key with "Read-only API Key" checked')
        return ProbeResult(summary=f"API key reads users and abilities at {self.api.base} ({len(abilities)} abilities)", warnings=tuple(warnings))
