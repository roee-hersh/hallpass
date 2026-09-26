"""Checks Jira Cloud permissions with the permissions/check API.

hallpass resolves the caller's email to an Atlassian accountId with the
user search API, then asks POST /rest/api/3/permissions/check whether that
account holds the permission on a project, an issue or globally. Jira
evaluates permission schemes, project roles, groups and issue-level grants;
hallpass only reads the answer. Nothing is changed.

The package also holds the Atlassian Cloud transport (Site, in site.py)
that the confluence integration shares. Jira Data Center is out of scope.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
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
    unsupported,
    user_ambiguous,
    user_not_found,
    wrap_error,
)
from hallpass.core.errors import as_error, go_quote, go_trim_space
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
)
from hallpass.integrations.jira.actions import ACTION_LIST, ACTIONS, ResKind, parse_resource
from hallpass.integrations.jira.site import Site, new_site, site_fields
from hallpass.net import httpx

__all__ = ["Jira", "JiraConnection", "equal_fold"]

# maxResults for user/search, and how many pages hallpass reads before
# giving up on a crowded query.
USER_SEARCH_PAGE_SIZE = 50
USER_SEARCH_MAX_PAGES = 5

_INT64_MAX = (1 << 63) - 1
_INT64_MIN = -(1 << 63)


class Jira(Integration):
    """The jira product."""

    def name(self) -> str:
        return "jira"

    def fields(self) -> list[Field]:
        return site_fields()

    def actions(self) -> list[Action]:
        """The native permission keys."""
        return [Action(name=a.name, description=a.desc) for a in ACTION_LIST]

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        return JiraConnection(new_site(s, d, "jira"))


# -- helpers -------------------------------------------------------------------


def _fold(c: str) -> str:
    """The simple case folding of one rune."""
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


def _classify(err: BaseException) -> HallpassError:
    out = httpx.classify(err)
    assert out is not None
    return out


def _int64s(d: dict[str, Any], key: str) -> list[int]:
    """A []int64 field: every element an integer literal in range; a null
    element is 0."""
    out = []
    for x in jsonx.arr(d, key):
        if x is None:
            out.append(0)
            continue
        if isinstance(x, bool) or not isinstance(x, int) or not _INT64_MIN <= x <= _INT64_MAX:
            raise jsonx.DecodeError(f"json: cannot unmarshal {x!r} into field {key} of type int64")
        out.append(x)
    return out


@dataclass(frozen=True)
class _User:
    account_id: str
    account_type: str
    active: bool
    email: str
    display: str


def _decode_users(v: Any) -> list[_User]:
    """A []user: an array (null is empty) of user objects."""
    if v is None:
        return []
    if not isinstance(v, list):
        raise jsonx.DecodeError("json: cannot unmarshal into []user")
    out = []
    for x in v:
        u = jsonx.obj(x, "user")
        out.append(
            _User(
                account_id=jsonx.s(u, "accountId"),
                account_type=jsonx.s(u, "accountType"),
                active=jsonx.b(u, "active"),
                email=jsonx.s(u, "emailAddress"),
                display=jsonx.s(u, "displayName"),
            )
        )
    return out


def _identity_of(u: _User) -> Identity:
    return Identity(id=u.account_id, display=u.display)


@dataclass(frozen=True)
class _ProjectPermissionEcho:
    permission: str
    projects: list[int]
    issues: list[int]


@dataclass(frozen=True)
class _CheckResponse:
    project_permissions: list[_ProjectPermissionEcho]
    global_permissions: list[str]

    def grants(self, perm: str, kind: ResKind, id: int) -> tuple[bool, bool]:
        """(granted, evaluated): whether the response lists the id under the
        permission, and whether it echoed the permission at all. Jira echoes
        every project permission it evaluated, with the ids that hold it, so
        a key missing from the echo was not evaluated and must not read as
        deny. Global permissions have no echo: the response lists only the
        keys the account holds."""
        if kind == ResKind.GLOBAL:
            return perm in self.global_permissions, True
        evaluated = False
        for pp in self.project_permissions:
            if pp.permission != perm:
                continue
            evaluated = True
            ids = pp.issues if kind == ResKind.ISSUE else pp.projects
            if id in ids:
                return True, True
        return False, evaluated


def _decode_check_response(v: Any) -> _CheckResponse:
    d = jsonx.obj(v)
    pps = []
    for x in jsonx.arr(d, "projectPermissions"):
        pp = jsonx.obj(x)
        pps.append(_ProjectPermissionEcho(jsonx.s(pp, "permission"), _int64s(pp, "projects"), _int64s(pp, "issues")))
    return _CheckResponse(pps, jsonx.strs(d, "globalPermissions"))


def _decision_or_raise(err: BaseException) -> Decision:
    """A not-visible error as a decision; everything else is raised."""
    ie = as_error(err, HallpassError)
    if ie is not None and ie.code == Code.RESOURCE_NOT_VISIBLE:
        return ie.decision()
    raise err


_PARSE_INT_RE = re.compile(r"[+-]?[0-9]+")


def _parse_id(s: str) -> int:
    """strconv.ParseInt(s, 10, 64), and positive."""
    if _PARSE_INT_RE.fullmatch(s):
        n = int(s)
        if 0 < n <= _INT64_MAX:
            return n
    raise ValueError("upstream returned a non-numeric id")


class JiraConnection(Connection):
    """One Jira Cloud site."""

    def __init__(self, site: Site) -> None:
        self._site = site

    def site(self) -> Site:
        """The transport, for integrations on the same site."""
        return self._site

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Map the caller's email to an Atlassian accountId."""
        return self.lookup_account_id(ctx, u.email)

    def lookup_account_id(self, ctx: Context, email: str) -> Identity:
        """Find the one active Atlassian account with the email. The
        confluence integration uses it, since Confluence's own user search
        has no email field.

        user/search?query= matches displayName as well as emailAddress, so a
        result counts only when its emailAddress equals the request email
        case-insensitively. A display name that looks like the email never
        does: a candidate whose email the profile hides is answered
        unsupported, not accepted, because hallpass cannot tell it from an
        impostor.
        """
        email = go_trim_space(email)
        if email == "":
            raise errorf(Code.INVALID_REQUEST, "no email given")
        # UNVERIFIED: whether the query parameter matches an email the
        # profile hides. When it does not, hidden accounts never show up here
        # and the answer is user_not_found rather than the hidden-email
        # branch below.
        matches: list[_User] = []
        hidden: list[_User] = []
        last_full = False
        for page in range(USER_SEARCH_MAX_PAGES):
            q = {
                "query": email,
                "startAt": str(page * USER_SEARCH_PAGE_SIZE),
                "maxResults": str(USER_SEARCH_PAGE_SIZE),
            }
            try:
                _, v = self._site.get_json(ctx, "/rest/api/3/user/search", q)
                users = _decode_users(v)
            except Exception as e:
                if httpx.status(e) == 403:
                    raise wrap_error(
                        Code.CREDENTIAL_REJECTED, e, "hallpass's account may not search users; it needs Browse users and groups (HTTP 403)"
                    ) from e
                raise _classify(e) from e
            for usr in users:
                if usr.account_type != "atlassian" or not usr.active:
                    continue
                if usr.email == "":
                    hidden.append(usr)
                elif equal_fold(usr.email, email):
                    matches.append(usr)
            last_full = len(users) >= USER_SEARCH_PAGE_SIZE
            if not last_full:
                break
        if len(matches) == 1:
            return _identity_of(matches[0])
        if len(matches) > 1:
            raise user_ambiguous(f"{len(matches)} active Atlassian accounts have the email {email}")
        if last_full:
            # Every page read was full, so more candidates may follow; a not
            # found here could be a user on a page hallpass did not read.
            raise errorf(
                Code.UNSUPPORTED,
                f"too many candidates: the user search for {email} filled {USER_SEARCH_MAX_PAGES} pages without an exact email match",
            )
        if hidden:
            raise errorf(
                Code.UNSUPPORTED,
                f"email hidden by profile visibility: {len(hidden)} candidate(s) for {email} show no email; "
                "make the email visible to the site or use a scoped token that can read it",
            )
        raise user_not_found(f"no active Atlassian account has the email {email}")

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """Post one permissions/check for the account and the resource."""
        act = ACTIONS.get(r.action_name)
        if act is None:
            raise errorf(Code.INVALID_REQUEST, f"unknown action {go_quote(r.action_name)}")
        try:
            res = parse_resource(r.resource)
        except ValueError as e:
            raise errorf(Code.INVALID_REQUEST, str(e)) from None
        if act.global_ and res.kind != ResKind.GLOBAL:
            raise errorf(Code.INVALID_REQUEST, f"{act.name} is a global permission; use the resource global")
        if not act.global_ and res.kind == ResKind.GLOBAL:
            raise errorf(Code.INVALID_REQUEST, f"{act.name} is a project permission; use project:<KEY> or issue:<KEY-N>")
        body: dict[str, Any] = {"accountId": r.identity.id}
        id = 0
        if res.kind == ResKind.GLOBAL:
            body["globalPermissions"] = [act.name]
        elif res.kind == ResKind.PROJECT:
            try:
                id = self._project_id(ctx, res.key)
            except Exception as e:
                return _decision_or_raise(e)
            body["projectPermissions"] = [{"permissions": [act.name], "projects": [id]}]
        else:
            try:
                id = self._issue_id(ctx, res.key)
            except Exception as e:
                return _decision_or_raise(e)
            body["projectPermissions"] = [{"permissions": [act.name], "issues": [id]}]
        try:
            _, v = self._site.post_json(ctx, "/rest/api/3/permissions/check", body, True)
            out = _decode_check_response(v)
        except Exception as e:
            st = httpx.status(e)
            if st == 403:
                raise wrap_error(
                    Code.CREDENTIAL_REJECTED, e, "hallpass's account may not check other users' permissions; it needs Administer Jira (HTTP 403)"
                ) from e
            if st == 400:
                # UNVERIFIED: Jira answers 400 for a permission key it does
                # not know. A project permission it silently drops instead is
                # caught below (no echo -> unsupported); a dropped global
                # permission has no echo to check and would read as deny.
                return unsupported(f"Jira rejected the permission check for {act.name}; the permission key may not exist on this site")
            raise _classify(e) from e
        who = r.identity.display or r.identity.id
        granted, evaluated = out.grants(act.name, res.kind, id)
        if not evaluated:
            return unsupported(f"Jira did not evaluate the permission key {act.name} for {res.describe()}; the key may not exist on this site")
        if granted:
            return allowed(f"{who} holds {act.name} on {res.describe()}")
        return denied(f"{who} does not hold {act.name} on {res.describe()}")

    def _lookup_id(self, ctx: Context, path: str, q: dict[str, str] | None, what: str) -> int:
        try:
            _, v = self._site.get_json(ctx, path, q)
            raw = jsonx.s(jsonx.obj(v), "id")
        except Exception as e:
            raise self._lookup_error(e, what) from e
        try:
            return _parse_id(raw)
        except ValueError as e:
            raise wrap_error(Code.UPSTREAM_ERROR, e, f"{what}: {e}") from e

    def _project_id(self, ctx: Context, key: str) -> int:
        """Look the project up by key. The bulk permission endpoint silently
        ignores unknown ids, so this lookup is what distinguishes a missing
        project from a denied one."""
        return self._lookup_id(ctx, "/rest/api/3/project/" + httpx.path_escape(key), None, "project " + key)

    def _issue_id(self, ctx: Context, key: str) -> int:
        """Look the issue up by key."""
        return self._lookup_id(ctx, "/rest/api/3/issue/" + httpx.path_escape(key), {"fields": "project"}, "issue " + key)

    def _lookup_error(self, err: BaseException, what: str) -> HallpassError:
        st = httpx.status(err)
        if st == 404:
            return wrap_error(Code.RESOURCE_NOT_VISIBLE, err, f"{what} does not exist or is not visible to hallpass's account")
        if st == 403:
            return wrap_error(Code.CREDENTIAL_REJECTED, err, f"hallpass's account may not browse {what} (HTTP 403)")
        return _classify(err)

    def probe(self, ctx: Context) -> ProbeResult:
        """Verify the credential, check for Administer Jira and validate
        that every action key exists on the site."""
        try:
            _, v = self._site.get_json(ctx, "/rest/api/3/myself")
            me = jsonx.obj(v)
            account_id, display_name = jsonx.s(me, "accountId"), jsonx.s(me, "displayName")
        except Exception as e:
            if httpx.status(e) == 403:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the credential is valid but may not read its own profile (HTTP 403)") from e
            raise _classify(e) from e
        summary = f"authenticated as {display_name} ({account_id}) with auth_mode {self._site.mode}"
        warnings: list[str] = []

        try:
            _, v = self._site.get_json(ctx, "/rest/api/3/mypermissions", {"permissions": "ADMINISTER"})
            perms = jsonx.o(jsonx.obj(v), "permissions")
            have: dict[str, bool] = {}
            for k, p in perms.items():
                have[k] = jsonx.b(jsonx.obj(p), "havePermission")
        except Exception as e:
            raise _classify(e) from e
        if not have.get("ADMINISTER", False):
            warnings.append("hallpass's account lacks Administer Jira; permissions/check for other users will answer unknown (credential_rejected)")

        try:
            _, v = self._site.get_json(ctx, "/rest/api/3/permissions")
            known = jsonx.o(jsonx.obj(v), "permissions")
        except Exception as e:
            raise _classify(e) from e
        missing = [a.name for a in ACTION_LIST if a.name not in known]
        if missing:
            warnings.append("this site does not list the permission keys " + ", ".join(missing) + "; checks for them will answer unknown or deny")
        return ProbeResult(summary=summary, warnings=tuple(warnings))

