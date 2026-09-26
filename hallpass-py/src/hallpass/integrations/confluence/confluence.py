"""Checks Confluence Cloud permissions.

Page and blog post actions go to Confluence's own permission check,
POST /wiki/rest/api/content/{id}/permission/check, which weighs site, space
and content restrictions for the given account. Space actions have no such
call, so hallpass reads the space's permission list
(GET /wiki/api/v2/spaces/{id}/permissions) and the user's groups and
matches them itself; a space administrator (administer/space) holds every
space operation, and a grant to a principal hallpass cannot resolve
(anonymous, a role, licensed users) answers unknown rather than deny.

Confluence's user search has no email field, so the caller's email is
resolved through a jira connection on the same Atlassian site
(identity_connection). The transport (auth modes, cloud id discovery) is
the jira package's Site. Confluence Data Center is out of scope.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
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
    wrap_error,
)
from hallpass.core.errors import go_quote, go_trim_space
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
)
from hallpass.core.integration import _go_url_parse as go_url_parse
from hallpass.integrations.confluence.actions import ACTION_LIST, ACTIONS, ConfluenceAction, ConfluenceResource, ResKind, parse_resource
from hallpass.integrations.jira import JiraConnection, Site, new_site, site_fields
from hallpass.net import httpx

__all__ = ["NO_IDENTITY_TEXT", "Confluence", "ConfluenceConnection", "next_path"]

# The reason every check answers unknown when no jira connection is
# configured for email lookup.
NO_IDENTITY_TEXT = "Confluence cannot look up users by email; set identity_connection to a jira connection on the same site"

# Space administrators (administer/space) implicitly hold every space
# operation, so that grant is evaluated alongside the requested one.
ADMIN_OPERATION = "administer"
ADMIN_TARGET = "space"


class Confluence(Integration):
    """The confluence product."""

    def name(self) -> str:
        return "confluence"

    def fields(self) -> list[Field]:
        """The Atlassian site keys plus identity_connection."""
        return [
            *site_fields(),
            connection_ref_field("identity_connection", "jira", False, "jira connection on the same Atlassian site, used to look users up by email"),
        ]

    def actions(self) -> list[Action]:
        return [Action(name=a.name, description=a.desc) for a in ACTION_LIST]

    def new(self, ctx: Context, s: Settings, d: Deps) -> Connection:
        site = new_site(s, d, "confluence")
        identity: JiraConnection | None = None
        id = s.get("identity_connection")
        if id != "":
            jc = d.connection(id)
            if not isinstance(jc, JiraConnection):
                raise ValueError(f"identity_connection {go_quote(id)} is not a jira connection")
            identity = jc
        return ConfluenceConnection(site, identity)


class _Allowed(Exception):
    """Stops a pagination once a grant is found (Go's errAllowed)."""


def _classify(err: BaseException) -> HallpassError:
    out = httpx.classify(err)
    assert out is not None
    return out


@dataclass
class _SpaceGrants:
    """What the permission list says about one operation and about
    administer/space, reduced to what hallpass can resolve."""

    groups: list[str] = field(default_factory=list)  # group ids holding the operation
    admin_groups: list[str] = field(default_factory=list)  # group ids holding administer/space
    unresolved: set[str] = field(default_factory=set)  # principal types hallpass cannot resolve, holding either


@dataclass(frozen=True)
class _SpacePermission:
    principal_type: str
    principal_id: str
    key: str
    target_type: str


def _links_next(page: dict[str, Any]) -> str:
    return jsonx.s(jsonx.o(page, "_links"), "next")


def _decode_space_permission_page(v: Any) -> tuple[list[_SpacePermission], str]:
    page = jsonx.obj(v)
    out = []
    for x in jsonx.arr(page, "results"):
        p = jsonx.obj(x)
        pr, op = jsonx.o(p, "principal"), jsonx.o(p, "operation")
        out.append(_SpacePermission(jsonx.s(pr, "type"), jsonx.s(pr, "id"), jsonx.s(op, "key"), jsonx.s(op, "targetType")))
    return out, _links_next(page)


def _decode_group_page(v: Any) -> tuple[list[tuple[str, str]], str]:
    page = jsonx.obj(v)
    out = []
    for x in jsonx.arr(page, "results"):
        g = jsonx.obj(x)
        out.append((jsonx.s(g, "id"), jsonx.s(g, "name")))
    return out, _links_next(page)


class ConfluenceConnection(Connection):
    """One Confluence Cloud site."""

    def __init__(self, site: Site, identity: JiraConnection | None) -> None:
        self._site = site
        # None when identity_connection is unset.
        self._identity = identity

    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        """Map the caller's email to an accountId through the jira
        connection."""
        if self._identity is None:
            raise errorf(Code.UNSUPPORTED, NO_IDENTITY_TEXT)
        return self._identity.lookup_account_id(ctx, u.email)

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        """Answer one question."""
        act = ACTIONS.get(r.action_name)
        if act is None:
            raise errorf(Code.INVALID_REQUEST, f"unknown action {go_quote(r.action_name)}")
        try:
            res = parse_resource(r.resource)
        except ValueError as e:
            raise errorf(Code.INVALID_REQUEST, str(e)) from None
        if res.kind != act.resource:
            raise errorf(Code.INVALID_REQUEST, f"{act.name} applies to {act.resource.value}:<{act.resource.id_shape()}>, not {r.resource.raw}")
        who = r.identity.display or r.identity.id
        if res.kind == ResKind.SPACE:
            return self._check_space(ctx, r.identity.id, who, act, res.id)
        return self._check_content(ctx, r.identity.id, who, act, res)

    def _check_content(self, ctx: Context, account_id: str, who: str, act: ConfluenceAction, res: ConfluenceResource) -> Decision:
        """Ask Confluence directly."""
        req = {"subject": {"type": "user", "identifier": account_id}, "operation": act.operation}
        path = "/wiki/rest/api/content/" + httpx.path_escape(res.id) + "/permission/check"
        kind = res.kind.value
        try:
            _, v = self._site.post_json(ctx, path, req, True)
            out = jsonx.obj(v)
            has = jsonx.b(out, "hasPermission")
            errs = jsonx.arr(out, "errors")
        except Exception as e:
            st = httpx.status(e)
            if st == 404:
                return unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"{kind} {res.id} does not exist or is not visible to hallpass's account")
            if st == 403:
                raise wrap_error(
                    Code.CREDENTIAL_REJECTED,
                    e,
                    "hallpass's account may not check other users' permissions; it needs Confluence Administrator (HTTP 403)",
                ) from e
            raise _classify(e) from e
        if has:
            return allowed(f"{who} may {act.operation} {kind} {res.id}")
        if errs:
            # UNVERIFIED: the errors list is taken to mean the check could
            # not be evaluated (unknown subject, operation not applicable,
            # ...). If a live site also fills it on an ordinary refusal,
            # those refusals answer unknown instead of deny; never the other
            # way round.
            return unsupported(f"Confluence reported {len(errs)} error(s) instead of a permission answer for {kind} {res.id}; the check could not be evaluated")
        return denied(f"{who} may not {act.operation} {kind} {res.id}")

    def _check_space(self, ctx: Context, account_id: str, who: str, act: ConfluenceAction, key: str) -> Decision:
        """Evaluate a space permission from the space's permission list."""
        space_id, d = self._space_id(ctx, key)
        if d is not None:
            return d

        # UNVERIFIED: the operation keys and targetTypes for export, restrict
        # and administer are taken from the specification, not from a live
        # site.
        # UNVERIFIED: how the v2 list represents anonymous and licensed-user
        # (site-wide) grants; every principal type other than user and group
        # is treated as unresolved, so such a grant never reads as deny.
        g = _SpaceGrants()
        direct = ""

        def page_fn(resp: httpx.Response) -> str:
            nonlocal direct
            results, nxt = _decode_space_permission_page(resp.json())
            for p in results:
                wanted = p.key == act.operation and p.target_type == act.target
                admin = p.key == ADMIN_OPERATION and p.target_type == ADMIN_TARGET
                if not wanted and not admin:
                    continue
                if p.principal_type == "user":
                    if p.principal_id != account_id:
                        continue
                    direct = "directly" if wanted else "as a space administrator"
                    raise _Allowed()
                if p.principal_type == "group":
                    if wanted:
                        g.groups.append(p.principal_id)
                    else:
                        g.admin_groups.append(p.principal_id)
                else:
                    g.unresolved.add(p.principal_type)
            return nxt

        what = f"{act.name} ({act.operation}/{act.target}) in space {key}"
        try:
            self._paginate(ctx, "/wiki/api/v2/spaces/" + httpx.path_escape(space_id) + "/permissions", {"limit": "250"}, page_fn)
        except _Allowed:
            return allowed(f"{who} holds {what} {direct}")
        except Exception as e:
            raise self._classify(e) from e

        if g.groups or g.admin_groups:
            try:
                member, group_id, group_name = self._member_of_any(ctx, account_id, [*g.groups, *g.admin_groups])
            except Exception as e:
                raise self._classify(e) from e
            if member:
                if group_id in g.admin_groups:
                    return allowed(f"{who} holds {what} as a space administrator through group {group_name}")
                return allowed(f"{who} holds {what} through group {group_name}")
        if g.unresolved:
            types = "/".join(sorted(g.unresolved))
            return unsupported(
                f"{types}-based space permissions not evaluated: {what} or {ADMIN_OPERATION}/{ADMIN_TARGET} "
                "is granted to a principal type hallpass does not model"
            )
        return denied(f"no space permission grants {what} or {ADMIN_OPERATION}/{ADMIN_TARGET} to {who} or their groups")

    def _space_id(self, ctx: Context, key: str) -> tuple[str, Decision | None]:
        """A space key resolved to its id with GET /wiki/api/v2/spaces?keys=.
        The key must match exactly: a case variant or several hits leave
        hallpass unsure which space is meant, which is unknown, not deny."""
        try:
            _, v = self._site.get_json(ctx, "/wiki/api/v2/spaces", {"keys": key})
            spaces = []
            for x in jsonx.arr(jsonx.obj(v), "results"):
                sp = jsonx.obj(x)
                spaces.append((jsonx.s(sp, "id"), jsonx.s(sp, "key")))
        except Exception as e:
            if httpx.status(e) == 404:
                return "", unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"space {key} does not exist or is not visible to hallpass's account")
            raise self._classify(e) from e
        exact = [sid for sid, skey in spaces if skey == key]
        others = [skey for _, skey in spaces if skey != key]
        if len(exact) == 1:
            return exact[0], None
        if len(exact) > 1:
            return "", unsupported(f"space key {key} matches {len(exact)} spaces; hallpass cannot tell which one is meant")
        if others:
            return "", unsupported(f"space key {key} has no exact match; Confluence returned {', '.join(others)}, use the exact key")
        return "", unknown_decision(Code.RESOURCE_NOT_VISIBLE, f"space {key} does not exist or is not visible to hallpass's account")

    def _member_of_any(self, ctx: Context, account_id: str, group_ids: list[str]) -> tuple[bool, str, str]:
        """Whether the account belongs to one of the groups, reading
        GET /wiki/rest/api/user/memberof page by page, and which group
        matched (id and name)."""
        want = set(group_ids)
        found: list[str] = []

        def page_fn(resp: httpx.Response) -> str:
            groups, nxt = _decode_group_page(resp.json())
            for gid, gname in groups:
                if gid in want:
                    found[:] = [gid, gname or gid]
                    raise _Allowed()
            return nxt

        try:
            self._paginate(ctx, "/wiki/rest/api/user/memberof", {"accountId": account_id, "limit": "200"}, page_fn)
        except _Allowed:
            return True, found[0], found[1]
        return False, "", ""

    def _paginate(self, ctx: Context, path: str, q: dict[str, str], page: Callable[[httpx.Response], str]) -> None:
        """Follow _links.next until the page func returns "" or raises."""
        first = self._site.resolve(ctx, path)
        base = self._site.base(ctx)

        def next_req(resp: httpx.Response) -> httpx.Request | None:
            nxt = page(resp)
            if nxt == "":
                return None
            np = next_path(nxt)
            if np == "":
                return None
            return httpx.Request(method="GET", path=base + np)

        self._site.client().paginate(ctx, httpx.Request(method="GET", path=first, query=q), next_req)

    def _classify(self, err: BaseException) -> HallpassError:
        if httpx.status(err) == 403:
            return wrap_error(Code.CREDENTIAL_REJECTED, err, "hallpass's account may not read space permissions or group memberships (HTTP 403)")
        return _classify(err)

    def probe(self, ctx: Context) -> ProbeResult:
        """Verify the credential and report the identity setup."""
        try:
            _, v = self._site.get_json(ctx, "/wiki/rest/api/user/current")
            me = jsonx.obj(v)
            account_id, display_name = jsonx.s(me, "accountId"), jsonx.s(me, "displayName")
        except Exception as e:
            if httpx.status(e) == 403:
                raise wrap_error(Code.CREDENTIAL_REJECTED, e, "the credential is valid but may not read its own profile (HTTP 403)") from e
            raise _classify(e) from e
        summary = f"authenticated as {display_name} ({account_id}) with auth_mode {self._site.mode}"
        warnings = []
        if self._identity is None:
            warnings.append("identity_connection is not set; every check will answer unknown because " + NO_IDENTITY_TEXT)
        warnings.append(
            "checking other users' permissions needs Confluence Administrator on hallpass's account; a plain user gets HTTP 403 (credential_rejected)"
        )
        return ProbeResult(summary=summary, warnings=tuple(warnings))


_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _request_uri(raw: str) -> str | None:
    """Go's url.Parse(raw).RequestURI() for an absolute http(s) URL, or None
    when url.Parse fails."""
    rest, has_frag, frag = raw.partition("#")
    if has_frag and _BAD_ESCAPE.search(frag):
        return None
    if rest.endswith("?") and rest.count("?") == 1:
        head, query, force = rest[:-1], "", True
    else:
        head, _, query = rest.partition("?")
        force = False
    try:
        go_url_parse(head)
    except ValueError:
        return None
    # head is scheme://authority[/path]
    after = head.split("://", 1)[1]
    slash = after.find("/")
    path = after[slash:] if slash >= 0 else ""
    out = path or "/"
    if force or query != "":
        out += "?" + query
    return out


def next_path(nxt: str) -> str:
    """A _links.next value normalised to a site-relative /wiki/... path.

    UNVERIFIED: v1 links are relative to {url}/wiki (/rest/api/...), v2
    links to the site (/wiki/api/v2/...), and either may be absolute; all
    three shapes are handled.
    """
    nxt = go_trim_space(nxt)
    if nxt == "":
        return ""
    if nxt.startswith("http://") or nxt.startswith("https://"):
        u = _request_uri(nxt)
        if u is None:
            return ""
        nxt = u
    i = nxt.find("/wiki/")
    if i >= 0:
        return nxt[i:]
    if not nxt.startswith("/"):
        nxt = "/" + nxt
    return "/wiki" + nxt
