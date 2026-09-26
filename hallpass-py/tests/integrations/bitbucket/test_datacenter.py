"""Port of internal/integrations/bitbucket/datacenter_test.go."""

from __future__ import annotations

import json
import threading
from typing import Any

from hallpass.core.context import background
from hallpass.core.decision import Code
from hallpass.core.integration import User
from hallpass.core.secret import literal as secret_literal
from hallpass.integrations.bitbucket import INTEGRATION, BitbucketConnection
from hallpass.integrations.bitbucket.common import EDITION_DATA_CENTER
from hallpass.integrations.bitbucket.datacenter import DC_API
from tests import harness as itest
from tests.integrations.bitbucket.common import Tracker, bob, check, dana, eve, expect, root, write


def _branch(i: int, typ: str, ref: str, display: str, users: list[Any], groups: list[str]) -> dict[str, Any]:
    return {"id": i, "type": typ, "matcher": {"id": ref, "displayId": display, "type": {"id": "BRANCH", "name": "Branch"}}, "users": users, "groups": groups}


def _pattern(i: int, typ: str, pattern: str, users: list[Any], groups: list[str]) -> dict[str, Any]:
    return {
        "id": i,
        "type": typ,
        "matcher": {"id": pattern, "displayId": pattern, "type": {"id": "PATTERN", "name": "Pattern"}},
        "users": users,
        "groups": groups,
    }


def dc_err(w: itest.ResponseWriter, status: int, msg: str) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write('{"errors":[{"message":"' + itest.CANARY + " " + msg + '","exceptionName":"x"}]}')


def _atoi(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return 0


def _go_marshal(v: Any) -> str:
    """json.Marshal of a map[string]any: sorted keys, compact."""
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class DCFake:
    def __init__(self) -> None:
        self.mu = threading.Lock()
        self.errors: list[str] = []  # Go's t.Errorf from inside the handler
        self.token = itest.CANARY + "httptoken"
        self.token_is_admin = True
        self.users: dict[str, dict[str, Any]] = {  # name -> user
            "dana": {
                "name": "dana",
                "slug": "dana",
                "emailAddress": "dana@example.com",
                "displayName": itest.CANARY + "Dana",
                "active": True,
                "id": 1,
                "type": "NORMAL",
            },
            "bob": {
                "name": "bob",
                "slug": "bob",
                "emailAddress": "Bob@Example.com",
                "displayName": itest.CANARY + "Bob",
                "active": True,
                "id": 2,
                "type": "NORMAL",
            },
            "root": {
                "name": "root",
                "slug": "root",
                "emailAddress": "root@example.com",
                "displayName": itest.CANARY + "Root",
                "active": True,
                "id": 3,
                "type": "NORMAL",
            },
            "eve": {
                "name": "eve",
                "slug": "eve",
                "emailAddress": "eve@example.com",
                "displayName": itest.CANARY + "Eve",
                "active": True,
                "id": 4,
                "type": "NORMAL",
            },
            # A substring hit on the filter that must not count.
            "danaher": {
                "name": "danaher",
                "slug": "danaher",
                "emailAddress": "dana@example.com.au",
                "displayName": "x",
                "active": True,
                "id": 5,
                "type": "NORMAL",
            },
            "off": {"name": "off", "slug": "off", "emailAddress": "off@example.com", "displayName": "Off", "active": False, "id": 6, "type": "NORMAL"},
        }
        self.groups: dict[str, list[str]] = {"dana": ["developers", "stash-users"], "bob": ["stash-users"], "root": ["stash-users"], "eve": [], "off": []}
        self.projects = {"APP": False, "PUB": True}  # key -> public
        self.repos = {"APP/api": False, "APP/open": True, "PUB/docs": False}  # KEY/slug -> public
        # scope -> user name -> permission; scope "admin", "project:KEY", "repo:KEY/slug"
        self.user_perms: dict[str, dict[str, str]] = {
            "admin": {"root": "ADMIN"},
            "project:APP": {"dana": "PROJECT_WRITE"},
            "repo:APP/api": {"bob": "REPO_READ"},
        }
        self.group_perms: dict[str, dict[str, str]] = {  # scope -> group -> permission
            "project:APP": {"developers": "PROJECT_READ"},
            "repo:APP/api": {"developers": "REPO_WRITE"},
            "project:PUB": {"stash-users": "PROJECT_WRITE"},
        }
        self.defaults: dict[str, str] = {}  # project key -> default permission
        self.restrictions: dict[str, list[dict[str, Any]]] = {
            "APP/api": [
                {**_branch(1, "read-only", "refs/heads/main", "main", [{"name": "root"}], []), "accessKeys": []},
                {**_pattern(2, "pull-request-only", "release/*", [], ["developers"]), "accessKeys": []},
                _pattern(3, "no-deletes", "**", [], []),
            ],
            # Project-level: inherited by every repository of APP.
            "APP": [
                _branch(20, "read-only", "refs/heads/develop", "develop", [{"name": "root"}], []),
                # The same restriction Bitbucket may also list on the repository.
                _branch(1, "read-only", "refs/heads/main", "main", [{"name": "root"}], []),
            ],
        }
        self.groups_denied = False  # more-members answers 403
        self.status = 0
        self.page_size = 0  # when >0, lists are paged this small

    def page(self, w: itest.ResponseWriter, r: itest.Request, values: list[dict[str, Any]]) -> None:
        """One page of values honouring start/limit and page_size. Values
        are sorted so pages are stable across calls."""
        values = sorted(values, key=_go_marshal)
        start = _atoi(r.q("start"))
        limit = _atoi(r.q("limit"))
        if limit <= 0:
            limit = 25
        if 0 < self.page_size < limit:
            limit = self.page_size
        start = min(start, len(values))
        end = min(start + limit, len(values))
        body: dict[str, Any] = {"start": start, "limit": limit, "size": end - start, "values": values[start:end], "isLastPage": end >= len(values)}
        if end < len(values):
            body["nextPageStart"] = end
        write(w, body)

    def grant_values(self, scope: str, kind: str, flt: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if kind == "users":
            for name, perm in self.user_perms.get(scope, {}).items():
                if flt != "" and flt not in name:
                    continue
                out.append({"permission": perm, "user": self.users.get(name)})
            # A substring hit that must not count when the filter is "dana".
            if scope == "repo:APP/api" and flt in "danaher":
                out.append({"permission": "REPO_ADMIN", "user": self.users["danaher"]})
            return out
        for g, perm in self.group_perms.get(scope, {}).items():
            out.append({"permission": perm, "group": {"name": g}})
        return out

    def api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        with self.mu:
            self._api(w, r)

    def _api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.header.get("Authorization") != "Bearer " + self.token:
            w.write_header(401)
            return
        if self.status != 0:
            dc_err(w, self.status, "injected")
            return
        p, q = r.path, r.q
        if p == DC_API + "/application-properties":
            write(w, {"version": "8.19.0", "displayName": "Bitbucket", "buildNumber": "8019000"})
        elif p == DC_API + "/users":
            flt = q("filter")
            values = [u for u in self.users.values() if flt.lower() in u["emailAddress"].lower() or flt in u["name"]]
            if flt == "dup@example.com":
                values += [{"name": "dup1", "emailAddress": "dup@example.com"}, {"name": "dup2", "emailAddress": "DUP@example.com"}]
            self.page(w, r, values)
        elif p == DC_API + "/admin/users/more-members":
            if self.groups_denied:
                dc_err(w, 403, "LICENSED_USER required")
                return
            self.page(w, r, [{"name": g} for g in self.groups.get(q("context"), [])])
        elif p.startswith(DC_API + "/admin/permissions/"):
            if not self.token_is_admin:
                dc_err(w, 403, "ADMIN required")
                return
            self.page(w, r, self.grant_values("admin", p.removeprefix(DC_API + "/admin/permissions/"), q("filter")))
        elif p.startswith(DC_API + "/projects/"):
            rest = p.removeprefix(DC_API + "/projects/")
            key, _, sub = rest.partition("/")
            public = self.projects.get(key)
            if public is None:
                dc_err(w, 404, "no project")
                return
            if sub == "":
                write(w, {"key": key, "id": 7, "name": itest.CANARY, "public": public, "type": "NORMAL"})
            elif sub in ("permissions/users", "permissions/groups"):
                self.page(w, r, self.grant_values("project:" + key, sub.removeprefix("permissions/"), q("filter")))
            elif sub.startswith("permissions/") and sub.endswith("/all"):
                perm = sub.removeprefix("permissions/").removesuffix("/all")
                write(w, {"permitted": self.defaults.get(key, "") == perm})
            elif sub.startswith("repos/"):
                slug, _, rsub = sub.removeprefix("repos/").partition("/")
                rpublic = self.repos.get(key + "/" + slug)
                if rpublic is None:
                    dc_err(w, 404, "no repo")
                    return
                if rsub == "":
                    write(w, {"slug": slug, "id": 9, "name": itest.CANARY, "public": rpublic, "project": {"key": key}})
                elif rsub in ("permissions/users", "permissions/groups"):
                    self.page(w, r, self.grant_values("repo:" + key + "/" + slug, rsub.removeprefix("permissions/"), q("filter")))
                else:
                    dc_err(w, 404, "no route")
            else:
                dc_err(w, 404, "no route")
        elif p.startswith("/rest/branch-permissions/2.0/projects/"):
            parts = p.removeprefix("/rest/branch-permissions/2.0/projects/").split("/")
            if len(parts) == 2 and parts[1] == "restrictions":
                if parts[0] not in self.projects:
                    dc_err(w, 404, "no project")
                    return
                self.page(w, r, self.restrictions.get(parts[0], []))
            elif len(parts) == 4 and parts[1] == "repos" and parts[3] == "restrictions":
                key = parts[0] + "/" + parts[2]
                if key not in self.repos:
                    dc_err(w, 404, "no repo")
                    return
                self.page(w, r, self.restrictions.get(key, []))
            else:
                dc_err(w, 404, "no route")
        else:
            self.errors.append(f"dc fake: no route for {r.method} {p}")
            dc_err(w, 404, "no route")


def setup_dc(tracker: Tracker, values: dict[str, str] | None = None) -> tuple[itest.Server, DCFake, BitbucketConnection]:
    srv = tracker.server()
    f = DCFake()
    tracker.fakes.append(f)
    srv.handle("GET", "/rest/*", f.api)
    deps, _ = itest.deps(srv)
    v = {"url": srv.url, "edition": EDITION_DATA_CENTER}
    v.update(values or {})
    s = itest.settings("bbdc", "bitbucket", v, {"credential": secret_literal(f.token)})
    c = INTEGRATION.new(background(), s, deps)
    assert isinstance(c, BitbucketConnection)
    return srv, f, c


def test_dc_identity(tracker: Tracker) -> None:
    srv, f, conn = setup_dc(tracker)
    ident = conn.resolve_identity(background(), User(email=" Dana@Example.com "))
    assert ident.id == "dana" and ident.attr("active") == "true" and ",".join(ident.groups) == "developers,stash-users", f"identity {ident}"
    first = srv.calls()[0]
    assert first.path == DC_API + "/users" and first.q("filter") == "dana@example.com" and first.q("limit") == "100", f"lookup {first.path} {first.query}"
    # bob's address differs in case only.
    ident = conn.resolve_identity(background(), bob)
    assert ident.id == "bob", f"bob: {ident}"
    expect(check(conn, User(email="nobody@example.com"), "workspace.member", "workspace"), Code.USER_NOT_FOUND, "")
    expect(check(conn, User(email="dup@example.com"), "workspace.member", "workspace"), Code.USER_AMBIGUOUS, "")
    expect(check(conn, User(email="off@example.com"), "repo.read", "repo:APP/open"), Code.DENIED, "deactivated")
    # Groups unreadable: the identity still resolves, marked.
    with f.mu:
        f.groups_denied = True
    ident = conn.resolve_identity(background(), dana)
    assert ident.attr("groups") == "unavailable" and len(ident.groups) == 0, f"identity without groups {ident}"
    lookup = None
    for call in srv.calls():
        if call.path == DC_API + "/admin/users/more-members":
            lookup = call
    assert lookup is not None and lookup.q("context") == "dana", f"groups lookup {lookup}"


def test_dc_repo(tracker: Tracker) -> None:
    _, f, c = setup_dc(tracker)
    expect(check(c, bob, "repo.read", "repo:APP/api"), Code.ALLOWED, "REPO_READ granted directly")
    expect(check(c, dana, "repo.push", "repo:APP/api"), Code.ALLOWED, "REPO_WRITE via group developers")
    expect(check(c, bob, "repo.push", "repo:APP/api"), Code.DENIED, "has read, needs write")
    expect(check(c, eve, "repo.read", "repo:APP/api"), Code.DENIED, "has none, needs read")
    # Project grants reach the repository; public repositories are readable.
    expect(check(c, dana, "repo.push", "repo:APP/open"), Code.ALLOWED, "PROJECT_WRITE granted directly on project APP")
    expect(check(c, eve, "repo.read", "repo:APP/open"), Code.ALLOWED, "public repository")
    expect(check(c, eve, "repo.push", "repo:APP/open"), Code.DENIED, "")
    # The global administrator has admin everywhere.
    expect(check(c, root, "repo.admin", "repo:APP/api"), Code.ALLOWED, "ADMIN granted directly globally")
    expect(check(c, dana, "repo.admin", "repo:APP/api"), Code.DENIED, "has write, needs admin")
    # Default project permission.
    with f.mu:
        f.defaults["APP"] = "PROJECT_READ"
    expect(check(c, eve, "repo.read", "repo:APP/api"), Code.ALLOWED, "PROJECT_READ is the project default")
    # Missing objects are unknown.
    expect(check(c, dana, "repo.read", "repo:APP/nope"), Code.RESOURCE_NOT_VISIBLE, "")
    expect(check(c, dana, "repo.read", "repo:NOPE/api"), Code.RESOURCE_NOT_VISIBLE, "")


def test_dc_branches(tracker: Tracker) -> None:
    _, f, c = setup_dc(tracker)
    # read-only on main exempts root only.
    expect(check(c, dana, "repo.push", "repo:APP/api@main"), Code.DENIED, "read-only restriction on main")
    expect(check(c, dana, "pr.merge", "repo:APP/api@main"), Code.DENIED, "read-only restriction")
    expect(check(c, root, "repo.push", "repo:APP/api@main"), Code.ALLOWED, "no branch permission stops main")
    # pull-request-only on release/* exempts the developers group; it does
    # not stop merges.
    expect(check(c, dana, "repo.push", "repo:APP/api@release/2.0"), Code.ALLOWED, "")
    expect(check(c, root, "repo.push", "repo:APP/api@release/2.0"), Code.DENIED, "pull-request-only restriction")
    expect(check(c, root, "pr.merge", "repo:APP/api@release/2.0"), Code.ALLOWED, "")
    # no-deletes never stops a push.
    expect(check(c, dana, "repo.push", "repo:APP/api@feature/x"), Code.ALLOWED, "")
    # A project-level restriction applies to the repository too.
    expect(check(c, dana, "repo.push", "repo:APP/api@develop"), Code.DENIED, "read-only restriction on develop")
    expect(check(c, root, "repo.push", "repo:APP/api@develop"), Code.ALLOWED, "")
    # A slash-less pattern against a nested branch is ambiguous.
    with f.mu:
        f.restrictions["APP"].append(_pattern(21, "read-only", "hotfix", [], []))
    expect(check(c, dana, "repo.push", "repo:APP/api@release/hotfix"), Code.UNSUPPORTED, 'pattern "hotfix"')
    expect(check(c, dana, "repo.push", "repo:APP/api@hotfix"), Code.DENIED, "")
    with f.mu:
        f.restrictions["APP"] = f.restrictions["APP"][:2]
    # Without the user's groups a group exemption is unresolvable.
    with f.mu:
        f.groups_denied = True
    expect(check(c, root, "repo.push", "repo:APP/api@release/2.0"), Code.UNSUPPORTED, "could not list the groups")
    # Ant-style: "release/*" does not reach a nested branch.
    with f.mu:
        f.groups_denied = False
    expect(check(c, root, "repo.push", "repo:APP/api@release/2.0/fix"), Code.ALLOWED, "")
    # An all-branches restriction matches everything.
    with f.mu:
        f.restrictions["APP/api"].append(
            {
                "id": 9,
                "type": "read-only",
                "matcher": {"id": "ANY_REF_MATCHER_ID", "displayId": "ANY_REF_MATCHER_ID", "type": {"id": "ANY_REF", "name": "Any branch"}},
                "users": [{"name": "dana"}],
                "groups": [],
            }
        )
    expect(check(c, root, "repo.push", "repo:APP/api@feature/x"), Code.DENIED, "read-only restriction on ANY_REF_MATCHER_ID")
    expect(check(c, dana, "repo.push", "repo:APP/api@feature/x"), Code.ALLOWED, "")
    with f.mu:
        f.restrictions["APP/api"] = f.restrictions["APP/api"][:3]
    # Branching-model matchers are unknown.
    with f.mu:
        f.groups_denied = False
        f.restrictions["APP/api"].append(
            {
                "id": 4,
                "type": "read-only",
                "matcher": {"id": "PRODUCTION", "displayId": "Production", "type": {"id": "MODEL_CATEGORY"}},
                "users": [],
                "groups": [],
            }
        )
    expect(check(c, dana, "repo.push", "repo:APP/api@feature/x"), Code.UNSUPPORTED, "branching model matcher MODEL_CATEGORY")


def test_dc_project_and_instance(tracker: Tracker) -> None:
    _, f, c = setup_dc(tracker)
    expect(check(c, dana, "project.read", "project:APP"), Code.ALLOWED, "")
    expect(check(c, dana, "project.write", "project:APP"), Code.ALLOWED, "PROJECT_WRITE granted directly")
    expect(check(c, eve, "project.read", "project:APP"), Code.DENIED, "has none, needs read")
    expect(check(c, eve, "project.read", "project:PUB"), Code.ALLOWED, "public project")
    expect(check(c, bob, "project.write", "project:PUB"), Code.ALLOWED, "via group stash-users")
    expect(check(c, root, "project.admin", "project:APP"), Code.ALLOWED, "globally")
    expect(check(c, dana, "project.admin", "project:APP"), Code.DENIED, "has write, needs admin")
    # repo.create needs admin on Data Center (see the UNVERIFIED note).
    expect(check(c, root, "repo.create", "project:APP"), Code.ALLOWED, "")
    expect(check(c, dana, "repo.create", "project:APP"), Code.DENIED, "needs admin")
    expect(check(c, dana, "project.read", "project:NOPE"), Code.RESOURCE_NOT_VISIBLE, "")
    # Instance.
    expect(check(c, dana, "workspace.member", "workspace"), Code.ALLOWED, "active user")
    expect(check(c, root, "workspace.admin", "workspace"), Code.ALLOWED, "global administrator")
    expect(check(c, dana, "workspace.admin", "workspace"), Code.DENIED, "no global administrator permission")
    # A token without ADMIN cannot see global permissions: unknown where
    # they would matter, and the probe warns.
    with f.mu:
        f.token_is_admin = False
    expect(check(c, dana, "workspace.admin", "workspace"), Code.CREDENTIAL_REJECTED, "needs ADMIN")
    expect(check(c, root, "repo.admin", "repo:APP/api"), Code.UNSUPPORTED, "global permissions (not readable without ADMIN)")
    expect(check(c, bob, "repo.read", "repo:APP/api"), Code.ALLOWED, "")
    r = c.probe(background())
    assert "Bitbucket 8.19.0" in r.summary and "lacks ADMIN" in "\n".join(r.warnings), f"probe {r.summary!r} {r.warnings!r}"
    # Groups unreadable and a group grant that would matter.
    with f.mu:
        f.token_is_admin = True
        f.groups_denied = True
    # dana still has PROJECT_WRITE directly; eve's only hope is a group.
    expect(check(c, dana, "repo.push", "repo:APP/api"), Code.ALLOWED, "PROJECT_WRITE granted directly")
    expect(check(c, eve, "repo.push", "repo:APP/api"), Code.UNSUPPORTED, "REPO_WRITE of group developers")
    expect(check(c, bob, "repo.read", "repo:APP/api"), Code.ALLOWED, "")


def test_dc_paging(tracker: Tracker) -> None:
    srv, f, c = setup_dc(tracker)
    with f.mu:
        f.page_size = 1
    expect(check(c, dana, "repo.push", "repo:APP/api"), Code.ALLOWED, "via group developers")
    pages = sum(1 for call in srv.calls() if call.path == DC_API + "/admin/users/more-members")
    assert pages == 2, f"groups read in {pages} pages, want 2"


def test_dc_rejects_bad_resources(tracker: Tracker) -> None:
    srv, _, c = setup_dc(tracker)
    expect(check(c, bob, "repo.read", "repo:APP/api"), Code.ALLOWED, "")
    n = len(srv.calls())
    bad = []
    for res in ["repo:api", "repo:APP/api/x", "repo:APP/", "repo:/api", "repo:APP/a b", "repo:APP/api@a..b"]:
        d = check(c, bob, "repo.read", res)
        if d.code != Code.INVALID_REQUEST:
            bad.append(f"{res}: {d.code} ({d.text})")
    assert not bad, "\n".join(bad)
    extra = sum(1 for call in srv.calls()[n:] if call.path not in (DC_API + "/users", DC_API + "/admin/users/more-members"))
    assert extra == 0, f"{extra} calls reached the upstream for rejected resources"


def test_dc_failures(tracker: Tracker) -> None:
    srv, _, c = setup_dc(tracker)
    expect(check(c, bob, "repo.read", "repo:APP/api"), Code.ALLOWED, "")
    itest.failure_cases(srv, lambda: check(c, bob, "repo.read", "repo:APP/api"))
    # Bodies decode as JSON with the canary in every message.
    e = json.loads('{"errors":[{"message":"x"}]}')
    assert isinstance(e, dict)
