"""Port of internal/integrations/linear/linear_test.go."""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from hallpass.core.context import background
from hallpass.core.decision import Code, Decision, HallpassError
from hallpass.core.errors import as_error
from hallpass.core.integration import Connection, User
from hallpass.core.secret import literal as secret_literal
from hallpass.integrations.linear import INTEGRATION
from hallpass.integrations.linear.linear import AUTH_OAUTH
from tests import harness as itest
from tests.harness.spec import SpecOptions, spec_from_env

U_OWNER = "00000000-0000-4000-8000-000000000001"
U_ADMIN = "00000000-0000-4000-8000-000000000002"
U_DANA = "00000000-0000-4000-8000-000000000003"  # member of ENG and SEC
U_BOB = "00000000-0000-4000-8000-000000000004"  # member of nothing
U_GUS = "00000000-0000-4000-8000-000000000005"  # guest in SEC
U_LEAD = "00000000-0000-4000-8000-000000000006"  # owner of team ENG
U_APP = "00000000-0000-4000-8000-000000000007"
U_SUSP = "00000000-0000-4000-8000-000000000008"
U_PEND = "00000000-0000-4000-8000-000000000009"
U_BOT = "00000000-0000-4000-8000-000000000010"

T_ENG = "10000000-0000-4000-8000-000000000001"  # public
T_SEC = "10000000-0000-4000-8000-000000000002"  # private
T_RST = "10000000-0000-4000-8000-000000000003"  # restricted
T_OLD = "10000000-0000-4000-8000-000000000004"  # archived

P_ENG = "20000000-0000-4000-8000-000000000001"
P_SEC = "20000000-0000-4000-8000-000000000002"
P_BOTH = "20000000-0000-4000-8000-000000000003"
P_NONE = "20000000-0000-4000-8000-000000000004"

owner = User(email="owner@example.com")
admin = User(email="admin@example.com")
dana = User(email="dana@example.com")
bob = User(email="bob@example.com")
gus = User(email="gus@example.com")
lead = User(email="lead@example.com")
app = User(email="app@example.com")


@dataclass
class FakeUser:
    id: str
    email: str
    active: bool = False
    admin: bool = False
    owner: bool = False
    guest: bool = False
    app: bool = False
    disable_reason: str | None = None
    teams: dict[str, bool] = field(default_factory=dict)  # team id -> owner


@dataclass
class FakeTeam:
    id: str
    key: str
    visibility: str
    archived: bool


@dataclass
class FakeIssue:
    id: str
    identifier: str
    team: str
    trashed: bool


@dataclass
class FakeProject:
    id: str
    slug: str
    teams: list[str]
    trashed: bool


def write(w: itest.ResponseWriter, status: int, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write(json.dumps(v) + "\n")


def gql_err(w: itest.ResponseWriter, status: int, typ: str, msg: str) -> None:
    write(w, status, {"errors": [{"message": msg, "extensions": {"type": typ, "userError": True, "userPresentableMessage": itest.CANARY}}]})


class Fake:
    def __init__(self) -> None:
        self.mu = threading.Lock()
        self.errors: list[str] = []  # Go: f.t.Errorf from the handler
        self.token = itest.CANARY + "key"
        self.page_size = 100
        self.not_found = "Entity not found: Issue - Could not find referenced Issue."
        self.status = 0
        self.gql_error = ""  # extensions.type to answer every query with
        self.ghost = ""  # a user id whose memberships answer not found
        self.users = [
            FakeUser(U_BOT, "bot@example.com", active=True, admin=True),
            FakeUser(U_OWNER, "owner@example.com", active=True, admin=True, owner=True, teams={T_ENG: True}),
            FakeUser(U_ADMIN, "admin@example.com", active=True, admin=True),
            FakeUser(U_DANA, "dana@example.com", active=True, teams={T_ENG: False, T_SEC: False}),
            FakeUser(U_BOB, "bob@example.com", active=True),
            FakeUser(U_GUS, "gus@example.com", active=True, guest=True, teams={T_SEC: False}),
            FakeUser(U_LEAD, "lead@example.com", active=True, teams={T_ENG: True}),
            FakeUser(U_APP, "app@example.com", active=True, app=True),
            FakeUser(U_SUSP, "susp@example.com", active=False, disable_reason="admin suspension"),
            FakeUser(U_PEND, "pend@example.com", active=False, disable_reason="pending invite"),
        ]
        self.teams = {
            T_ENG: FakeTeam(T_ENG, "ENG", "public", False),
            T_SEC: FakeTeam(T_SEC, "SEC", "private", False),
            T_RST: FakeTeam(T_RST, "RST", "restricted", False),
            T_OLD: FakeTeam(T_OLD, "OLD", "public", True),
        }
        self.issues = {
            "ENG-1": FakeIssue("30000000-0000-4000-8000-000000000001", "ENG-1", T_ENG, False),
            "ENG-2": FakeIssue("30000000-0000-4000-8000-000000000002", "ENG-2", T_ENG, True),
            "SEC-1": FakeIssue("30000000-0000-4000-8000-000000000003", "SEC-1", T_SEC, False),
            "RST-1": FakeIssue("30000000-0000-4000-8000-000000000004", "RST-1", T_RST, False),
        }
        self.projects = {
            P_ENG: FakeProject(P_ENG, "eng-proj", [T_ENG], False),
            P_SEC: FakeProject(P_SEC, "sec-proj", [T_SEC], False),
            P_BOTH: FakeProject(P_BOTH, "both-proj", [T_SEC, T_ENG], False),
            P_NONE: FakeProject(P_NONE, "none-proj", [], False),
        }

    def user_json(self, u: FakeUser) -> dict[str, Any]:
        return {
            "id": u.id,
            "email": u.email,
            "name": itest.CANARY + " name",
            "active": u.active,
            "admin": u.admin,
            "owner": u.owner,
            "guest": u.guest,
            "app": u.app,
            "disableReason": u.disable_reason,
        }

    def team_json(self, id: str) -> dict[str, Any]:
        t = self.teams[id]
        archived = "2026-01-01T00:00:00.000Z" if t.archived else None
        return {"id": t.id, "key": t.key, "name": itest.CANARY + " team", "visibility": t.visibility, "archivedAt": archived}

    def api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        with self.mu:
            self._api(w, r)

    def _api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        h = r.header.get("Authorization")
        if h != self.token and h.lower() != ("Bearer " + self.token).lower():
            gql_err(w, 401, "authentication error", itest.CANARY)
            return
        if self.status != 0:
            write(w, self.status, {"errors": [{"message": itest.CANARY}]})
            return
        if self.gql_error != "":
            gql_err(w, 400, self.gql_error, itest.CANARY)
            return
        try:
            body = r.json()
        except ValueError as e:
            self.errors.append(f"fake: bad body: {e}")
            return
        q = body.get("query") or ""
        v = body.get("variables") or {}
        data: dict[str, Any] = {}
        if "users(filter" in q:
            email = v.get("email") if isinstance(v.get("email"), str) else ""
            nodes = [self.user_json(u) for u in self.users if u.email.lower() == email.lower()]
            if email == "dup@example.com":
                nodes += [
                    self.user_json(FakeUser("00000000-0000-4000-8000-0000000000aa", "dup@example.com", active=True)),
                    self.user_json(FakeUser("00000000-0000-4000-8000-0000000000ab", "Dup@example.com", active=True)),
                ]
            data["users"] = {"nodes": nodes}
        elif "teamMemberships(" in q:
            id = v.get("id") if isinstance(v.get("id"), str) else ""
            u = None
            for x in self.users:
                if x.id == id:
                    u = x
            if u is None or u.id == self.ghost:
                gql_err(w, 200, "invalid input", self.not_found.replace("Issue", "User"))
                return
            all_ = [{"owner": u.teams[tid], "team": {"id": tid, "key": self.teams[tid].key}} for tid in sorted(u.teams)]
            start = 0
            after = v.get("after") if isinstance(v.get("after"), str) else ""
            if after != "":
                m = re.match(r"cursor-([+-]?[0-9]+)", after)
                if m:
                    start = int(m.group(1))
            end = min(start + self.page_size, len(all_))
            start = min(start, len(all_))
            nodes = all_[start:end]
            cursor = f"cursor-{end}" if end < len(all_) else None
            data["user"] = {"teamMemberships": {"nodes": nodes, "pageInfo": {"hasNextPage": end < len(all_), "endCursor": cursor}}}
        elif "teams(filter" in q:
            flt = v.get("filter") if isinstance(v.get("filter"), dict) else {}
            nodes = []
            for id in sorted(self.teams):
                t = self.teams[id]
                key = flt.get("key")
                if isinstance(key, dict) and key.get("eq") == t.key:
                    nodes.append(self.team_json(id))
                idf = flt.get("id")
                if isinstance(idf, dict) and idf.get("eq") == t.id:
                    nodes.append(self.team_json(id))
            data["teams"] = {"nodes": nodes}
        elif "issue(id" in q:
            id = v.get("id") if isinstance(v.get("id"), str) else ""
            found = None
            for i in self.issues.values():
                if i.identifier == id or i.id == id:
                    found = i
            if found is None:
                gql_err(w, 200, "invalid input", self.not_found)
                return
            data["issue"] = {"id": found.id, "identifier": found.identifier, "trashed": found.trashed, "archivedAt": None, "team": self.team_json(found.team)}
        elif "project(id" in q:
            id = v.get("id") if isinstance(v.get("id"), str) else ""
            fp = None
            for p in self.projects.values():
                if p.id == id or p.slug == id:
                    fp = p
            if fp is None:
                gql_err(w, 200, "invalid input", self.not_found.replace("Issue", "Project"))
                return
            teams = [self.team_json(tid) for tid in fp.teams]
            data["project"] = {"id": fp.id, "name": itest.CANARY, "slugId": fp.slug, "trashed": fp.trashed, "archivedAt": None, "teams": {"nodes": teams}}
        elif "viewer {" in q:
            data["viewer"] = self.user_json(self.users[0])
            data["organization"] = {"id": "40000000-0000-4000-8000-000000000001", "name": itest.CANARY, "urlKey": "acme"}
        else:
            self.errors.append(f"fake: no handler for query {q}")
            gql_err(w, 400, "graphql error", itest.CANARY)
            return
        write(w, 200, {"data": data})


class Env:
    """The servers and fakes of one test (Go: itest.NewServer's t.Cleanup)."""

    def __init__(self) -> None:
        self.servers: list[itest.Server] = []
        self.fakes: list[Fake] = []

    def server(self) -> itest.Server:
        srv = itest.Server()
        self.servers.append(srv)
        return srv

    def fake(self) -> Fake:
        f = Fake()
        self.fakes.append(f)
        return f

    def setup_mode(self, mode: str) -> tuple[itest.Server, Fake, Connection]:
        srv = self.server()
        srv.use_spec(spec_from_env("linear"), SpecOptions())
        f = self.fake()
        srv.handle("POST", "/graphql", f.api)
        deps, _ = itest.deps(srv)
        values = {"url": srv.url + "/graphql"}
        if mode != "":
            values["auth_mode"] = mode
        s = itest.settings("ln", "linear", values, {"credential": secret_literal(f.token)})
        c = INTEGRATION.new(background(), s, deps)
        return srv, f, c

    def setup(self) -> tuple[itest.Server, Fake, Connection]:
        return self.setup_mode("")

    def close(self) -> None:
        for s in self.servers:
            s.close()
        for s in self.servers:
            assert not s.spec_errors, "requests did not match the API description:\n" + "\n".join(s.spec_errors)
        for f in self.fakes:
            assert not f.errors, "\n".join(f.errors)


@pytest.fixture
def env() -> Iterator[Env]:
    e = Env()
    yield e
    e.close()


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, INTEGRATION, u, action, resource)


def expect(d: Decision, code: Code, text: str) -> None:
    itest.expect_code(d, code)
    assert text == "" or text in d.text, f"text {d.text!r} does not contain {text!r}"
    itest.assert_no_canary(d.text)


# --- the action table ---------------------------------------------------------


def test_action_team_view_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "team.view", "team:ENG"), Code.ALLOWED, "public")
    expect(check(c, dana, "team.view", "team:SEC"), Code.ALLOWED, "member of private team SEC")
    expect(check(c, gus, "team.view", "team:SEC"), Code.ALLOWED, "member of private team SEC")
    # By id, in any case.
    expect(check(c, bob, "team.view", "team:" + T_ENG.upper()), Code.ALLOWED, "public")


def test_action_team_view_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "team.view", "team:SEC"), Code.DENIED, "private")
    expect(check(c, gus, "team.view", "team:ENG"), Code.DENIED, "guest")


def test_team_visibility_unknowns(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, admin, "team.view", "team:SEC"), Code.UNSUPPORTED, "administrator but not a member")
    expect(check(c, bob, "team.view", "team:RST"), Code.UNSUPPORTED, "restricted")
    expect(check(c, bob, "team.view", "team:OLD"), Code.UNSUPPORTED, "archived")
    expect(check(c, admin, "team.admin", "team:OLD"), Code.UNSUPPORTED, "archived")
    expect(check(c, admin, "team.member", "team:OLD"), Code.UNSUPPORTED, "archived")
    expect(check(c, bob, "team.view", "team:NOPE"), Code.RESOURCE_NOT_VISIBLE, "team NOPE")
    expect(check(c, app, "team.view", "team:ENG"), Code.UNSUPPORTED, "app user")


def test_action_team_member_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "team.member", "team:ENG"), Code.ALLOWED, "member of team ENG")
    expect(check(c, gus, "team.member", "team:SEC"), Code.ALLOWED, "")


def test_action_team_member_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "team.member", "team:ENG"), Code.DENIED, "not a member")
    expect(check(c, admin, "team.member", "team:ENG"), Code.DENIED, "not a member")


def test_action_team_admin_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, lead, "team.admin", "team:ENG"), Code.ALLOWED, "owner of team ENG")
    expect(check(c, admin, "team.admin", "team:SEC"), Code.ALLOWED, "workspace administrator")
    expect(check(c, owner, "team.admin", "team:SEC"), Code.ALLOWED, "")


def test_action_team_admin_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "team.admin", "team:ENG"), Code.DENIED, "not a member")
    expect(check(c, dana, "team.admin", "team:ENG"), Code.UNSUPPORTED, "not an owner")


def test_action_issue_view_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "issue.view", "issue:ENG-1"), Code.ALLOWED, "public")
    expect(check(c, dana, "issue.view", "issue:SEC-1"), Code.ALLOWED, "private team SEC")
    expect(check(c, bob, "issue.view", "issue:eng-1"), Code.ALLOWED, "")
    expect(check(c, bob, "issue.view", "issue:30000000-0000-4000-8000-000000000001"), Code.ALLOWED, "")


def test_action_issue_view_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "issue.view", "issue:SEC-1"), Code.DENIED, "private")
    expect(check(c, gus, "issue.view", "issue:ENG-1"), Code.DENIED, "guest")
    expect(check(c, bob, "issue.view", "issue:ENG-9"), Code.RESOURCE_NOT_VISIBLE, "issue ENG-9")
    expect(check(c, bob, "issue.view", "issue:ENG-2"), Code.UNSUPPORTED, "trash")
    expect(check(c, bob, "issue.view", "issue:RST-1"), Code.UNSUPPORTED, "restricted")


def test_action_issue_edit_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, gus, "issue.edit", "issue:SEC-1"), Code.ALLOWED, "edit and comment")
    expect(check(c, bob, "issue.edit", "issue:ENG-1"), Code.ALLOWED, "")


def test_action_issue_edit_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "issue.edit", "issue:SEC-1"), Code.DENIED, "")


def test_action_project_view_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "project.view", "project:" + P_ENG), Code.ALLOWED, "public")
    # One visible team suffices.
    expect(check(c, bob, "project.view", "project:both-proj"), Code.ALLOWED, "public")
    expect(check(c, gus, "project.view", "project:both-proj"), Code.ALLOWED, "private team SEC")


def test_action_project_view_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "project.view", "project:sec-proj"), Code.DENIED, "cannot see any of the 1 team(s)")
    expect(check(c, gus, "project.view", "project:eng-proj"), Code.DENIED, "")
    expect(check(c, bob, "project.view", "project:none-proj"), Code.UNSUPPORTED, "no team")
    expect(check(c, admin, "project.view", "project:sec-proj"), Code.UNSUPPORTED, "administrator")
    expect(check(c, bob, "project.view", "project:missing"), Code.RESOURCE_NOT_VISIBLE, "project missing")


def test_action_workspace_member_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "workspace.member", "workspace"), Code.ALLOWED, "full member")
    expect(check(c, admin, "workspace.member", "workspace"), Code.ALLOWED, "")


def test_action_workspace_member_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, gus, "workspace.member", "workspace"), Code.DENIED, "guest")
    expect(check(c, app, "workspace.member", "workspace"), Code.DENIED, "app")


def test_action_workspace_admin_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, admin, "workspace.admin", "workspace"), Code.ALLOWED, "administrator")
    expect(check(c, owner, "workspace.admin", "workspace"), Code.ALLOWED, "owner")


def test_action_workspace_admin_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "workspace.admin", "workspace"), Code.DENIED, "neither")


def test_action_workspace_owner_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, owner, "workspace.owner", "workspace"), Code.ALLOWED, "owner")


def test_action_workspace_owner_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, admin, "workspace.owner", "workspace"), Code.DENIED, "not a workspace owner")


# --- identity -----------------------------------------------------------------


def test_identity(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, User(email="nobody@example.com"), "workspace.member", "workspace"), Code.USER_NOT_FOUND, "no Linear user")
    expect(check(c, User(email="dup@example.com"), "workspace.member", "workspace"), Code.USER_AMBIGUOUS, "2 Linear users")
    expect(check(c, User(email="not an email"), "workspace.member", "workspace"), Code.INVALID_REQUEST, "")
    expect(check(c, User(email="susp@example.com"), "workspace.member", "workspace"), Code.DENIED, "admin suspension")
    expect(check(c, User(email="pend@example.com"), "team.view", "team:ENG"), Code.DENIED, "pending invite")


def test_identity_attrs(env: Env) -> None:
    _, _, c = env.setup()
    ident = c.resolve_identity(background(), lead)
    assert ident.id == U_LEAD and ident.attr("owned_teams") == T_ENG and len(ident.groups) == 1 and ident.groups[0] == T_ENG, f"identity {ident}"
    for k, v in ident.attrs.items():
        itest.assert_no_canary(k + "=" + v)


def test_membership_paging(env: Env) -> None:
    srv, f, c = env.setup()
    with f.mu:
        f.page_size = 1
        for u in f.users:
            if u.id == U_DANA:
                u.teams = {T_ENG: False, T_SEC: True, T_RST: False}
    ident = c.resolve_identity(background(), dana)
    assert len(ident.groups) == 3 and ident.attr("owned_teams") == T_SEC, f"identity {ident}"
    pages = sum(1 for call in srv.calls() if b"teamMemberships" in call.body)
    assert pages == 3, f"{pages} membership pages, want 3"


def test_caller_groups_ignored(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, User(email="bob@example.com", groups=(T_SEC, "SEC")), "team.view", "team:SEC"), Code.DENIED, "")


def test_variables_carry_input(env: Env) -> None:
    srv, _, c = env.setup()
    check(c, bob, "issue.view", "issue:ENG-1")
    for call in srv.calls():
        body = json.loads(call.body)
        q = body.get("query") or ""
        assert "example.com" not in q and "ENG-1" not in q, f"value interpolated into the query: {q}"


def test_invalid_requests(env: Env) -> None:
    _, _, c = env.setup()
    errors = []
    for action, resource in (
        ("team.view", "team:eng team"),
        ("team.view", "team:"),
        ("team.view", "issue:ENG-1"),
        ("team.view", "team:ENG?x=1"),
        ("workspace.admin", "workspace:1"),
        ("issue.view", "issue:ENG"),
        ("issue.view", "issue:ENG-0"),
        ("issue.view", "issue:ENG-1/2"),
        ("project.view", "project:a/b"),
        ("team.view", "team:TOOLONGTEAMKEY"),
    ):
        d = check(c, bob, action, resource)
        if d.code != Code.INVALID_REQUEST:
            errors.append(f"{action} {resource}: {d.code} {d.text}")
    assert not errors, "\n".join(errors)


def test_failures(env: Env) -> None:
    srv, _, c = env.setup()
    itest.failure_cases(srv, lambda: check(c, bob, "team.view", "team:ENG"))


def test_graphql_errors(env: Env) -> None:
    _, f, c = env.setup()
    errors = []
    for typ, code in {
        "ratelimited": Code.UPSTREAM_RATE_LIMIT,
        "usage limit exceeded": Code.UPSTREAM_RATE_LIMIT,
        "authentication error": Code.CREDENTIAL_REJECTED,
        "forbidden": Code.CREDENTIAL_REJECTED,
        "feature not accessible": Code.CREDENTIAL_REJECTED,
        "internal error": Code.UPSTREAM_ERROR,
    }.items():
        with f.mu:
            f.gql_error = typ
        d = check(c, bob, "team.view", "team:ENG")
        if d.code != code:
            errors.append(f"{typ}: {d.code} {d.text}, want {code}")
        itest.assert_no_canary(d.text)
    assert not errors, "\n".join(errors)
    # A not-found while listing memberships is an upstream inconsistency,
    # not resource_not_visible.
    with f.mu:
        f.gql_error = ""
        f.users.append(FakeUser("00000000-0000-4000-8000-0000000000ff", "ghost@example.com", active=True))
    with f.mu:
        f.ghost = "00000000-0000-4000-8000-0000000000ff"
    expect(check(c, User(email="ghost@example.com"), "workspace.member", "workspace"), Code.UPSTREAM_ERROR, "vanished")


def test_oauth_mode(env: Env) -> None:
    srv, _, c = env.setup_mode(AUTH_OAUTH)
    expect(check(c, bob, "workspace.member", "workspace"), Code.ALLOWED, "")
    h = srv.last_call().header.get("Authorization")
    assert h.startswith("Bearer "), f"authorization {h!r}"
    # A token stored with its scheme, in any case, is not prefixed twice.
    for stored in ("Bearer ", "bearer "):
        srv = env.server()
        f = env.fake()
        srv.handle("POST", "/graphql", f.api)
        deps, _ = itest.deps(srv)
        s = itest.settings("ln", "linear", {"url": srv.url + "/graphql", "auth_mode": AUTH_OAUTH}, {"credential": secret_literal(stored + f.token)})
        c = INTEGRATION.new(background(), s, deps)
        expect(check(c, bob, "workspace.member", "workspace"), Code.ALLOWED, "")
        h = srv.last_call().header.get("Authorization")
        assert h == stored + f.token, f"authorization {h!r}"


def test_null_object_is_not_visible(env: Env) -> None:
    srv, _, c = env.setup()
    srv.reset()

    def h(w: itest.ResponseWriter, r: itest.Request) -> None:
        try:
            q = r.json().get("query") or ""
        except ValueError:
            q = ""
        if "users(filter" in q:
            write(w, 200, {"data": {"users": {"nodes": [{"id": U_BOB, "email": "bob@example.com", "active": True}]}}})
        elif "teamMemberships(" in q:
            write(w, 200, {"data": {"user": {"teamMemberships": {"nodes": [], "pageInfo": {"hasNextPage": False}}}}})
        elif "issue(id" in q:
            write(w, 200, {"data": {"issue": None}})
        else:
            write(w, 200, {"data": {"project": None}})

    srv.handle("POST", "/graphql", h)
    expect(check(c, bob, "issue.view", "issue:ENG-1"), Code.RESOURCE_NOT_VISIBLE, "issue ENG-1")
    expect(check(c, bob, "project.view", "project:x"), Code.RESOURCE_NOT_VISIBLE, "project x")


def test_new_validation(env: Env) -> None:
    srv = env.server()
    deps, _ = itest.deps(srv)
    for values, with_secret in (
        ({}, False),
        ({"url": "ftp://x"}, True),
        ({"auth_mode": "magic"}, True),
    ):
        secrets = {"credential": secret_literal("x")} if with_secret else {}
        with pytest.raises(ValueError):
            INTEGRATION.new(background(), itest.settings("ln", "linear", values, secrets), deps)
    INTEGRATION.new(background(), itest.settings("ln", "linear", {}, {"credential": secret_literal("x")}), deps)


def test_probe(env: Env) -> None:
    _, f, c = env.setup()
    res = c.probe(background())
    assert "bot@example.com in workspace acme" in res.summary and len(res.warnings) == 1, f"probe {res}"
    itest.assert_no_canary(res.summary)
    with f.mu:
        f.users[0].admin = False
    res = c.probe(background())
    assert len(res.warnings) == 2, f"probe {res}"
    with f.mu:
        f.token = "other"
    with pytest.raises(Exception) as ei:
        c.probe(background())
    ie = as_error(ei.value, HallpassError)
    assert ie is not None and ie.code == Code.CREDENTIAL_REJECTED, f"bad token: {ei.value}"


def test_no_secret_in_logs(env: Env) -> None:
    srv = env.server()
    f = env.fake()
    srv.handle("POST", "/graphql", f.api)
    deps, logs = itest.deps(srv)
    s = itest.settings("ln", "linear", {"url": srv.url + "/graphql"}, {"credential": secret_literal(f.token)})
    c = INTEGRATION.new(background(), s, deps)
    check(c, bob, "issue.view", "issue:ENG-1")
    check(c, bob, "issue.view", "issue:ENG-9")
    itest.assert_no_canary(logs.text())
