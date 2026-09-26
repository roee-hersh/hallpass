"""Port of internal/integrations/gitlab/gitlab_test.go."""

from __future__ import annotations

import datetime
import json
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from hallpass.core.context import background
from hallpass.core.decision import Code, Decision, to_decision
from hallpass.core.integration import Connection, User, find_action, validate_fields
from hallpass.core.secret import Secret
from hallpass.integrations.gitlab import INTEGRATION, GitLabConnection
from hallpass.integrations.gitlab.actions import (
    ACTIONS,
    LEVEL_DEVELOPER,
    LEVEL_GUEST,
    LEVEL_MAINTAINER,
    LEVEL_MINIMAL,
    LEVEL_OWNER,
    LEVEL_PLANNER,
    LEVEL_REPORTER,
    LEVEL_SECURITY_MANAGER,
    match_wildcard,
    validate_branch,
    validate_path,
)
from hallpass.net import httpx
from tests import harness as itest
from tests.harness.spec import SpecOptions, escaped_path, spec_from_env


@dataclass
class FakeUser:
    """One account in the fake GitLab."""

    id: int
    username: str = ""
    state: str = ""
    email: str = ""
    public_email: str = ""
    bot: bool = False
    is_admin: bool = False
    external: bool = False
    # When set, written as the "emails" array of the full record.
    emails: list[Any] | None = None


@dataclass
class FakeMember:
    """One effective membership."""

    level: int
    state: str = ""
    role_id: int = 0
    role_name: str = ""


@dataclass
class FakeProject:
    id: int
    visibility: str
    members: dict[int, FakeMember] = field(default_factory=dict)
    protected: list[dict[str, Any]] | None = None
    # When non-zero, answered for the protected_branches list.
    pb_status: int = 0
    # Written when set.
    issues_access_level: str = ""
    issues_enabled: bool | None = None


@dataclass
class FakeGroup:
    id: int
    members: dict[int, FakeMember] = field(default_factory=dict)
    # When non-zero, answered for every call about the group.
    status: int = 0


TOKEN = "glpat"


def write_json(w: itest.ResponseWriter, status: int, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write(json.dumps(v) + "\n")


def not_found(w: itest.ResponseWriter) -> None:
    write_json(w, 404, {"message": "404 Not Found " + itest.CANARY + "body"})


def member_json(m: FakeMember) -> dict[str, Any]:
    out: dict[str, Any] = {"access_level": m.level, "state": m.state, "name": itest.CANARY + "member"}
    if m.role_id != 0:
        out["member_role"] = {"id": m.role_id, "name": m.role_name, "base_access_level": m.level}
    else:
        out["member_role"] = None
    return out


def _atoi(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return 0


class FakeGitLab:
    """The fake API. Only what hallpass reads is modelled."""

    def __init__(self) -> None:
        self.admin = True  # the token is an administrator's: search returns email and is_admin
        self.users: list[FakeUser] = []
        self.search_hits: list[FakeUser] | None = None  # when set, every /users?search answers these (paginated)
        self.enterprise: list[FakeUser] = []  # enterprise users of the configured group (with email)
        self.saml: list[dict[str, Any]] = []  # SAML identities of the configured group
        self.saml_pages = 0  # split saml into this many pages
        self.next_link = ""  # when set, every paginated list points its next page here
        self.projects: dict[str, FakeProject] = {}  # by path and by numeric id
        self.groups: dict[str, FakeGroup] = {}
        self.me = FakeUser(0)
        self.scopes: list[str] = []
        self.token_code = 0  # status for /personal_access_tokens/self (0 = 200)
        self.expires_at = ""
        self.last_escaped = ""
        # Go's t.Errorf from inside the handler.
        self.errors: list[str] = []

    def user_json(self, u: FakeUser, full: bool) -> dict[str, Any]:
        m: dict[str, Any] = {
            "id": u.id,
            "username": u.username,
            "state": u.state,
            "bot": u.bot,
            "name": itest.CANARY + "name",
            "web_url": "https://gitlab.example/" + u.username,
            "public_email": u.public_email,
        }
        if full:
            m["email"] = u.email
            m["is_admin"] = u.is_admin
            m["external"] = u.external
            if u.emails is not None:
                m["emails"] = u.emails
        return m

    def link(self, r: itest.Request, page: int) -> str:
        """A next-page URL on the fake's own host, or next_link when set."""
        if self.next_link != "":
            return self.next_link
        q = {k: list(v) for k, v in r.query.items()}
        q["page"] = [str(page)]
        return "https://" + r.host + r.raw_path + "?" + httpx.encode_query(q)

    def member(self, project: str, u: FakeUser, level: int) -> None:
        self.projects[project].members[u.id] = FakeMember(level, "active")

    def group_member(self, group: str, u: FakeUser, level: int) -> None:
        self.groups[group].members[u.id] = FakeMember(level, "active")

    def handler(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.header.get("PRIVATE-TOKEN") != itest.CANARY + TOKEN:
            write_json(w, 401, {"message": "401 Unauthorized"})
            return
        if r.header.get("Authorization") != "":
            self.errors.append("unexpected Authorization header")
        esc = escaped_path(r.raw_path)
        self.last_escaped = esc
        if not esc.startswith("/api/v4/"):
            not_found(w)
            return
        seg = [urllib.parse.unquote(s) for s in esc[len("/api/v4/") :].split("/")]
        q = r.q
        if len(seg) == 1 and seg[0] == "user":
            write_json(w, 200, self.user_json(self.me, True))
        elif len(seg) == 2 and seg[0] == "personal_access_tokens" and seg[1] == "self":
            if self.token_code != 0:
                write_json(w, self.token_code, {"message": "nope"})
                return
            write_json(w, 200, {"scopes": self.scopes, "expires_at": self.expires_at, "active": True, "name": itest.CANARY + "tok"})
        elif len(seg) == 1 and seg[0] == "users":
            out: list[dict[str, Any]] = []
            uname = q("username")
            s = q("search").lower()
            if uname != "":
                out = [self.user_json(u, self.admin) for u in self.users if u.username == uname]
            elif s != "":
                if self.search_hits is not None:
                    out = [self.user_json(u, self.admin) for u in self.search_hits]
                else:
                    for u in self.users:
                        hay = (u.username + " " + u.email + " " + u.public_email).lower()
                        if s in hay:
                            out.append(self.user_json(u, self.admin))
                # Offset pagination like GitLab: page and per_page, Link rel=next.
                per = _atoi(q("per_page"))
                if per < 1:
                    per = 20
                page = _atoi(q("page"))
                if page < 1:
                    page = 1
                lo, hi = min((page - 1) * per, len(out)), min(page * per, len(out))
                if hi < len(out):
                    w.header().set("Link", f'<{self.link(r, page + 1)}>; rel="next"')
                out = out[lo:hi]
            write_json(w, 200, out)
        elif len(seg) == 2 and seg[0] == "users":
            uid = _atoi(seg[1])
            for u in self.users:
                if u.id == uid:
                    write_json(w, 200, self.user_json(u, self.admin))
                    return
            not_found(w)
        elif len(seg) >= 2 and seg[0] == "projects":
            p = self.projects.get(seg[1])
            if p is None:
                not_found(w)
                return
            if len(seg) == 2:
                pj: dict[str, Any] = {"id": p.id, "visibility": p.visibility, "description": itest.CANARY + "desc"}
                if p.issues_access_level != "":
                    pj["issues_access_level"] = p.issues_access_level
                if p.issues_enabled is not None:
                    pj["issues_enabled"] = p.issues_enabled
                write_json(w, 200, pj)
            elif len(seg) == 5 and seg[2] == "members" and seg[3] == "all":
                m = p.members.get(_atoi(seg[4]))
                if m is None:
                    not_found(w)
                    return
                write_json(w, 200, member_json(m))
            elif len(seg) == 3 and seg[2] == "protected_branches":
                if p.pb_status != 0:
                    write_json(w, p.pb_status, {"message": "nope"})
                    return
                write_json(w, 200, p.protected if p.protected is not None else [])
            else:
                not_found(w)
        elif len(seg) >= 2 and seg[0] == "groups":
            g = self.groups.get(seg[1])
            if g is None:
                not_found(w)
                return
            if g.status != 0:
                write_json(w, g.status, {"message": "nope"})
                return
            if len(seg) == 2:
                write_json(w, 200, {"id": g.id, "full_path": seg[1], "visibility": "private"})
            elif len(seg) == 5 and seg[2] == "members" and seg[3] == "all":
                m = g.members.get(_atoi(seg[4]))
                if m is None:
                    not_found(w)
                    return
                write_json(w, 200, member_json(m))
            elif len(seg) == 3 and seg[2] == "enterprise_users":
                s = q("search").lower()
                write_json(w, 200, [self.user_json(u, self.admin) for u in self.enterprise if s in (u.email + " " + u.username).lower()])
            elif len(seg) == 4 and seg[2] == "saml" and seg[3] == "identities":
                pages = max(self.saml_pages, 1)
                page = max(_atoi(q("page")), 1)
                per = max((len(self.saml) + pages - 1) // pages, 1)
                lo, hi = min((page - 1) * per, len(self.saml)), min(page * per, len(self.saml))
                if hi < len(self.saml):
                    w.header().set("Link", f'<{self.link(r, page + 1)}>; rel="next"')
                write_json(w, 200, self.saml[lo:hi])
            else:
                not_found(w)
        else:
            not_found(w)


alice = FakeUser(id=7, username="alice", state="active", email="Alice@Example.com", public_email="")
bob = FakeUser(id=8, username="bob", state="active", email="bob@example.com")
blocked = FakeUser(id=9, username="blocked", state="blocked", email="blocked@example.com")
bot = FakeUser(id=10, username="project_bot", state="active", email="bot@example.com", bot=True)
root = FakeUser(id=1, username="root", state="active", email="root@example.com", is_admin=True)
dup1 = FakeUser(id=11, username="dup1", state="active", email="dup@example.com")
dup2 = FakeUser(id=12, username="dup2", state="active", email="dup@example.com")
pub = FakeUser(id=13, username="pub", state="active", email="hidden@example.com", public_email="pub@example.com")


def new_fake() -> FakeGitLab:
    f = FakeGitLab()
    f.users = [alice, bob, blocked, bot, root, dup1, dup2, pub]
    f.me = FakeUser(id=2, username="hallpass", state="active", is_admin=True)
    f.scopes = ["read_api"]
    webapp = FakeProject(id=100, visibility="private")
    f.projects["acme/webapp"] = webapp
    f.projects["100"] = webapp
    f.projects["acme/public"] = FakeProject(id=101, visibility="public")
    f.projects["acme/internal"] = FakeProject(id=102, visibility="internal")
    acme = FakeGroup(id=200)
    f.groups["acme"] = acme
    f.groups["200"] = acme
    return f


# GitLab's published OpenAPI keys paths with /api/v4 and leaves out the
# users, user, SAML identities, enterprise users and token endpoints.
SPEC_OPTS = SpecOptions(
    ignore_paths=[r"^/api/v4/users(/|$)", r"^/api/v4/user$", r"/saml/identities$", r"/enterprise_users$", r"^/api/v4/personal_access_tokens/self$"]
)

_servers: list[itest.Server] = []
_fakes: list[FakeGitLab] = []


@pytest.fixture(autouse=True)
def _cleanup() -> Iterator[None]:
    """Close every server the test started; fail on spec mismatches and on
    errors the fake recorded (Go: t.Errorf inside the handler)."""
    _servers.clear()
    _fakes.clear()
    yield
    errors: list[str] = []
    for s in _servers:
        s.close()
        errors.extend(s.spec_errors)
    for f in _fakes:
        errors.extend(f.errors)
    _servers.clear()
    _fakes.clear()
    assert not errors, "\n".join(errors)


def new_server(tls: bool = True) -> itest.Server:
    s = itest.Server(tls=tls)
    _servers.append(s)
    return s


def setup(f: FakeGitLab, values: dict[str, str] | None = None) -> tuple[itest.Server, GitLabConnection]:
    srv = new_server()
    srv.use_spec(spec_from_env("gitlab"), SPEC_OPTS)
    srv.handle("", "/api/v4/*", f.handler)
    _fakes.append(f)
    deps, _ = itest.deps(srv)
    v = {"url": srv.url, "identity_mode": "admin_search", "username_template": "{local}"}
    v.update(values or {})
    s = itest.settings("gl", "gitlab", v, {"credential": itest.literal(TOKEN)})
    c = INTEGRATION.new(background(), s, deps)
    assert isinstance(c, GitLabConnection)
    return srv, c


def check(c: Connection, email: str, action: str, resource: str) -> Decision:
    return itest.check(c, INTEGRATION, User(email=email), action, resource)


def resolve(c: Connection, email: str) -> tuple[Any, BaseException | None]:
    """ResolveIdentity as Go returns it: the identity or the error."""
    try:
        return c.resolve_identity(background(), User(email=email)), None
    except Exception as e:
        return None, e


def code_of(err: BaseException | None) -> Code | None:
    """integration.ToDecision(err).Code; a nil error is no code."""
    if err is None:
        return None
    return to_decision(err).code


# -- identity modes --


def test_identity_admin_search() -> None:
    f = new_fake()
    srv, c = setup(f)
    ident = c.resolve_identity(background(), User(email="alice@example.com"))
    assert ident.id == "7" and ident.display == "alice" and ident.attr("state") == "active" and ident.attr("bot") == "false"
    assert ident.attr("is_admin") == "false", f"identity {ident}"
    last = srv.last_call()
    assert last.path == "/api/v4/users" and last.q("search") == "alice@example.com", f"call {last.path} {last.query}"
    assert last.header.get("PRIVATE-TOKEN") != "", "PRIVATE-TOKEN header missing"
    # public_email is used when email is absent.
    f.admin = False
    ident, err = resolve(c, "PUB@example.com")
    assert err is None and ident.id == "13" and ident.attr("is_admin") == "", f"public_email match: {ident} {err}"


def test_identity_not_found_ambiguous_and_non_admin() -> None:
    f = new_fake()
    _, c = setup(f)
    itest.expect_code(check(c, "nobody@example.com", "project.read", "project:acme/webapp"), Code.USER_NOT_FOUND)
    itest.expect_code(check(c, "dup@example.com", "project.read", "project:acme/webapp"), Code.USER_AMBIGUOUS)
    # Search hits (substring of alice's email) that do not match exactly: not found.
    itest.expect_code(check(c, "alice@example.co", "project.read", "project:acme/webapp"), Code.USER_NOT_FOUND)
    # A non-admin token gets results without an email field: unknown, not user_not_found.
    f.admin = False
    d = check(c, "alice@example.com", "project.read", "project:acme/webapp")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "administrator" in d.text, f"text {d.text!r} should explain the token is not an administrator's"


def test_identity_enterprise_users() -> None:
    f = new_fake()
    f.enterprise = [alice, bob]
    f.member("acme/webapp", alice, LEVEL_DEVELOPER)
    srv, c = setup(f, {"identity_mode": "enterprise_users", "group": "acme"})
    itest.expect_code(check(c, "alice@example.com", "mr.create", "project:acme/webapp"), Code.ALLOWED)
    saw = any(call.path == "/api/v4/groups/acme/enterprise_users" and call.q("search") == "alice@example.com" for call in srv.calls())
    assert saw, "enterprise_users endpoint not called"
    itest.expect_code(check(c, "nobody@example.com", "mr.create", "project:acme/webapp"), Code.USER_NOT_FOUND)
    f.admin = False
    itest.expect_code(check(c, "alice@example.com", "mr.create", "project:acme/webapp"), Code.UNSUPPORTED)
    # Group not visible.
    f.groups["acme"].status = 404
    itest.expect_code(check(c, "alice@example.com", "mr.create", "project:acme/webapp"), Code.RESOURCE_NOT_VISIBLE)
    f.groups["acme"].status = 403
    itest.expect_code(check(c, "alice@example.com", "mr.create", "project:acme/webapp"), Code.CREDENTIAL_REJECTED)


def test_identity_saml() -> None:
    f = new_fake()
    f.saml = [
        {"extern_uid": "someone@example.com", "user_id": 99},
        {"extern_uid": "bob@example.com", "user_id": 8},
        {"extern_uid": "ALICE@example.com", "user_id": 7},
        {"extern_uid": "dup@example.com", "user_id": 11},
        {"extern_uid": "dup@example.com", "user_id": 12},
    ]
    f.saml_pages = 3
    f.member("acme/webapp", alice, LEVEL_MAINTAINER)
    srv, c = setup(f, {"identity_mode": "saml", "group": "acme"})
    d = check(c, "alice@example.com", "project.admin", "project:acme/webapp")
    itest.expect_code(d, Code.ALLOWED)
    pages = sum(1 for call in srv.calls() if call.path == "/api/v4/groups/acme/saml/identities")
    assert pages == 3, f"saml identities fetched in {pages} pages, want 3"
    itest.expect_code(check(c, "nobody@example.com", "project.admin", "project:acme/webapp"), Code.USER_NOT_FOUND)
    itest.expect_code(check(c, "dup@example.com", "project.admin", "project:acme/webapp"), Code.USER_AMBIGUOUS)
    # A next page on another host is not fetched: the request would carry
    # the token there.
    evil = new_server(tls=False)
    token_seen: list[str] = []

    def elsewhere(w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.header.get("PRIVATE-TOKEN") != "":
            token_seen.append(r.host)
        write_json(w, 200, [])

    evil.unmatched = elsewhere
    f.next_link = evil.url + "/api/v4/groups/acme/saml/identities?page=2"
    d = check(c, "carol@example.com", "project.admin", "project:acme/webapp")
    itest.expect_code(d, Code.UPSTREAM_ERROR)
    assert "outside the connection's url" in d.text and len(evil.calls()) == 0, f"off-host next link: {d}, {len(evil.calls())} requests elsewhere"
    assert not token_seen, f"token sent to {token_seen}"
    f.next_link = ""
    # Identity pointing at a deleted user.
    itest.expect_code(check(c, "someone@example.com", "project.admin", "project:acme/webapp"), Code.USER_NOT_FOUND)


def test_identity_template() -> None:
    f = new_fake()
    f.admin = False
    f.member("acme/webapp", bob, LEVEL_REPORTER)
    srv, c = setup(f, {"identity_mode": "template", "username_template": "{local}", "email_domains": "corp.example"})
    itest.expect_code(check(c, "bob@corp.example", "issue.create", "project:acme/webapp"), Code.ALLOWED)
    first = srv.calls()[0]
    assert first.q("username") == "bob" and first.q("search") == "", f"query {first.query}"
    itest.expect_code(check(c, "nobody@corp.example", "issue.create", "project:acme/webapp"), Code.USER_NOT_FOUND)

    _, c2 = setup(f, {"identity_mode": "template", "username_template": "{domain}-{local}", "email_domains": "corp.example"})
    ident, err = resolve(c2, "bob@corp.example")
    assert err is not None and ident is None, f"corp.example-bob should not exist: {ident} {err}"
    assert c2.username("bob@corp.example") == "corp.example-bob"


def test_new_validation() -> None:
    srv = new_server()
    srv.use_spec(spec_from_env("gitlab"), SPEC_OPTS)
    deps, _ = itest.deps(srv)

    def build(values: dict[str, str] | None, cred: Secret) -> BaseException | None:
        v = {"url": srv.url}
        v.update(values or {})
        try:
            INTEGRATION.new(background(), itest.settings("gl", "gitlab", v, {"credential": cred}), deps)
        except Exception as e:
            return e
        return None

    err = build({"identity_mode": "saml"}, itest.literal(TOKEN))
    assert err is not None and "group is required" in str(err), f"saml without group: {err}"
    assert build({"identity_mode": "enterprise_users"}, itest.literal(TOKEN)) is not None, "enterprise_users without group accepted"
    assert build({"identity_mode": "saml", "group": "bad path!"}, itest.literal(TOKEN)) is not None, "bad group path accepted"
    assert build({"identity_mode": "ldap"}, itest.literal(TOKEN)) is not None, "unknown identity_mode accepted"
    assert build({"username_template": "static"}, itest.literal(TOKEN)) is not None, "static template accepted"
    err = build({"identity_mode": "template"}, itest.literal(TOKEN))
    assert err is not None and "email_domains" in str(err), f"template without email_domains: {err}"
    for bad in ["acme.com,", ",acme.com", "acme.com, ,acme.io", "acme.com;acme.io", "a/b", ",", "a b.com", "exa_mple.com"]:
        assert build({"identity_mode": "template", "email_domains": bad}, itest.literal(TOKEN)) is not None, f"email_domains {bad!r} accepted"
    # Spaces around the commas and upper case are normalised, as in github.
    for good in ["acme.com,acme.io", "acme.com, acme.io", "Acme.com"]:
        err = build({"identity_mode": "template", "email_domains": good}, itest.literal(TOKEN))
        assert err is None, f"email_domains {good!r}: {err}"
    assert build(None, Secret()) is not None, "missing credential accepted"
    assert build({"identity_mode": "saml", "group": "acme/sub"}, itest.literal(TOKEN)) is None
    assert build({}, itest.literal(TOKEN)) is None
    assert len(srv.calls()) == 0, "New touched the network"
    for fl in INTEGRATION.fields():
        if fl.name == "url":
            assert fl.default == "https://gitlab.com", f"url default {fl.default!r}"
    validate_fields(INTEGRATION.fields())


# -- users that exist but may not act --


def test_inactive_and_bot_users_denied() -> None:
    f = new_fake()
    f.member("acme/webapp", blocked, LEVEL_OWNER)
    f.member("acme/webapp", bot, LEVEL_OWNER)
    srv, c = setup(f)
    d = check(c, "blocked@example.com", "project.read", "project:acme/webapp")
    itest.expect_code(d, Code.DENIED)
    assert "blocked" in d.text, d.text
    for call in srv.calls():
        assert "/members/" not in call.path, "membership looked up for a blocked user"
    d = check(c, "bot@example.com", "project.read", "project:acme/webapp")
    itest.expect_code(d, Code.DENIED)
    assert "bot" in d.text, d.text


def test_membership_not_active() -> None:
    f = new_fake()
    f.projects["acme/webapp"].members[alice.id] = FakeMember(LEVEL_OWNER, "awaiting")
    _, c = setup(f)
    d = check(c, "alice@example.com", "project.read", "project:acme/webapp")
    itest.expect_code(d, Code.DENIED)
    assert "awaiting" in d.text, d.text


# -- level semantics --


def test_non_cumulative_levels() -> None:
    f = new_fake()
    f.member("acme/webapp", alice, LEVEL_PLANNER)
    f.member("acme/webapp", bob, LEVEL_SECURITY_MANAGER)
    _, c = setup(f)
    itest.expect_code(check(c, "alice@example.com", "mr.create", "project:acme/webapp"), Code.DENIED)
    itest.expect_code(check(c, "alice@example.com", "issue.edit", "project:acme/webapp"), Code.ALLOWED)
    itest.expect_code(check(c, "alice@example.com", "project.read", "project:acme/webapp"), Code.ALLOWED)
    itest.expect_code(check(c, "bob@example.com", "repo.push", "project:acme/webapp"), Code.DENIED)
    itest.expect_code(check(c, "bob@example.com", "pipeline.run", "project:acme/webapp"), Code.DENIED)
    itest.expect_code(check(c, "bob@example.com", "project.read", "project:acme/webapp"), Code.ALLOWED)
    # Minimal Access (5) grants nothing.
    f.member("acme/webapp", root, LEVEL_MINIMAL)
    itest.expect_code(check(c, "root@example.com", "project.read", "project:acme/webapp"), Code.DENIED)


def test_conditional_level_is_unknown() -> None:
    f = new_fake()
    f.member("acme/webapp", alice, LEVEL_REPORTER)
    f.member("acme/webapp", bob, LEVEL_PLANNER)
    _, c = setup(f)
    d = check(c, "alice@example.com", "mr.approve", "project:acme/webapp")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "approval rules" in d.text, d.text
    itest.expect_code(check(c, "bob@example.com", "mr.approve", "project:acme/webapp"), Code.UNSUPPORTED)


def test_non_member_visibility() -> None:
    f = new_fake()
    srv, c = setup(f)
    itest.expect_code(check(c, "alice@example.com", "project.read", "project:acme/public"), Code.ALLOWED)
    itest.expect_code(check(c, "alice@example.com", "project.read", "project:acme/internal"), Code.ALLOWED)
    itest.expect_code(check(c, "alice@example.com", "issue.create", "project:acme/internal"), Code.ALLOWED)
    itest.expect_code(check(c, "alice@example.com", "issue.create", "project:acme/public"), Code.ALLOWED)
    itest.expect_code(check(c, "alice@example.com", "project.read", "project:acme/webapp"), Code.DENIED)
    itest.expect_code(check(c, "alice@example.com", "mr.create", "project:acme/public"), Code.DENIED)
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/public@main"), Code.DENIED)
    # A non-member never triggers a protected-branch lookup.
    for call in srv.calls():
        assert not call.path.endswith("/protected_branches"), "protected branches read for a non-member"
    # Group: non-member of an existing group is denied; a missing group is not visible.
    itest.expect_code(check(c, "alice@example.com", "group.member", "group:acme"), Code.DENIED)
    itest.expect_code(check(c, "alice@example.com", "group.member", "group:nope"), Code.RESOURCE_NOT_VISIBLE)


def test_project_not_visible() -> None:
    f = new_fake()
    _, c = setup(f)
    d = check(c, "alice@example.com", "project.read", "project:acme/missing")
    itest.expect_code(d, Code.RESOURCE_NOT_VISIBLE)
    itest.expect_code(check(c, "alice@example.com", "project.read", "project:12345"), Code.RESOURCE_NOT_VISIBLE)


def test_path_escaping_and_numeric_ids() -> None:
    f = new_fake()
    f.member("acme/webapp", alice, LEVEL_DEVELOPER)
    srv, c = setup(f)
    itest.expect_code(check(c, "alice@example.com", "mr.create", "project:acme/webapp"), Code.ALLOWED)
    assert "/projects/acme%2Fwebapp/members/all/7" in f.last_escaped, f"path {f.last_escaped!r} should encode / as %2F"
    itest.expect_code(check(c, "alice@example.com", "mr.create", "project:100"), Code.ALLOWED)
    last = srv.last_call()
    assert last.path == "/api/v4/projects/100/members/all/7", last.path
    f.group_member("acme", alice, LEVEL_GUEST)
    itest.expect_code(check(c, "alice@example.com", "group.member", "group:200"), Code.ALLOWED)


def test_custom_role_unknown() -> None:
    f = new_fake()
    f.projects["acme/webapp"].members[alice.id] = FakeMember(LEVEL_GUEST, "active", role_id=5, role_name="guest-plus")
    _, c = setup(f)
    # Base level grants: allow.
    itest.expect_code(check(c, "alice@example.com", "project.read", "project:acme/webapp"), Code.ALLOWED)
    # Base level does not grant: unknown, the custom role may add it.
    d = check(c, "alice@example.com", "repo.push", "project:acme/webapp")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "guest-plus" in d.text, d.text
    itest.expect_code(check(c, "alice@example.com", "project.delete", "project:acme/webapp"), Code.UNSUPPORTED)


def test_credential_rejected_on403() -> None:
    f = new_fake()
    _, c = setup(f)
    f.groups["acme"].status = 403
    itest.expect_code(check(c, "alice@example.com", "group.member", "group:acme"), Code.CREDENTIAL_REJECTED)


# -- protected branches --


def entry(*kv: Any) -> dict[str, Any]:
    m: dict[str, Any] = {"access_level": 0, "user_id": None, "group_id": None, "access_level_description": itest.CANARY + "entry"}
    for i in range(0, len(kv) - 1, 2):
        m[kv[i]] = kv[i + 1]
    return m


def protect(name: str, push: list[dict[str, Any]] | None, merge: list[dict[str, Any]] | None) -> dict[str, Any]:
    return {"name": name, "push_access_levels": push if push is not None else [], "merge_access_levels": merge if merge is not None else []}


def test_protected_branch_wildcard_and_levels() -> None:
    f = new_fake()
    p = f.projects["acme/webapp"]
    f.member("acme/webapp", alice, LEVEL_DEVELOPER)
    f.member("acme/webapp", bob, LEVEL_MAINTAINER)
    p.protected = [
        protect("main", [entry("access_level", 40)], [entry("access_level", 30)]),
        protect("release/*", [entry("access_level", 40)], [entry("access_level", 40)]),
        protect("*-hotfix", [entry("access_level", 30)], None),
    ]
    _, c = setup(f)
    # main: push maintainers, merge developers.
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@main"), Code.DENIED)
    itest.expect_code(check(c, "alice@example.com", "mr.merge", "project:acme/webapp@main"), Code.ALLOWED)
    itest.expect_code(check(c, "bob@example.com", "repo.push", "project:acme/webapp@main"), Code.ALLOWED)
    # Wildcards.
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@release/2.0"), Code.DENIED)
    itest.expect_code(check(c, "bob@example.com", "repo.push", "project:acme/webapp@release/2.0/rc1"), Code.ALLOWED)
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@v1-hotfix"), Code.ALLOWED)
    # Unprotected branch: the unprotected rule applies.
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@feature/x"), Code.ALLOWED)
    # No branch given while rules exist: unknown, the caller must name the branch.
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp"), Code.UNSUPPORTED)
    # Merge on "*-hotfix" allows no one (empty entry list): deny.
    itest.expect_code(check(c, "bob@example.com", "mr.merge", "project:acme/webapp@v1-hotfix"), Code.DENIED)


def test_protected_branch_user_and_no_one() -> None:
    f = new_fake()
    p = f.projects["acme/webapp"]
    f.member("acme/webapp", alice, LEVEL_DEVELOPER)
    f.member("acme/webapp", bob, LEVEL_OWNER)
    p.protected = [
        protect("main", [entry("access_level", 40, "user_id", 7)], [entry("access_level", 0)]),
        protect("locked", [entry("access_level", 0)], [entry("access_level", 0)]),
    ]
    _, c = setup(f)
    # user_id entry names alice: allowed although she is only a Developer.
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@main"), Code.ALLOWED)
    # bob is an Owner but the only entry names alice.
    itest.expect_code(check(c, "bob@example.com", "repo.push", "project:acme/webapp@main"), Code.DENIED)
    # access_level 0 for every entry: no one, even an Owner.
    d = check(c, "bob@example.com", "mr.merge", "project:acme/webapp@main")
    itest.expect_code(d, Code.DENIED)
    assert "no one" in d.text, d.text
    itest.expect_code(check(c, "bob@example.com", "repo.push", "project:acme/webapp@locked"), Code.DENIED)


def test_protected_branch_group_entries() -> None:
    f = new_fake()
    p = f.projects["acme/webapp"]
    f.member("acme/webapp", alice, LEVEL_DEVELOPER)
    f.member("acme/webapp", bob, LEVEL_DEVELOPER)
    f.groups["300"] = FakeGroup(id=300, members={alice.id: FakeMember(LEVEL_DEVELOPER, "active")})
    f.groups["301"] = FakeGroup(id=301, status=403)
    p.protected = [
        protect("main", [entry("access_level", 40, "group_id", 300)], None),
        protect("staging", [entry("access_level", 40, "group_id", 301)], None),
    ]
    srv, c = setup(f)
    # Group resolved: alice is in group 300, bob is not.
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@main"), Code.ALLOWED)
    last = srv.last_call()
    assert last.path == "/api/v4/groups/300/members/all/7", last.path
    itest.expect_code(check(c, "bob@example.com", "repo.push", "project:acme/webapp@main"), Code.DENIED)
    # Group unresolved (403): unknown.
    d = check(c, "alice@example.com", "repo.push", "project:acme/webapp@staging")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "301" in d.text, d.text


def test_protected_branch_admins_and_custom_roles() -> None:
    f = new_fake()
    p = f.projects["acme/webapp"]
    f.member("acme/webapp", alice, LEVEL_MAINTAINER)
    f.member("acme/webapp", root, LEVEL_MAINTAINER)
    f.projects["acme/webapp"].members[bob.id] = FakeMember(LEVEL_DEVELOPER, "active", role_id=5, role_name="pusher")
    p.protected = [
        protect("main", [entry("access_level", 60)], None),
        protect("roles", [entry("access_level", 30, "member_role_id", 5)], None),
        protect("strict", [entry("access_level", 40)], None),
    ]
    _, c = setup(f)
    # Admins only: known admin allowed, known non-admin denied.
    itest.expect_code(check(c, "root@example.com", "repo.push", "project:acme/webapp@main"), Code.ALLOWED)
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@main"), Code.DENIED)
    # Admin status unknown (non-admin token does not return is_admin): unknown.
    f.admin = False
    f.users = [
        FakeUser(id=7, username="alice", state="active", public_email="alice@example.com"),
        FakeUser(id=8, username="bob", state="active", public_email="bob@example.com"),
    ]
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@main"), Code.UNSUPPORTED)
    # Custom role entries.
    itest.expect_code(check(c, "bob@example.com", "repo.push", "project:acme/webapp@roles"), Code.ALLOWED)
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@roles"), Code.UNSUPPORTED)
    # A member with a custom role whose base level misses the rule: unknown.
    itest.expect_code(check(c, "bob@example.com", "repo.push", "project:acme/webapp@strict"), Code.UNSUPPORTED)
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@strict"), Code.ALLOWED)


def test_protected_branch_list_forbidden() -> None:
    f = new_fake()
    f.member("acme/webapp", alice, LEVEL_DEVELOPER)
    f.projects["acme/webapp"].pb_status = 403
    _, c = setup(f)
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@main"), Code.CREDENTIAL_REJECTED)
    # Without a branch the rules are still listed, so the 403 shows here too.
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp"), Code.CREDENTIAL_REJECTED)
    # Actions without a branch rule never list protected branches.
    itest.expect_code(check(c, "alice@example.com", "mr.create", "project:acme/webapp"), Code.ALLOWED)


@pytest.mark.parametrize(
    ("pattern", "name", "want"),
    [
        ("main", "main", True),
        ("main", "maint", False),
        ("*", "anything/at/all", True),
        ("release/*", "release/1.0", True),
        ("release/*", "release/", True),
        ("release/*", "releases/1.0", False),
        ("*-stable", "v1-stable", True),
        ("*-stable", "v1-stable-x", False),
        ("v*.*.*", "v1.2.3", True),
        ("v*.*.*", "v1.2", False),
        ("**", "x", True),
        ("a*b*c", "abc", True),
        ("a*b*c", "axxbyyc", True),
        ("a*b*c", "axxbyy", False),
        ("", "", True),
        ("", "x", False),
    ],
)
def test_wildcard(pattern: str, name: str, want: bool) -> None:
    assert match_wildcard(pattern, name) == want, f"match_wildcard({pattern!r}, {name!r})"


def test_bad_resources() -> None:
    f = new_fake()
    _, c = setup(f)
    cases = [
        ("project.read", "group:acme"),
        ("group.member", "project:acme/webapp"),
        ("project.read", "repo:acme/webapp"),
        ("project.read", "project:"),
        ("project.read", "project:-bad"),
        ("project.read", "project:acme//webapp"),
        ("project.read", "project:acme/webapp/"),
        ("project.read", "project:acme/web app"),
        ("project.read", "project:../etc"),
        ("project.read", "project:acme/webapp?x=1"),
        ("repo.push", "project:acme/webapp@"),
        ("repo.push", "project:acme/webapp@-x"),
        ("repo.push", "project:acme/webapp@a..b"),
        ("repo.push", "project:acme/webapp@a b"),
        ("repo.push", "project:acme/webapp@a~b"),
        ("repo.push", "project:acme/webapp@a/"),
        ("group.member", "group:acme@main"),
    ]
    bad = []
    for action, resource in cases:
        d = check(c, "alice@example.com", action, resource)
        if d.code != Code.INVALID_REQUEST:
            bad.append(f"{action} {resource} -> {d.code}: {d.text}")
    assert not bad, "\n".join(bad)
    for ok in ["acme/webapp", "acme/sub.group/web-app_2", "42", "a.b"]:
        validate_path(ok)
    for ok in ["main", "release/2.0", "feature/JIRA-123_x", "v1.2.3", "a@b"]:
        validate_branch(ok)


def test_failures() -> None:
    f = new_fake()
    f.member("acme/webapp", alice, LEVEL_DEVELOPER)
    srv, c = setup(f)
    itest.failure_cases(srv, lambda: check(c, "alice@example.com", "repo.push", "project:acme/webapp@main"))


def test_probe() -> None:
    f = new_fake()
    srv, c = setup(f)
    r = c.probe(background())
    assert "hallpass" in r.summary and "administrator" in r.summary and len(r.warnings) == 0, r

    # Non-admin token with admin_search: warn. Broad scopes: warn.
    f.me.is_admin = False
    f.scopes = ["api", "read_api", "sudo"]
    r = c.probe(background())
    assert len(r.warnings) == 2 and "administrator" in r.warnings[0] and "sudo" in r.warnings[1], r.warnings

    # Missing read_api.
    f.me.is_admin = True
    f.scopes = ["read_user"]
    r = c.probe(background())
    assert len(r.warnings) == 1 and "read_api" in r.warnings[0], r.warnings

    # Token endpoint unavailable: a warning, not an error.
    f.scopes = ["read_api"]
    f.token_code = 404
    r = c.probe(background())
    assert len(r.warnings) == 1 and "could not verify" in r.warnings[0], r
    f.token_code = 0

    # Expiring soon.
    f.expires_at = (datetime.datetime.now() + datetime.timedelta(days=3)).strftime("%Y-%m-%d")
    r = c.probe(background())
    assert len(r.warnings) == 1 and "expires" in r.warnings[0], r.warnings
    f.expires_at = ""

    # Group modes report the group; a missing group fails the probe.
    f.enterprise = [alice]
    _, c2 = setup(f, {"identity_mode": "enterprise_users", "group": "acme"})
    r = c2.probe(background())
    assert "group acme" in r.summary, r
    _, c3 = setup(f, {"identity_mode": "saml", "group": "other"})
    with pytest.raises(Exception):  # noqa: B017 - Go: err == nil fails
        c3.probe(background())
    # Template mode on a non-admin token: no admin warning.
    f.me.is_admin = False
    _, c4 = setup(f, {"identity_mode": "template", "email_domains": "example.com"})
    r = c4.probe(background())
    assert len(r.warnings) == 0, r.warnings
    # Bad credential.
    srv.fail(itest.Failure.UNAUTHORIZED)
    try:
        with pytest.raises(Exception) as ei:
            c.probe(background())
        assert to_decision(ei.value).code == Code.CREDENTIAL_REJECTED, f"401 on probe: {ei.value}"
    finally:
        srv.fail(itest.Failure.NONE)


# -- allow/deny tests per action (coverage gate) --


def action_allow(action: str, resource: str, level: int) -> None:
    f = new_fake()
    if resource.startswith("group:"):
        f.group_member("acme", alice, level)
    else:
        f.member("acme/webapp", alice, level)
    _, c = setup(f)
    itest.expect_code(check(c, "alice@example.com", action, resource), Code.ALLOWED)


def action_deny(action: str, resource: str, level: int) -> None:
    f = new_fake()
    if resource.startswith("group:"):
        f.group_member("acme", alice, level)
    else:
        f.member("acme/webapp", alice, level)
    _, c = setup(f)
    itest.expect_code(check(c, "alice@example.com", action, resource), Code.DENIED)


PROJ = "project:acme/webapp"


def test_action_project_read_allow() -> None:
    action_allow("project.read", PROJ, LEVEL_GUEST)


def test_action_project_read_deny() -> None:
    action_deny("project.read", PROJ, LEVEL_MINIMAL)


def test_action_issue_create_allow() -> None:
    action_allow("issue.create", PROJ, LEVEL_GUEST)


def test_action_issue_create_deny() -> None:
    action_deny("issue.create", PROJ, LEVEL_MINIMAL)


def test_action_issue_edit_allow() -> None:
    action_allow("issue.edit", PROJ, LEVEL_PLANNER)


def test_action_issue_edit_deny() -> None:
    action_deny("issue.edit", PROJ, LEVEL_GUEST)


def test_action_mr_create_allow() -> None:
    action_allow("mr.create", PROJ, LEVEL_DEVELOPER)


def test_action_mr_create_deny() -> None:
    action_deny("mr.create", PROJ, LEVEL_SECURITY_MANAGER)


def test_action_mr_approve_allow() -> None:
    action_allow("mr.approve", PROJ, LEVEL_DEVELOPER)


def test_action_mr_approve_deny() -> None:
    action_deny("mr.approve", PROJ, LEVEL_GUEST)


def test_action_repo_push_allow() -> None:
    action_allow("repo.push", PROJ, LEVEL_DEVELOPER)


def test_action_repo_push_deny() -> None:
    action_deny("repo.push", PROJ, LEVEL_REPORTER)


def test_action_mr_merge_allow() -> None:
    action_allow("mr.merge", PROJ, LEVEL_MAINTAINER)


def test_action_mr_merge_deny() -> None:
    action_deny("mr.merge", PROJ, LEVEL_REPORTER)


def test_action_branch_protect_allow() -> None:
    action_allow("branch.protect", PROJ, LEVEL_MAINTAINER)


def test_action_branch_protect_deny() -> None:
    action_deny("branch.protect", PROJ, LEVEL_DEVELOPER)


def test_action_project_admin_allow() -> None:
    action_allow("project.admin", PROJ, LEVEL_OWNER)


def test_action_project_admin_deny() -> None:
    action_deny("project.admin", PROJ, LEVEL_DEVELOPER)


def test_action_member_manage_allow() -> None:
    action_allow("member.manage", PROJ, LEVEL_MAINTAINER)


def test_action_member_manage_deny() -> None:
    action_deny("member.manage", PROJ, LEVEL_DEVELOPER)


def test_action_project_delete_allow() -> None:
    action_allow("project.delete", PROJ, LEVEL_OWNER)


def test_action_project_delete_deny() -> None:
    action_deny("project.delete", PROJ, LEVEL_MAINTAINER)


def test_action_pipeline_run_allow() -> None:
    action_allow("pipeline.run", PROJ, LEVEL_DEVELOPER)


def test_action_pipeline_run_deny() -> None:
    action_deny("pipeline.run", PROJ, LEVEL_PLANNER)


def test_action_variable_manage_allow() -> None:
    action_allow("variable.manage", PROJ, LEVEL_MAINTAINER)


def test_action_variable_manage_deny() -> None:
    action_deny("variable.manage", PROJ, LEVEL_DEVELOPER)


def test_action_runner_manage_allow() -> None:
    action_allow("runner.manage", PROJ, LEVEL_MAINTAINER)


def test_action_runner_manage_deny() -> None:
    action_deny("runner.manage", PROJ, LEVEL_DEVELOPER)


def test_action_group_member_allow() -> None:
    action_allow("group.member", "group:acme", LEVEL_GUEST)


def test_action_group_member_deny() -> None:
    action_deny("group.member", "group:acme", LEVEL_MINIMAL)


def test_action_group_admin_allow() -> None:
    action_allow("group.admin", "group:acme", LEVEL_OWNER)


def test_action_group_admin_deny() -> None:
    action_deny("group.admin", "group:acme", LEVEL_MAINTAINER)


def test_action_group_project_create_allow() -> None:
    action_allow("group.project.create", "group:acme", LEVEL_DEVELOPER)


def test_action_group_project_create_deny() -> None:
    action_deny("group.project.create", "group:acme", LEVEL_REPORTER)


def test_every_action_has_a_spec() -> None:
    for a in INTEGRATION.actions():
        assert a.name in ACTIONS and not a.pattern, f"action {a.name}"
        assert find_action(INTEGRATION, a.name) is not None, f"action {a.name} not found"
    assert find_action(INTEGRATION, "repo.delete") is None, "unknown action matched"


# -- security-review findings --


def test_protected_branch_deploy_key_entry() -> None:
    f = new_fake()
    p = f.projects["acme/webapp"]
    f.member("acme/webapp", alice, LEVEL_MAINTAINER)
    # alice's user id is 7, the same number as the deploy key: the entry
    # must never be read as naming her, nor as "Maintainers and up".
    p.protected = [
        protect("main", [entry("access_level", 40, "deploy_key_id", 7)], None),
        protect("both", [entry("access_level", 40, "deploy_key_id", 7), entry("access_level", 40)], None),
    ]
    _, c = setup(f)
    d = check(c, "alice@example.com", "repo.push", "project:acme/webapp@main")
    itest.expect_code(d, Code.DENIED)
    assert "no one" not in d.text, f"a deploy key may push, so the rule is not 'no one': {d.text}"
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@both"), Code.ALLOWED)


def test_external_user_on_internal_project() -> None:
    f = new_fake()
    ext = FakeUser(id=20, username="ext", state="active", email="ext@example.com", public_email="ext@example.com", external=True)
    f.users.append(ext)
    _, c = setup(f)
    ident, err = resolve(c, "ext@example.com")
    assert err is None and ident.attr("external") == "true", f"identity {ident} {err}"
    # External users cannot see internal projects; public ones they can.
    d = check(c, "ext@example.com", "project.read", "project:acme/internal")
    itest.expect_code(d, Code.DENIED)
    assert "external" in d.text, d.text
    itest.expect_code(check(c, "ext@example.com", "issue.create", "project:acme/internal"), Code.DENIED)
    itest.expect_code(check(c, "ext@example.com", "project.read", "project:acme/public"), Code.ALLOWED)
    # A known non-external user is still allowed.
    itest.expect_code(check(c, "alice@example.com", "project.read", "project:acme/internal"), Code.ALLOWED)
    # A non-admin token cannot see the external flag: unknown on internal, allow on public.
    f.admin = False
    ident, err = resolve(c, "ext@example.com")
    assert err is None and ident.attr("external") == "", f"identity {ident} {err}"
    itest.expect_code(check(c, "ext@example.com", "project.read", "project:acme/internal"), Code.UNSUPPORTED)
    itest.expect_code(check(c, "ext@example.com", "project.read", "project:acme/public"), Code.ALLOWED)


def test_admin_non_member_allowed() -> None:
    f = new_fake()
    _, c = setup(f)
    d = check(c, "root@example.com", "project.delete", "project:acme/webapp")
    itest.expect_code(d, Code.ALLOWED)
    assert "instance administrator" in d.text, d.text
    itest.expect_code(check(c, "root@example.com", "group.admin", "group:acme"), Code.ALLOWED)
    # A project the token cannot see is still not visible, even for an administrator.
    itest.expect_code(check(c, "root@example.com", "project.read", "project:acme/missing"), Code.RESOURCE_NOT_VISIBLE)
    # Issues disabled: even an administrator cannot create one.
    f.projects["acme/webapp"].issues_access_level = "disabled"
    itest.expect_code(check(c, "root@example.com", "issue.create", "project:acme/webapp"), Code.DENIED)
    # Administrator status unknown (non-admin token): the membership deny stands.
    f.admin = False
    f.users = [FakeUser(id=1, username="root", state="active", public_email="root@example.com")]
    itest.expect_code(check(c, "root@example.com", "project.delete", "project:acme/webapp"), Code.DENIED)


def filler_users(n: int) -> list[FakeUser]:
    return [FakeUser(id=1000 + i, username=f"filler{i}", state="active", email=f"filler{i}@example.com") for i in range(n)]


def test_secondary_emails_and_pagination() -> None:
    f = new_fake()
    carol = FakeUser(
        id=30,
        username="carol",
        state="active",
        email="carol@example.com",
        emails=[
            {"email": "Carol.Alias@example.com", "confirmed_at": "2020-01-02T03:04:05Z"},
            {"email": "pending@example.com", "confirmed_at": None},
            "plain@example.com",
        ],
    )
    # carol is on page 2 of a 100-per-page listing.
    f.search_hits = [*filler_users(150), carol]
    srv, c = setup(f)
    ident, err = resolve(c, "carol@example.com")
    assert err is None and ident.id == "30", f"primary email on page 2: {ident} {err}"
    pages: set[str] = set()
    for call in srv.calls():
        if call.path == "/api/v4/users":
            assert call.q("per_page") == "100", f"per_page {call.q('per_page')!r}"
            pages.add(call.q("page"))
    assert pages == {"1", "2"}, f"pages fetched: {pages}"
    # A confirmed secondary email matches, ignoring case.
    ident, err = resolve(c, "carol.alias@example.com")
    assert err is None and ident.id == "30", f"confirmed secondary email: {ident} {err}"
    # A secondary email without confirmed_at at all is accepted.
    ident, err = resolve(c, "plain@example.com")
    assert err is None and ident.id == "30", f"secondary email without confirmed_at: {ident} {err}"
    # An unconfirmed secondary email never matches.
    _, err = resolve(c, "pending@example.com")
    assert code_of(err) == Code.USER_NOT_FOUND, f"unconfirmed secondary email: {err}"
    # Never a substring.
    _, err = resolve(c, "alias@example.com")
    assert code_of(err) == Code.USER_NOT_FOUND, f"substring: {err}"
    # Two accounts sharing a secondary email are ambiguous.
    dave = FakeUser(
        id=31, username="dave", state="active", email="dave@example.com", emails=[{"email": "carol.alias@example.com", "confirmed_at": "2020-01-02T03:04:05Z"}]
    )
    f.search_hits = [carol, dave]
    _, err = resolve(c, "carol.alias@example.com")
    assert code_of(err) == Code.USER_AMBIGUOUS, f"shared secondary email: {err}"


def test_search_too_many_candidates() -> None:
    f = new_fake()
    f.search_hits = filler_users(520)
    srv, c = setup(f)
    _, err = resolve(c, "alice@example.com")
    assert err is not None
    d = to_decision(err)
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "too many candidates" in d.text, d.text
    n = sum(1 for call in srv.calls() if call.path == "/api/v4/users")
    assert n == 5, f"{n} pages fetched, want 5"
    # A match on the fifth page is still found.
    f.search_hits = [*filler_users(450), alice]
    ident, err = resolve(c, "alice@example.com")
    assert err is None and ident.id == "7", f"match on page 5: {ident} {err}"
    # Exactly five full pages and no match: unknown, not user_not_found.
    f.search_hits = filler_users(500)
    _, err = resolve(c, "alice@example.com")
    assert err is not None
    itest.expect_code(to_decision(err), Code.UNSUPPORTED)
    # A short last page with no match: user_not_found.
    f.search_hits = filler_users(499)
    _, err = resolve(c, "alice@example.com")
    assert err is not None
    itest.expect_code(to_decision(err), Code.USER_NOT_FOUND)


def test_branchless_push_with_protected_rules() -> None:
    f = new_fake()
    f.member("acme/webapp", alice, LEVEL_DEVELOPER)
    f.member("acme/webapp", bob, LEVEL_MAINTAINER)
    f.projects["acme/webapp"].protected = [protect("main", [entry("access_level", 40)], [entry("access_level", 40)])]
    srv, c = setup(f)
    for action in ["repo.push", "mr.merge"]:
        for u in ["alice@example.com", "bob@example.com"]:
            d = check(c, u, action, "project:acme/webapp")
            itest.expect_code(d, Code.UNSUPPORTED)
            assert "@branch" in d.text, f"{action} {u}: {d.text}"
    # With the branch named, the rule decides.
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@main"), Code.DENIED)
    itest.expect_code(check(c, "bob@example.com", "repo.push", "project:acme/webapp@main"), Code.ALLOWED)
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp@feature"), Code.ALLOWED)
    # No rules at all: the level rule applies.
    f.projects["acme/webapp"].protected = None
    srv.reset()
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp"), Code.ALLOWED)
    listed = any(call.path.endswith("/protected_branches") for call in srv.calls())
    assert listed, "protected branches were not listed for a branchless push"
    # A level that never pushes is still denied when no rules exist.
    f.member("acme/webapp", alice, LEVEL_REPORTER)
    itest.expect_code(check(c, "alice@example.com", "repo.push", "project:acme/webapp"), Code.DENIED)


def test_public_issue_creation_and_issues_disabled() -> None:
    f = new_fake()
    pubp = f.projects["acme/public"]
    _, c = setup(f)
    itest.expect_code(check(c, "alice@example.com", "issue.create", "project:acme/public"), Code.ALLOWED)
    pubp.issues_access_level = "enabled"
    itest.expect_code(check(c, "alice@example.com", "issue.create", "project:acme/public"), Code.ALLOWED)
    pubp.issues_access_level = "disabled"
    d = check(c, "alice@example.com", "issue.create", "project:acme/public")
    itest.expect_code(d, Code.DENIED)
    assert "issues" in d.text, d.text
    # Issues disabled does not touch other actions.
    itest.expect_code(check(c, "alice@example.com", "project.read", "project:acme/public"), Code.ALLOWED)
    # issues_enabled false (older shape) also denies.
    pubp.issues_access_level = ""
    pubp.issues_enabled = False
    itest.expect_code(check(c, "alice@example.com", "issue.create", "project:acme/public"), Code.DENIED)
    # Issues for members only: a non-member is denied.
    pubp.issues_enabled = None
    pubp.issues_access_level = "private"
    itest.expect_code(check(c, "alice@example.com", "issue.create", "project:acme/public"), Code.DENIED)
    # Internal projects stay open to non-external signed-in users.
    itest.expect_code(check(c, "alice@example.com", "issue.create", "project:acme/internal"), Code.ALLOWED)
    f.projects["acme/internal"].issues_access_level = "disabled"
    itest.expect_code(check(c, "alice@example.com", "issue.create", "project:acme/internal"), Code.DENIED)


def test_account_state_handling() -> None:
    f = new_fake()

    def mk(uid: int, state: str) -> FakeUser:
        return FakeUser(id=uid, username=f"u{uid}", state=state, email=f"u{uid}@example.com")

    states = {40: "", 41: "deactivated", 42: "ldap_blocked", 43: "banned", 44: "blocked_pending_approval", 45: "blocked", 46: "something_new"}
    for uid, st in states.items():
        u = mk(uid, st)
        f.users.append(u)
        f.member("acme/webapp", u, LEVEL_OWNER)
    _, c = setup(f)
    for uid in [41, 42, 43, 44, 45]:
        d = check(c, f"u{uid}@example.com", "project.read", "project:acme/webapp")
        itest.expect_code(d, Code.DENIED)
        assert states[uid] in d.text, d.text
    # Empty or unrecognised state: hallpass cannot tell, so unknown.
    for uid in [40, 46]:
        d = check(c, f"u{uid}@example.com", "project.read", "project:acme/webapp")
        itest.expect_code(d, Code.UNSUPPORTED)


def test_email_domains_spaced_list() -> None:
    """`acme.com, acme.io` (with the space) is one list of two domains, and
    an upper-case entry matches the lower-case email."""
    f = new_fake()
    f.admin = False
    f.member("acme/webapp", bob, LEVEL_DEVELOPER)
    _, c = setup(f, {"identity_mode": "template", "username_template": "{local}", "email_domains": "Acme.com, acme.io"})
    itest.expect_code(check(c, "bob@acme.io", "mr.create", "project:acme/webapp"), Code.ALLOWED)
    itest.expect_code(check(c, "bob@acme.com", "mr.create", "project:acme/webapp"), Code.ALLOWED)
    itest.expect_code(check(c, "bob@acme.org", "mr.create", "project:acme/webapp"), Code.UNSUPPORTED)


def test_template_domain_allowlist() -> None:
    f = new_fake()
    f.admin = False
    f.member("acme/webapp", root, LEVEL_OWNER)
    f.member("acme/webapp", bob, LEVEL_DEVELOPER)
    _, c = setup(f, {"identity_mode": "template", "username_template": "{local}", "email_domains": "acme.com,acme.io"})
    # A listed domain resolves through the template.
    itest.expect_code(check(c, "bob@acme.io", "mr.create", "project:acme/webapp"), Code.ALLOWED)
    itest.expect_code(check(c, "bob@ACME.com", "mr.create", "project:acme/webapp"), Code.ALLOWED)
    # root@attacker.example must not become the root account: unknown, not a lookup.
    d = check(c, "root@attacker.example", "project.delete", "project:acme/webapp")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "domain not allowed for template identities" in d.text, d.text
    for e in ["root@sub.acme.com", "root@acme.com.evil", "root@acme.comm", "root", "root@"]:
        itest.expect_code(check(c, e, "project.delete", "project:acme/webapp"), Code.UNSUPPORTED)
    # With an administrator's token the account's email is visible and must
    # equal the request email.
    f.admin = True
    itest.expect_code(check(c, "bob@acme.com", "mr.create", "project:acme/webapp"), Code.USER_NOT_FOUND)
    f.users.append(FakeUser(id=50, username="eve", state="active", email="Eve@Acme.com"))
    f.member("acme/webapp", FakeUser(id=50), LEVEL_DEVELOPER)
    itest.expect_code(check(c, "eve@acme.com", "mr.create", "project:acme/webapp"), Code.ALLOWED)


# -- Python-only: decoding follows Go's typed structs --


def test_decode_semantics() -> None:
    """Go: the user struct decoding (json.Unmarshal into typed fields and
    secondaryEmail.UnmarshalJSON) — not a Go test of its own; covers the
    shapes the Go decoder accepts and refuses, which the port reimplements."""
    from hallpass.integrations.gitlab import _secondary_email, _user

    assert _secondary_email(None) == _secondary_email("")
    assert _secondary_email({"email": "a@b", "confirmed_at": None}).confirmed is False
    assert _secondary_email({"email": "a@b", "confirmed_at": False}).confirmed is True
    assert _secondary_email({"email": None}).email == ""
    for bad in [1, [], True, {"email": 1}]:
        with pytest.raises(ValueError):
            _secondary_email(bad)
    assert _user(None).id == 0
    for bad_user in [{"id": "7"}, {"id": 1.5}, {"is_admin": "yes"}, {"emails": "x"}, [1]]:
        with pytest.raises(ValueError):
            _user(bad_user)
