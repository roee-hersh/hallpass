"""Port of internal/integrations/confluence/confluence_test.go."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest

from hallpass.core.catalog import parse_resource
from hallpass.core.context import Context, background
from hallpass.core.decision import Code, Decision, to_decision
from hallpass.core.integration import CheckRequest, Connection, Identity, ProbeResult, User, find_action, validate_fields
from hallpass.core.secret import Secret
from hallpass.integrations.confluence import Confluence
from hallpass.integrations.confluence.confluence import next_path
from hallpass.integrations.jira import MODE_BASIC, MODE_SCOPED_TOKEN, Jira
from hallpass.integrations.jira import site as jira_site
from tests import harness as itest
from tests.harness.spec import SpecOptions, any_spec, spec_from_env

CLOUD_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _spec() -> Any:
    return any_spec(spec_from_env("confluence-v1"), spec_from_env("confluence-v2"), spec_from_env("jira"))


SPEC_OPTIONS = SpecOptions(strip_prefix=[r"/ex/(confluence|jira)/[^/]+"], ignore_paths=[r"^/_edge/tenant_info$", r"/oauth/token$"])


@dataclass(frozen=True)
class Principal:
    typ: str
    id: str


@dataclass(frozen=True)
class Grant:
    principal: Principal
    op: str
    target: str


@dataclass(frozen=True)
class Group:
    id: str
    name: str


def write_json(w: itest.ResponseWriter, status: int, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write(json.dumps(v) + "\n")


def basic(user: str, pw: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


def _atoi(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return 0


class FakeSite:
    """One fake Atlassian site serving Jira's user search (for the identity
    connection) and Confluence's content, space and group APIs."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.conf_mode = MODE_BASIC
        self.page_size = 1
        self.users: list[dict[str, Any]] = [
            {"accountId": "acc-dana", "accountType": "atlassian", "active": True, "emailAddress": "dana@example.com", "displayName": "Dana"},
            {"accountId": "acc-bob", "accountType": "atlassian", "active": True, "emailAddress": "bob@example.com", "displayName": "Bob"},
        ]
        # id -> accountId -> operations
        self.content: dict[str, dict[str, list[str]]] = {
            "100": {"acc-dana": ["read", "update", "delete"], "acc-bob": ["read"]},
            "200": {"acc-dana": ["read", "update", "delete"]},
        }
        self.spaces = {"DEV": "98307", "OPS": "98308", "PUB": "98309"}  # key -> id
        # accountId -> groups
        self.memberships: dict[str, list[Group]] = {
            "acc-dana": [Group("grp-a", "alpha"), Group("grp-b", "beta"), Group("grp-eng", "engineering")],
            "acc-bob": [Group("grp-x", "xray")],
        }
        self.check_status = 0  # injected status for the content permission check
        self.check_errors = False  # the content permission check answers false with a non-empty errors list
        self.perm_pages = 0
        self.member_pages = 0
        self.perm_calls = 0
        self.memberof_call = 0
        dana = Principal("user", "acc-dana")
        dev = [
            Grant(dana, op, target)
            for op, target in (
                ("read", "space"),
                ("create", "page"),
                ("create", "blogpost"),
                ("create", "comment"),
                ("create", "attachment"),
                ("export", "space"),
                ("restrict_content", "space"),
                ("administer", "space"),
            )
        ]
        dev += [
            Grant(Principal("group", "grp-eng"), "read", "space"),
            Grant(Principal("group", "grp-eng"), "create", "page"),
            Grant(Principal("group", "grp-x"), "read", "space"),
        ]
        # space id -> grants
        self.space_grants: dict[str, list[Grant]] = {
            "98307": dev,
            "98308": [
                Grant(Principal("group", "grp-ops"), "create", "page"),
                Grant(Principal("group", "grp-ops"), "read", "space"),
                Grant(Principal("role", "site-admins"), "administer", "space"),
                Grant(Principal("role", "site-admins"), "read", "space"),
                Grant(Principal("user", "acc-bob"), "read", "space"),
            ],
            # PUB: anonymous read, a group nobody here is in for create/page
            "98309": [
                Grant(Principal("anonymous", ""), "read", "space"),
                Grant(Principal("group", "grp-pub"), "create", "page"),
            ],
        }

    def handler(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        path = r.path
        if path == "/_edge/tenant_info":
            write_json(w, 200, {"cloudId": CLOUD_ID})
            return
        # Jira side: the identity connection always uses basic auth.
        if path == "/rest/api/3/user/search":
            if r.header.get("Authorization") != basic("jirabot@example.com", itest.CANARY + "jira"):
                write_json(w, 401, {"errorMessages": ["unauthorized " + itest.CANARY]})
                return
            q = r.q("query").lower()
            write_json(w, 200, [u for u in self.users if q in u["emailAddress"].lower()])
            return
        # Confluence side.
        if self.conf_mode != MODE_BASIC:
            prefix = "/ex/confluence/" + CLOUD_ID
            if not path.startswith(prefix + "/wiki/"):
                self.errors.append(f"token mode request outside the gateway: {path}")
                w.write_header(404)
                return
            path = path.removeprefix(prefix)
        want_auth = basic("confbot@example.com", itest.CANARY + "conf")
        if self.conf_mode == MODE_SCOPED_TOKEN:
            want_auth = "Bearer " + itest.CANARY + "scoped"
        if r.header.get("Authorization") != want_auth:
            write_json(w, 401, {"message": "unauthorized " + itest.CANARY})
            return
        if path.startswith("/wiki/rest/api/content/") and path.endswith("/permission/check") and r.method == "POST":
            if self.check_status != 0:
                write_json(w, self.check_status, {"message": "injected " + itest.CANARY})
                return
            cid = path.removeprefix("/wiki/rest/api/content/").removesuffix("/permission/check")
            perms = self.content.get(cid)
            if perms is None:
                write_json(w, 404, {"message": "No content found with id: " + cid})
                return
            try:
                req = json.loads(r.body)
            except ValueError:
                req = {}
            subject = req.get("subject") or {}
            if subject.get("type") != "user":
                self.errors.append(f"subject type {subject.get('type')!r}")
            has = req.get("operation") in perms.get(subject.get("identifier", ""), [])
            out: dict[str, Any] = {"hasPermission": has, "errors": []}
            if not has and self.check_errors:
                out["errors"] = [{"message": {"key": "injected " + itest.CANARY, "args": []}}]
            write_json(w, 200, out)
        elif path == "/wiki/api/v2/spaces":
            key = r.q("keys")
            results = []
            if key in self.spaces:
                results.append({"id": self.spaces[key], "key": key, "name": "Space " + key})
            write_json(w, 200, {"results": results, "_links": {}})
        elif path.startswith("/wiki/api/v2/spaces/") and path.endswith("/permissions"):
            self.perm_calls += 1
            sid = path.removeprefix("/wiki/api/v2/spaces/").removesuffix("/permissions")
            grants = self.space_grants.get(sid)
            if grants is None:
                write_json(w, 404, {"message": "not found"})
                return
            cursor = _atoi(r.q("cursor"))
            end = min(cursor + self.page_size, len(grants))
            results = [
                {
                    "id": str(cursor + i),
                    "principal": {"type": g.principal.typ, "id": g.principal.id},
                    "operation": {"key": g.op, "targetType": g.target},
                }
                for i, g in enumerate(grants[cursor:end])
            ]
            links: dict[str, Any] = {}
            if end < len(grants):
                self.perm_pages += 1
                links["next"] = f"/wiki/api/v2/spaces/{sid}/permissions?cursor={end}&limit={self.page_size}"
            write_json(w, 200, {"results": results, "_links": links})
        elif path == "/wiki/rest/api/user/memberof":
            self.memberof_call += 1
            acc = r.q("accountId")
            groups = self.memberships.get(acc, [])
            start = _atoi(r.q("start"))
            end = min(start + self.page_size, len(groups))
            results = [{"type": "group", "id": g.id, "name": g.name} for g in groups[start:end]]
            links = {"base": "https://example.atlassian.net/wiki"}
            if end < len(groups):
                self.member_pages += 1
                # v1 links are relative to {url}/wiki
                links["next"] = f"/rest/api/user/memberof?accountId={acc}&start={end}&limit={self.page_size}"
            write_json(w, 200, {"results": results, "start": start, "limit": self.page_size, "size": len(results), "_links": links})
        elif path == "/wiki/rest/api/user/current":
            write_json(w, 200, {"type": "known", "accountId": "acc-confbot", "displayName": "confluence bot"})
        else:
            write_json(w, 404, {"message": "no route " + path})


class _Servers:
    """Servers made by a test, closed and checked when it ends (Go:
    itest.NewServer's cleanup)."""

    def __init__(self) -> None:
        self.servers: list[itest.Server] = []
        self.fakes: list[FakeSite] = []

    def server(self) -> itest.Server:
        srv = itest.Server()
        srv.use_spec(_spec(), SPEC_OPTIONS)
        self.servers.append(srv)
        return srv

    def close(self) -> None:
        for srv in self.servers:
            srv.close()
        for f in self.fakes:
            assert not f.errors, "\n".join(f.errors)
        for srv in self.servers:
            assert not srv.spec_errors, "requests did not match the API description:\n" + "\n".join(srv.spec_errors)


@pytest.fixture
def servers() -> Iterator[_Servers]:
    s = _Servers()
    yield s
    s.close()


Setup = Callable[[FakeSite, bool], tuple[itest.Server, Connection]]


@pytest.fixture
def setup(servers: _Servers, monkeypatch: pytest.MonkeyPatch) -> Setup:
    def make(f: FakeSite, with_identity: bool) -> tuple[itest.Server, Connection]:
        """A jira connection and a confluence connection against one fake
        site. with_identity False leaves identity_connection unset."""
        srv = servers.server()
        servers.fakes.append(f)
        srv.handle("", "*", f.handler)
        monkeypatch.setattr(jira_site, "GATEWAY", srv.url)
        monkeypatch.setattr(jira_site, "TOKEN_URL", srv.url + "/oauth/token")

        js = itest.settings("jira-1", "jira", {"url": srv.url, "auth_mode": "basic", "username": "jirabot@example.com"}, {"credential": itest.literal("jira")})
        deps, _ = itest.deps(srv)
        jc = Jira().new(background(), js, deps)

        def connection(id: str) -> Connection:
            if id != "jira-1":
                raise ValueError(f'no connection "{id}"')
            return jc

        deps.connection = connection
        values = {"url": srv.url, "auth_mode": f.conf_mode}
        cred = Secret()
        if f.conf_mode == MODE_BASIC:
            values["username"] = "confbot@example.com"
            cred = itest.literal("conf")
        elif f.conf_mode == MODE_SCOPED_TOKEN:
            cred = itest.literal("scoped")
        if with_identity:
            values["identity_connection"] = "jira-1"
        cs = itest.settings("conf-1", "confluence", values, {"credential": cred})
        c = Confluence().new(background(), cs, deps)
        assert len(srv.calls()) == 0, "new touched the network"
        return srv, c

    return make


dana = User(email="dana@example.com")
bob = User(email="bob@example.com")


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, Confluence(), u, action, resource)


def test_fields_valid() -> None:
    validate_fields(Confluence().fields())
    ref = any(f.name == "identity_connection" and f.ref == "jira" and not f.required for f in Confluence().fields())
    assert ref, "identity_connection must be an optional ref to jira"


class FakeConn(Connection):
    def resolve_identity(self, ctx: Context, u: User) -> Identity:
        return Identity()

    def check(self, ctx: Context, r: CheckRequest) -> Decision:
        return Decision()

    def probe(self, ctx: Context) -> ProbeResult:
        return ProbeResult()


def test_new_rejects_wrong_identity_connection(servers: _Servers) -> None:
    srv = servers.server()
    deps, _ = itest.deps(srv, connection=lambda _id: FakeConn())
    s = itest.settings("c", "confluence", {"url": srv.url, "username": "x@example.com", "identity_connection": "k8s"}, {"credential": itest.literal("x")})
    with pytest.raises(Exception, match="not a jira connection"):
        Confluence().new(background(), s, deps)


def test_no_identity_connection(setup: Setup) -> None:
    srv, c = setup(FakeSite(), False)
    d = check(c, dana, "page.read", "page:100")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "identity_connection" in d.text, d.text
    assert len(srv.calls()) == 0, "no upstream call expected without an identity"
    r = c.probe(background())
    assert len(r.warnings) == 2 and "identity_connection" in r.warnings[0], r


def test_content_check(setup: Setup) -> None:
    srv, c = setup(FakeSite(), True)
    d = check(c, dana, "page.update", "page:100")
    itest.expect_code(d, Code.ALLOWED)
    calls = srv.calls()
    assert (
        len(calls) == 2
        and calls[0].path == "/rest/api/3/user/search"
        and calls[1].path == "/wiki/rest/api/content/100/permission/check"
        and calls[1].method == "POST"
    ), f"calls {calls}"
    assert calls[1].header.get("Authorization").startswith("Basic "), f"Authorization {calls[1].header.get('Authorization')!r}"
    req = calls[1].json()
    assert req["subject"]["type"] == "user" and req["subject"]["identifier"] == "acc-dana" and req["operation"] == "update", f"body {calls[1].body!r}"
    itest.expect_code(check(c, bob, "page.update", "page:100"), Code.DENIED)
    itest.expect_code(check(c, bob, "page.read", "page:100"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "blogpost.delete", "blogpost:200"), Code.ALLOWED)
    itest.expect_code(check(c, bob, "blogpost.read", "blogpost:200"), Code.DENIED)
    itest.expect_code(check(c, dana, "page.read", "page:999"), Code.RESOURCE_NOT_VISIBLE)
    itest.expect_code(check(c, User(email="nobody@example.com"), "page.read", "page:100"), Code.USER_NOT_FOUND)


def test_content_forbidden(setup: Setup) -> None:
    f = FakeSite()
    _, c = setup(f, True)
    f.check_status = 403
    d = check(c, dana, "page.read", "page:100")
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)
    assert "Confluence Administrator" in d.text, d.text


def test_space_user_principal(setup: Setup) -> None:
    f = FakeSite()
    srv, c = setup(f, True)
    d = check(c, dana, "space.export", "space:DEV")
    itest.expect_code(d, Code.ALLOWED)
    assert f.memberof_call == 0, "a direct user grant should not fetch groups"
    saw_spaces = saw_perms = False
    for call in srv.calls():
        if call.path == "/wiki/api/v2/spaces":
            saw_spaces = True
            assert call.q("keys") == "DEV", f"spaces query {call.query}"
        elif call.path == "/wiki/api/v2/spaces/98307/permissions":
            saw_perms = True
    assert saw_spaces and saw_perms, f"calls {srv.calls()}"
    itest.expect_code(check(c, dana, "space.export", "space:NOPE"), Code.RESOURCE_NOT_VISIBLE)


def test_space_group_principal_with_pagination(setup: Setup) -> None:
    f = FakeSite()
    _, c = setup(f, True)
    # dana holds create/page on DEV both directly and via grp-eng; remove the
    # direct grants so the group path is what allows.
    f.space_grants["98307"] = [g for g in f.space_grants["98307"] if g.principal.typ != "user"]
    d = check(c, dana, "page.create", "space:DEV")
    itest.expect_code(d, Code.ALLOWED)
    assert "engineering" in d.text, d.text
    assert f.perm_pages >= 1 and f.member_pages >= 2, f"expected pagination: permission pages {f.perm_pages}, member pages {f.member_pages}"
    assert f.memberof_call >= 3, f"memberof pages fetched {f.memberof_call}, want 3 (grp-eng is the third group)"
    # bob is in grp-x, which has read/space but not create/page
    itest.expect_code(check(c, bob, "page.create", "space:DEV"), Code.DENIED)
    itest.expect_code(check(c, bob, "space.read", "space:DEV"), Code.ALLOWED)
    # no grant at all for the operation: deny without a group lookup
    f.memberof_call = 0
    itest.expect_code(check(c, bob, "blogpost.create", "space:DEV"), Code.DENIED)
    assert f.memberof_call == 0, "no group principal for the operation, so no memberof call expected"


def test_space_unknown_principal(setup: Setup) -> None:
    f = FakeSite()
    _, c = setup(f, True)
    # OPS: administer/space is granted to a role only
    d = check(c, dana, "space.admin", "space:OPS")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "role" in d.text, d.text
    # read/space: a role and bob directly; dana is neither -> unsupported, bob -> allow
    itest.expect_code(check(c, dana, "space.read", "space:OPS"), Code.UNSUPPORTED)
    itest.expect_code(check(c, bob, "space.read", "space:OPS"), Code.ALLOWED)
    # create/page: a group dana is not in, but administer/space is held by a
    # role, whose members hold every operation -> unsupported, not deny
    itest.expect_code(check(c, dana, "page.create", "space:OPS"), Code.UNSUPPORTED)
    # export/space: no grant at all, yet the role's administer/space -> unsupported
    itest.expect_code(check(c, dana, "space.export", "space:OPS"), Code.UNSUPPORTED)
    # without the role's administer/space, the create/page and export/space answers are deny
    f.space_grants["98308"] = [g for g in f.space_grants["98308"] if not (g.principal.typ == "role" and g.op == "administer")]
    itest.expect_code(check(c, dana, "page.create", "space:OPS"), Code.DENIED)
    itest.expect_code(check(c, dana, "space.export", "space:OPS"), Code.DENIED)
    itest.expect_code(check(c, dana, "space.read", "space:OPS"), Code.UNSUPPORTED)


def test_content_check_errors(setup: Setup) -> None:
    """hasPermission false with a non-empty errors list means Confluence
    could not evaluate the check, which is unknown, not deny."""
    f = FakeSite()
    _, c = setup(f, True)
    f.check_errors = True
    d = check(c, bob, "page.update", "page:100")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "error" in d.text, d.text
    itest.assert_no_canary(d.text)
    # a positive answer is allow whatever the errors list says
    itest.expect_code(check(c, dana, "page.update", "page:100"), Code.ALLOWED)
    f.check_errors = False
    itest.expect_code(check(c, bob, "page.update", "page:100"), Code.DENIED)


def test_space_administer_implies_all(setup: Setup) -> None:
    """A holder of administer/space, directly or through a group, holds
    every space operation."""
    f = FakeSite()
    _, c = setup(f, True)
    # DEV: keep only dana's administer/space among her direct grants
    kept = [g for g in f.space_grants["98307"] if g.principal.typ != "user" or g.op == "administer"]
    f.space_grants["98307"] = kept
    for a in ("space.read", "page.create", "blogpost.create", "comment.create", "attachment.create", "space.export", "page.restrict", "space.admin"):
        d = check(c, dana, a, "space:DEV")
        itest.expect_code(d, Code.ALLOWED)
        if a != "space.admin":
            assert "space administrator" in d.text, f"{a}: {d.text}"
    assert f.memberof_call == 0, "a direct administer grant should not fetch groups"
    # bob is not an administrator: blogpost.create is still a deny
    itest.expect_code(check(c, bob, "blogpost.create", "space:DEV"), Code.DENIED)

    # administer/space through a group: grp-eng, which dana is in and bob is not
    kept = [g for g in f.space_grants["98307"] if g.principal.typ != "user"]
    f.space_grants["98307"] = [*kept, Grant(Principal("group", "grp-eng"), "administer", "space")]
    d = check(c, dana, "space.export", "space:DEV")
    itest.expect_code(d, Code.ALLOWED)
    assert "space administrator" in d.text and "engineering" in d.text, d.text
    itest.expect_code(check(c, bob, "space.export", "space:DEV"), Code.DENIED)


def test_space_anonymous_grant(setup: Setup) -> None:
    """An anonymous (or any non user/group) grant for the operation is
    unknown when nothing else allows, never deny; operations nobody holds
    stay deny."""
    f = FakeSite()
    _, c = setup(f, True)
    d = check(c, dana, "space.read", "space:PUB")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "anonymous" in d.text, d.text
    itest.expect_code(check(c, bob, "space.read", "space:PUB"), Code.UNSUPPORTED)
    # create/page is granted to a group neither is in, and administer/space to nobody
    itest.expect_code(check(c, dana, "page.create", "space:PUB"), Code.DENIED)
    itest.expect_code(check(c, dana, "space.export", "space:PUB"), Code.DENIED)
    # administer/space granted anonymously: every operation is unknown now,
    # since an administrator holds them all and hallpass cannot resolve who
    f.space_grants["98309"].append(Grant(Principal("anonymous", ""), "administer", "space"))
    for a in ("page.create", "space.export", "space.admin"):
        d = check(c, dana, a, "space:PUB")
        itest.expect_code(d, Code.UNSUPPORTED)
        assert "anonymous" in d.text, f"{a}: {d.text}"
    # a direct grant still wins over the anonymous one
    f.space_grants["98309"].append(Grant(Principal("user", "acc-bob"), "read", "space"))
    itest.expect_code(check(c, bob, "space.read", "space:PUB"), Code.ALLOWED)


def test_space_key_exact_match(setup: Setup) -> None:
    """The space is the one whose key equals the request exactly; a case
    variant or several hits is unknown, never another space's answer."""
    f = FakeSite()
    srv, c = setup(f, True)
    # Confluence answers the lookup for "dev" with DEV
    srv.json("GET", "/wiki/api/v2/spaces", 200, '{"results":[{"id":"98307","key":"DEV","name":"Space DEV"}],"_links":{}}')
    d = check(c, dana, "space.export", "space:dev")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "exact" in d.text, d.text
    assert f.perm_calls == 0, "no permission list must be read for a space that did not match exactly"
    # several exact hits
    srv.json("GET", "/wiki/api/v2/spaces", 200, '{"results":[{"id":"98307","key":"DEV"},{"id":"98308","key":"DEV"}],"_links":{}}')
    d = check(c, dana, "space.export", "space:DEV")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "2 spaces" in d.text and f.perm_calls == 0, f"{d.text} (perm calls {f.perm_calls})"
    # one exact hit next to a variant: the exact one is used
    srv.json("GET", "/wiki/api/v2/spaces", 200, '{"results":[{"id":"98308","key":"dev"},{"id":"98307","key":"DEV"}],"_links":{}}')
    itest.expect_code(check(c, dana, "space.export", "space:DEV"), Code.ALLOWED)
    # no hit at all
    srv.json("GET", "/wiki/api/v2/spaces", 200, '{"results":[],"_links":{}}')
    itest.expect_code(check(c, dana, "space.export", "space:DEV"), Code.RESOURCE_NOT_VISIBLE)


def test_space_forbidden(setup: Setup) -> None:
    srv, c = setup(FakeSite(), True)
    srv.json("GET", "/wiki/api/v2/spaces/98307/permissions", 403, '{"message":"forbidden"}')
    itest.expect_code(check(c, dana, "space.export", "space:DEV"), Code.CREDENTIAL_REJECTED)
    srv.json("GET", "/wiki/api/v2/spaces", 404, '{"message":"gone"}')
    itest.expect_code(check(c, dana, "space.export", "space:DEV"), Code.RESOURCE_NOT_VISIBLE)


def test_scoped_token_base(setup: Setup) -> None:
    f = FakeSite()
    f.conf_mode = MODE_SCOPED_TOKEN
    srv, c = setup(f, True)
    itest.expect_code(check(c, dana, "page.read", "page:100"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "page.create", "space:DEV"), Code.ALLOWED)
    tenant = 0
    for call in srv.calls():
        if call.path == "/_edge/tenant_info":
            tenant += 1
        elif call.path == "/rest/api/3/user/search":
            pass
        else:
            assert call.path.startswith("/ex/confluence/" + CLOUD_ID + "/wiki/") and call.header.get("Authorization") == "Bearer " + itest.CANARY + "scoped", (
                f"{call.path} {call.header.get('Authorization')!r}"
            )
    assert tenant == 1, f"tenant_info called {tenant} times"


@pytest.mark.parametrize(
    ("inp", "want"),
    [
        ("", ""),
        ("/wiki/api/v2/spaces/1/permissions?cursor=x", "/wiki/api/v2/spaces/1/permissions?cursor=x"),
        ("/rest/api/user/memberof?start=1", "/wiki/rest/api/user/memberof?start=1"),
        ("rest/api/user/memberof?start=1", "/wiki/rest/api/user/memberof?start=1"),
        ("https://acme.atlassian.net/wiki/api/v2/x?c=1", "/wiki/api/v2/x?c=1"),
        ("https://api.atlassian.com/ex/confluence/abc/wiki/api/v2/x?c=1", "/wiki/api/v2/x?c=1"),
    ],
)
def test_next_path(inp: str, want: str) -> None:
    got = next_path(inp)
    assert got == want, f"next_path({inp!r}) = {got!r}, want {want!r}"


@pytest.mark.parametrize(
    ("action", "resource"),
    [
        ("page.read", "space:DEV"),
        ("page.read", "blogpost:200"),
        ("blogpost.read", "page:100"),
        ("space.read", "page:100"),
        ("page.create", "page:100"),
        ("page.read", "page:abc"),
        ("page.read", "page:0"),
        ("page.read", "page:100/x"),
        ("space.read", "space:bad key"),
        ("space.read", "space:"),
        ("page.read", "global"),
    ],
)
def test_invalid_requests(setup: Setup, action: str, resource: str) -> None:
    srv, c = setup(FakeSite(), True)
    srv.reset()
    d = check(c, dana, action, resource)
    assert d.code == Code.INVALID_REQUEST, f"{action} {resource} -> {d.code}: {d.text}"
    for call in srv.calls():
        assert call.path == "/rest/api/3/user/search", f"{action} {resource} reached upstream: {call.path}"


def test_failures(setup: Setup) -> None:
    srv, c = setup(FakeSite(), True)
    itest.failure_cases(srv, lambda: check(c, dana, "page.read", "page:100"))


def test_failures_after_identity(servers: _Servers) -> None:
    """Identity resolved first, then the Confluence call fails."""
    f = FakeSite()
    servers.fakes.append(f)
    srv = servers.server()
    srv.handle("", "*", f.handler)
    deps, _ = itest.deps(srv)
    js = itest.settings("jira-1", "jira", {"url": srv.url, "username": "jirabot@example.com"}, {"credential": itest.literal("jira")})
    jc = Jira().new(background(), js, deps)
    ident = jc.resolve_identity(background(), dana)
    deps.connection = lambda _id: jc
    cs = itest.settings(
        "conf-1", "confluence", {"url": srv.url, "username": "confbot@example.com", "identity_connection": "jira-1"}, {"credential": itest.literal("conf")}
    )
    c = Confluence().new(background(), cs, deps)
    act = find_action(Confluence(), "space.export")
    assert act is not None

    def run() -> Decision:
        res = parse_resource("space:DEV")
        try:
            return c.check(background(), CheckRequest(user=dana, identity=ident, action=act, action_name="space.export", resource=res))
        except Exception as e:
            return to_decision(e)

    itest.failure_cases(srv, run)


def test_probe(setup: Setup) -> None:
    srv, c = setup(FakeSite(), True)
    r = c.probe(background())
    assert "confluence bot" in r.summary and len(r.warnings) == 1 and "Confluence Administrator" in r.warnings[0], r
    assert srv.last_call().path == "/wiki/rest/api/user/current", srv.last_call().path
    srv.fail(itest.Failure.UNAUTHORIZED)
    try:
        c.probe(background())
        d = None
    except Exception as e:
        d = to_decision(e)
    srv.fail(itest.Failure.NONE)
    assert d is not None, "probe succeeded"
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)


# Allow/deny tests per action (coverage gate). Dana holds everything on page
# 100, blog post 200 and space DEV; Bob holds page.read on 100 and, through
# grp-x, space.read on DEV.


def allow(setup: Setup, action: str, resource: str) -> None:
    _, c = setup(FakeSite(), True)
    itest.expect_code(check(c, dana, action, resource), Code.ALLOWED)


def deny(setup: Setup, action: str, resource: str) -> None:
    _, c = setup(FakeSite(), True)
    itest.expect_code(check(c, bob, action, resource), Code.DENIED)


def test_action_page_read_allow(setup: Setup) -> None:
    allow(setup, "page.read", "page:100")


def test_action_page_read_deny(setup: Setup) -> None:
    deny(setup, "page.read", "page:200")


def test_action_page_update_allow(setup: Setup) -> None:
    allow(setup, "page.update", "page:100")


def test_action_page_update_deny(setup: Setup) -> None:
    deny(setup, "page.update", "page:100")


def test_action_page_delete_allow(setup: Setup) -> None:
    allow(setup, "page.delete", "page:100")


def test_action_page_delete_deny(setup: Setup) -> None:
    deny(setup, "page.delete", "page:100")


def test_action_blogpost_read_allow(setup: Setup) -> None:
    allow(setup, "blogpost.read", "blogpost:200")


def test_action_blogpost_read_deny(setup: Setup) -> None:
    deny(setup, "blogpost.read", "blogpost:200")


def test_action_blogpost_update_allow(setup: Setup) -> None:
    allow(setup, "blogpost.update", "blogpost:200")


def test_action_blogpost_update_deny(setup: Setup) -> None:
    deny(setup, "blogpost.update", "blogpost:200")


def test_action_blogpost_delete_allow(setup: Setup) -> None:
    allow(setup, "blogpost.delete", "blogpost:200")


def test_action_blogpost_delete_deny(setup: Setup) -> None:
    deny(setup, "blogpost.delete", "blogpost:200")


def test_action_space_read_allow(setup: Setup) -> None:
    allow(setup, "space.read", "space:DEV")


def test_action_space_read_deny(setup: Setup) -> None:
    # DEV grants read/space to grp-x (Bob's group); without it Bob has no read.
    f = FakeSite()
    f.space_grants["98307"] = [g for g in f.space_grants["98307"] if g.principal.id != "grp-x"]
    _, c = setup(f, True)
    itest.expect_code(check(c, bob, "space.read", "space:DEV"), Code.DENIED)


def test_action_page_create_allow(setup: Setup) -> None:
    allow(setup, "page.create", "space:DEV")


def test_action_page_create_deny(setup: Setup) -> None:
    deny(setup, "page.create", "space:DEV")


def test_action_blogpost_create_allow(setup: Setup) -> None:
    allow(setup, "blogpost.create", "space:DEV")


def test_action_blogpost_create_deny(setup: Setup) -> None:
    deny(setup, "blogpost.create", "space:DEV")


def test_action_comment_create_allow(setup: Setup) -> None:
    allow(setup, "comment.create", "space:DEV")


def test_action_comment_create_deny(setup: Setup) -> None:
    deny(setup, "comment.create", "space:DEV")


def test_action_attachment_create_allow(setup: Setup) -> None:
    allow(setup, "attachment.create", "space:DEV")


def test_action_attachment_create_deny(setup: Setup) -> None:
    deny(setup, "attachment.create", "space:DEV")


def test_action_space_export_allow(setup: Setup) -> None:
    allow(setup, "space.export", "space:DEV")


def test_action_space_export_deny(setup: Setup) -> None:
    deny(setup, "space.export", "space:DEV")


def test_action_page_restrict_allow(setup: Setup) -> None:
    allow(setup, "page.restrict", "space:DEV")


def test_action_page_restrict_deny(setup: Setup) -> None:
    deny(setup, "page.restrict", "space:DEV")


def test_action_space_admin_allow(setup: Setup) -> None:
    allow(setup, "space.admin", "space:DEV")


def test_action_space_admin_deny(setup: Setup) -> None:
    deny(setup, "space.admin", "space:DEV")
