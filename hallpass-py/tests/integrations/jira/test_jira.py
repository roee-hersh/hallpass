"""Port of internal/integrations/jira/jira_test.go."""

from __future__ import annotations

import base64
import datetime
import json
import threading
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from hallpass.core.context import background
from hallpass.core.decision import Code, Decision, to_decision
from hallpass.core.integration import Connection, User, validate_fields
from hallpass.core.secret import Secret
from hallpass.integrations.jira import MODE_BASIC, MODE_OAUTH_CLIENT, MODE_SCOPED_TOKEN, Jira
from hallpass.integrations.jira import site as site_mod
from hallpass.integrations.jira.actions import ACTION_LIST
from tests import harness as itest
from tests.harness.spec import SpecOptions, spec_from_env

CLOUD_ID = "11111111-2222-3333-4444-555555555555"

SPEC_OPTIONS = SpecOptions(strip_prefix=[r"/ex/jira/[^/]+"], ignore_paths=[r"^/_edge/tenant_info$", r"/oauth/token$"])


def write_json(w: itest.ResponseWriter, status: int, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write(json.dumps(v) + "\n")


def _atoi(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return 0


class FakeJira:
    """The fake Jira Cloud site. Grants are per accountId: a permission key
    maps to targets "p:<projectId>", "i:<issueId>" or "g" (global)."""

    def __init__(self, mode: str) -> None:
        self.errors: list[str] = []
        self.mode = mode
        self.admin = True
        self.users: list[dict[str, Any]] = [
            {"accountId": "acc-dana", "accountType": "atlassian", "active": True, "emailAddress": "Dana@example.com", "displayName": "Dana"},
            {"accountId": "acc-bob", "accountType": "atlassian", "active": True, "emailAddress": "bob@example.com", "displayName": "Bob"},
            {"accountId": "acc-bob-old", "accountType": "atlassian", "active": False, "emailAddress": "bob@example.com", "displayName": "Bob (old)"},
            {"accountId": "acc-bot", "accountType": "app", "active": True, "emailAddress": "bob@example.com", "displayName": "Bot"},
            {"accountId": "acc-twin1", "accountType": "atlassian", "active": True, "emailAddress": "twin@example.com", "displayName": "Twin 1"},
            {"accountId": "acc-twin2", "accountType": "atlassian", "active": True, "emailAddress": "twin@example.com", "displayName": "Twin 2"},
            {"accountId": "acc-hidden", "accountType": "atlassian", "active": True, "emailAddress": "", "displayName": "Hidden"},
            {"accountId": "acc-hidden2", "accountType": "atlassian", "active": True, "emailAddress": "", "displayName": "Hidden 2"},
        ]
        self.projects = {"OPS": "10000", "SEC": "10001"}  # key -> id
        self.issues = {"OPS-1": ("10010", "10000"), "SEC-7": ("10020", "10001")}  # key -> issue id, project id
        self.grants: dict[str, dict[str, list[str]]] = {
            "acc-dana": {"*": ["p:10000", "i:10010", "g"]},
            "acc-bob": {"BROWSE_PROJECTS": ["p:10000", "i:10010"]},
        }
        self.check_status = 0  # injected status for permissions/check (0 = normal)
        self.echo_drop = False  # permissions/check omits the echo of the requested project permission
        self.known_perms = [a.name for a in ACTION_LIST]
        self.token_calls = 0
        self.tenant_calls = 0
        self.logs: itest.Logs | None = None

    def authorized(self, r: itest.Request) -> bool:
        h = r.header.get("Authorization")
        if self.mode == MODE_BASIC:
            return h == "Basic " + base64.b64encode(("bot@example.com:" + itest.CANARY + "jira").encode()).decode()
        if self.mode == MODE_SCOPED_TOKEN:
            return h == "Bearer " + itest.CANARY + "scoped"
        if self.mode == MODE_OAUTH_CLIENT:
            return h == "Bearer " + itest.CANARY + "access"
        return False

    def has(self, account: str, perm: str, target: str) -> bool:
        for key in ("*", perm):
            if target in self.grants.get(account, {}).get(key, []):
                return True
        return False

    def handler(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        path = r.path
        if path == "/_edge/tenant_info":
            self.tenant_calls += 1
            if r.header.get("Authorization") != "":
                self.errors.append("tenant_info was sent an Authorization header")
            write_json(w, 200, {"cloudId": CLOUD_ID})
            return
        if path == "/oauth/token":
            self.token_calls += 1
            try:
                body = json.loads(r.body)
            except ValueError:
                body = {}
            if body.get("grant_type") != "client_credentials" or body.get("client_id") != "cid-1" or body.get("audience") != "api.atlassian.com":
                self.errors.append(f"token body {body}")
            if body.get("client_secret") != itest.CANARY + "oauth":
                write_json(w, 401, {"error": "access_denied", "error_description": "Unauthorized " + itest.CANARY})
                return
            write_json(w, 200, {"access_token": itest.CANARY + "access", "expires_in": 3600, "token_type": "Bearer"})
            return
        if self.mode != MODE_BASIC:
            prefix = "/ex/jira/" + CLOUD_ID
            if not path.startswith(prefix + "/"):
                self.errors.append(f"token mode request outside the gateway: {path}")
                w.write_header(404)
                return
            path = path.removeprefix(prefix)
        if not self.authorized(r):
            write_json(w, 401, {"errorMessages": ["unauthorized " + itest.CANARY]})
            return
        if path == "/rest/api/3/user/search":
            q = r.q("query").lower()
            out = []
            for u in self.users:
                email = u["emailAddress"]
                name = u["displayName"]
                if q in email.lower() or q in name.lower() or (email == "" and q.startswith("hidden")):
                    out.append(u)
            # startAt/maxResults paging, as Jira does it.
            start_at = _atoi(r.q("startAt"))
            max_results = _atoi(r.q("maxResults"))
            if max_results <= 0:
                max_results = 50
            start_at = min(start_at, len(out))
            end = min(start_at + max_results, len(out))
            write_json(w, 200, out[start_at:end])
        elif path.startswith("/rest/api/3/project/"):
            key = path.removeprefix("/rest/api/3/project/")
            pid = self.projects.get(key)
            if pid is None:
                write_json(w, 404, {"errorMessages": ["No project could be found with key " + key]})
                return
            write_json(w, 200, {"id": pid, "key": key, "name": "Project " + key})
        elif path.startswith("/rest/api/3/issue/"):
            key = path.removeprefix("/rest/api/3/issue/")
            if r.q("fields") != "project":
                self.errors.append(f"issue lookup without fields=project: {r.raw_query}")
            iss = self.issues.get(key)
            if iss is None:
                write_json(w, 404, {"errorMessages": ["Issue does not exist"]})
                return
            write_json(w, 200, {"id": iss[0], "key": key, "fields": {"project": {"id": iss[1]}}})
        elif path == "/rest/api/3/permissions/check" and r.method == "POST":
            if self.check_status != 0:
                write_json(w, self.check_status, {"errorMessages": ["injected " + itest.CANARY]})
                return
            try:
                req = json.loads(r.body)
            except ValueError:
                req = {}
            account = req.get("accountId", "")
            out: dict[str, Any] = {"projectPermissions": [], "globalPermissions": []}
            pps = []
            for pp in req.get("projectPermissions") or []:
                for perm in pp.get("permissions") or []:
                    if self.echo_drop:
                        continue
                    entry: dict[str, Any] = {"permission": perm, "projects": [], "issues": []}
                    for p in pp.get("projects") or []:
                        if self.has(account, perm, f"p:{p}"):
                            entry["projects"].append(p)
                    for i in pp.get("issues") or []:
                        if self.has(account, perm, f"i:{i}"):
                            entry["issues"].append(i)
                    pps.append(entry)
            if pps:
                out["projectPermissions"] = pps
            gs = [g for g in req.get("globalPermissions") or [] if self.has(account, g, "g")]
            if gs:
                out["globalPermissions"] = gs
            write_json(w, 200, out)
        elif path == "/rest/api/3/myself":
            write_json(w, 200, {"accountId": "acc-hallpass", "displayName": "hallpass bot", "emailAddress": "bot@example.com"})
        elif path == "/rest/api/3/mypermissions":
            write_json(w, 200, {"permissions": {"ADMINISTER": {"havePermission": self.admin}}})
        elif path == "/rest/api/3/permissions":
            write_json(w, 200, {"permissions": {k: {"key": k} for k in self.known_perms}})
        else:
            write_json(w, 404, {"message": "no route " + path})


Env = tuple[itest.Server, FakeJira, Connection]
Setup = Callable[..., Env]


class _Servers:
    """Servers made by a test, closed and checked when it ends (Go:
    itest.NewServer's cleanup)."""

    def __init__(self) -> None:
        self.servers: list[itest.Server] = []
        self.fakes: list[FakeJira] = []

    def server(self) -> itest.Server:
        srv = itest.Server()
        srv.use_spec(spec_from_env("jira"), SPEC_OPTIONS)
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


@pytest.fixture
def setup(servers: _Servers, monkeypatch: pytest.MonkeyPatch) -> Setup:
    def make(mode: str, values: dict[str, str] | None = None, now: Callable[[], float] | None = None) -> Env:
        """setup with an optional injected clock (None for the wall clock)."""
        srv = servers.server()
        f = FakeJira(mode)
        servers.fakes.append(f)
        srv.handle("", "*", f.handler)
        deps, logs = itest.deps(srv, now=now)
        f.logs = logs
        monkeypatch.setattr(site_mod, "GATEWAY", srv.url)
        monkeypatch.setattr(site_mod, "TOKEN_URL", srv.url + "/oauth/token")
        v = {"url": srv.url, "auth_mode": mode}
        cred = Secret()
        if mode == MODE_BASIC:
            v["username"] = "bot@example.com"
            cred = itest.literal("jira")
        elif mode == MODE_SCOPED_TOKEN:
            cred = itest.literal("scoped")
        elif mode == MODE_OAUTH_CLIENT:
            v["client_id"] = "cid-1"
            cred = itest.literal("oauth")
        v.update(values or {})
        s = itest.settings("jira-1", "jira", v, {"credential": cred})
        c = Jira().new(background(), s, deps)
        return srv, f, c

    return make


dana = User(email="dana@example.com")
bob = User(email="bob@example.com")


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, Jira(), u, action, resource)


def resolve_err(c: Connection, u: User) -> Decision:
    try:
        c.resolve_identity(background(), u)
    except Exception as e:
        return to_decision(e)
    raise AssertionError(f"resolve_identity({u.email}) succeeded")


def probe_err(c: Connection) -> Decision:
    try:
        c.probe(background())
    except Exception as e:
        return to_decision(e)
    raise AssertionError("probe succeeded")


def test_fields_valid() -> None:
    validate_fields(Jira().fields())
    for a in Jira().actions():
        assert not a.pattern, f"{a.name}: pattern action unexpected"


def test_new_validation(servers: _Servers) -> None:
    srv = servers.server()
    deps, _ = itest.deps(srv)
    cases = [
        ("no credential", {"url": srv.url}, Secret()),
        ("basic without username", {"url": srv.url, "auth_mode": "basic"}, itest.literal("x")),
        ("oauth without client_id", {"url": srv.url, "auth_mode": "oauth_client"}, itest.literal("x")),
        ("bad mode", {"url": srv.url, "auth_mode": "pat"}, itest.literal("x")),
    ]
    for name, values, sec in cases:
        s = itest.settings("j", "jira", values, {"credential": sec})
        try:
            Jira().new(background(), s, deps)
        except Exception:
            continue
        pytest.fail(f"{name}: new accepted")
    assert len(srv.calls()) == 0, "new touched the network"


def test_identity(setup: Setup) -> None:
    srv, _, c = setup(MODE_BASIC)
    ctx = background()
    ident = c.resolve_identity(ctx, dana)
    assert ident.id == "acc-dana" and ident.display == "Dana", f"dana: {ident}"
    call = srv.last_call()
    assert call.path == "/rest/api/3/user/search" and call.q("query") == "dana@example.com" and call.q("maxResults") == "50" and call.q("startAt") == "0", (
        f"search call {call.path} {call.query}"
    )
    # inactive and app accounts with the same email are ignored
    ident = c.resolve_identity(ctx, bob)
    assert ident.id == "acc-bob", f"bob: {ident}"
    itest.expect_code(resolve_err(c, User(email="twin@example.com")), Code.USER_AMBIGUOUS)
    itest.expect_code(resolve_err(c, User(email="nobody@example.com")), Code.USER_NOT_FOUND)

    # hidden email: unknown, never a match, however many candidates
    d = resolve_err(c, User(email="hidden@example.com"))
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "hidden" in d.text, d.text

    # search forbidden: credential_rejected
    srv.json("GET", "/rest/api/3/user/search", 403, '{"errorMessages":["forbidden"]}')
    itest.expect_code(resolve_err(c, dana), Code.CREDENTIAL_REJECTED)


def test_identity_empty_email(setup: Setup) -> None:
    """A request without an email is a bad request, not a user that
    positively does not exist."""
    srv, _, c = setup(MODE_BASIC)
    for email in ("", "   "):
        itest.expect_code(resolve_err(c, User(email=email)), Code.INVALID_REQUEST)
    assert len(srv.calls()) == 0, "an empty email must not reach upstream"


def _spoof() -> dict[str, Any]:
    return {"accountId": "acc-spoof", "accountType": "atlassian", "active": True, "emailAddress": "", "displayName": "cfo@example.com"}


def _resolve(c: Connection, u: User) -> tuple[str, Decision | None]:
    try:
        return c.resolve_identity(background(), u).id, None
    except Exception as e:
        return "", to_decision(e)


def test_identity_display_name_spoof(setup: Setup) -> None:
    """user/search?query= also matches displayName, so an account named
    "cfo@example.com" is a candidate for that email. It must never be
    resolved as the CFO: with a hidden email it is unsupported, with a
    visible other email it is not found. The strict_email_match switch that
    used to accept a single hidden candidate is gone."""
    for f in Jira().fields():
        assert f.name != "strict_email_match", "strict_email_match must no longer be a connection key"
    _, f, c = setup(MODE_BASIC)
    f.users.append(_spoof())
    id_, d = _resolve(c, User(email="cfo@example.com"))
    assert d is not None
    itest.expect_code(d, Code.UNSUPPORTED)
    assert id_ == "" and "hidden" in d.text, f"{id_} {d.text}"
    # The same name with a visible, different email: plainly not the CFO.
    f.users[-1]["emailAddress"] = "impostor@example.com"
    id_, d = _resolve(c, User(email="cfo@example.com"))
    assert d is not None
    itest.expect_code(d, Code.USER_NOT_FOUND)
    assert id_ == ""
    # Explicitly asking for the old non-strict behaviour changes nothing.
    _, f2, c2 = setup(MODE_BASIC, {"strict_email_match": "false"})
    f2.users.append(_spoof())
    id_, d = _resolve(c2, User(email="cfo@example.com"))
    assert d is not None
    itest.expect_code(d, Code.UNSUPPORTED)
    assert id_ == ""


def crowd(n: int, query: str) -> list[dict[str, Any]]:
    """n active Atlassian accounts whose display name contains the query, so
    that a user search for it fills pages."""
    return [
        {
            "accountId": f"acc-crowd-{i}",
            "accountType": "atlassian",
            "active": True,
            "emailAddress": f"crowd-{i}@example.com",
            "displayName": f"Crowd {i} ({query})",
        }
        for i in range(n)
    ]


def search_calls(srv: itest.Server) -> list[int]:
    return [_atoi(call.q("startAt")) for call in srv.calls() if call.path == "/rest/api/3/user/search"]


def test_identity_pagination(setup: Setup) -> None:
    """The match on a later page is found; a match on the last page hallpass
    reads still wins even when that page is full."""
    srv, f, c = setup(MODE_BASIC)
    ctx = background()
    f.users = crowd(60, "dana@example.com") + f.users
    ident = c.resolve_identity(ctx, dana)
    assert ident.id == "acc-dana", f"dana on page 2: {ident}"
    starts = search_calls(srv)
    assert starts == [0, 50], f"search pages {starts}, want [0 50]"
    for call in srv.calls():
        assert call.q("maxResults") == "50", f"maxResults {call.q('maxResults')!r}"

    srv.reset()
    f.users = crowd(249, "dana@example.com") + f.users[60:]  # dana is result 250, the last slot of page 5
    ident = c.resolve_identity(ctx, dana)
    assert ident.id == "acc-dana", f"dana on a full page 5: {ident}"
    starts = search_calls(srv)
    assert len(starts) == 5, f"search pages {starts}, want 5"


def test_identity_too_many_candidates(setup: Setup) -> None:
    """Five full pages without an exact email match is unknown, since the
    user may sit on a page hallpass did not read."""
    srv, f, c = setup(MODE_BASIC)
    f.users = crowd(300, "nobody@example.com") + crowd(300, "hidden@example.com") + f.users
    d = resolve_err(c, User(email="nobody@example.com"))
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "too many candidates" in d.text, d.text
    starts = search_calls(srv)
    assert len(starts) == 5 and starts[4] == 200, f"search pages {starts}, want [0 50 100 150 200]"
    # hidden candidates on full pages are "too many", not "hidden"
    srv.reset()
    d = resolve_err(c, User(email="hidden@example.com"))
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "too many candidates" in d.text, d.text


def test_check_missing_permission_echo(setup: Setup) -> None:
    """A 200 whose projectPermissions does not echo the requested key means
    Jira did not evaluate it; that is unknown, not deny. The global list has
    no echo and is unaffected."""
    _, f, c = setup(MODE_BASIC)
    f.echo_drop = True
    for res in ("project:OPS", "issue:OPS-1"):
        d = check(c, dana, "CREATE_ISSUES", res)
        itest.expect_code(d, Code.UNSUPPORTED)
        assert "did not evaluate" in d.text, d.text
    itest.expect_code(check(c, dana, "ADMINISTER", "global"), Code.ALLOWED)
    itest.expect_code(check(c, bob, "ADMINISTER", "global"), Code.DENIED)
    f.echo_drop = False
    itest.expect_code(check(c, dana, "CREATE_ISSUES", "project:OPS"), Code.ALLOWED)
    itest.expect_code(check(c, bob, "CREATE_ISSUES", "project:OPS"), Code.DENIED)


def test_basic_request_shape(setup: Setup) -> None:
    srv, _, c = setup(MODE_BASIC)
    d = check(c, dana, "CREATE_ISSUES", "project:OPS")
    itest.expect_code(d, Code.ALLOWED)
    calls = srv.calls()
    assert len(calls) == 3, f"{len(calls)} calls"
    want = ["/rest/api/3/user/search", "/rest/api/3/project/OPS", "/rest/api/3/permissions/check"]
    for i, w in enumerate(want):
        assert calls[i].path == w, f"call {i}: {calls[i].path}, want {w}"
        assert calls[i].header.get("Authorization").startswith("Basic "), f"call {i}: Authorization {calls[i].header.get('Authorization')!r}"
    req = calls[2].json()
    pps = req.get("projectPermissions")
    assert (
        req.get("accountId") == "acc-dana"
        and isinstance(pps, list)
        and len(pps) == 1
        and pps[0]["permissions"][0] == "CREATE_ISSUES"
        and pps[0].get("projects") == [10000]
        and pps[0].get("issues") is None
        and req.get("globalPermissions") is None
    ), f"body {calls[2].body!r}"


def test_scoped_token(setup: Setup) -> None:
    srv, f, c = setup(MODE_SCOPED_TOKEN)
    itest.expect_code(check(c, dana, "CREATE_ISSUES", "project:OPS"), Code.ALLOWED)
    itest.expect_code(check(c, bob, "CREATE_ISSUES", "project:OPS"), Code.DENIED)
    assert f.tenant_calls == 1, f"tenant_info called {f.tenant_calls} times, want 1 (cached)"
    for call in srv.calls():
        if call.path == "/_edge/tenant_info":
            continue
        assert call.path.startswith("/ex/jira/" + CLOUD_ID + "/rest/api/3/"), f"path {call.path} not under the gateway"
        assert call.header.get("Authorization") == "Bearer " + itest.CANARY + "scoped", f"Authorization {call.header.get('Authorization')!r}"
    # tenant_info failure surfaces as unknown, not as deny
    srv2, _, c2 = setup(MODE_SCOPED_TOKEN)
    srv2.json("GET", "/_edge/tenant_info", 200, "{}")
    itest.expect_code(check(c2, dana, "CREATE_ISSUES", "project:OPS"), Code.UPSTREAM_ERROR)


def test_oauth_client(setup: Setup) -> None:
    srv, f, c = setup(MODE_OAUTH_CLIENT)
    itest.expect_code(check(c, dana, "ADMINISTER", "global"), Code.ALLOWED)
    itest.expect_code(check(c, bob, "ADMINISTER", "global"), Code.DENIED)
    assert f.token_calls == 1, f"token endpoint called {f.token_calls} times, want 1 (cached)"
    assert f.tenant_calls == 1, f"tenant_info called {f.tenant_calls} times"
    saw_token = saw_api = False
    for call in srv.calls():
        if call.path == "/oauth/token":
            saw_token = True
            assert call.header.get("Content-Type") == "application/json", f"token request content type {call.header.get('Content-Type')!r}"
        elif call.path == "/_edge/tenant_info":
            pass
        else:
            saw_api = True
            assert call.path.startswith("/ex/jira/" + CLOUD_ID + "/rest/api/3/") and call.header.get("Authorization") == "Bearer " + itest.CANARY + "access", (
                f"{call.path} {call.header.get('Authorization')!r}"
            )
    assert saw_token and saw_api, "expected token and API calls"
    # a rejected client secret is credential_rejected
    s = itest.settings("j", "jira", {"url": srv.url, "auth_mode": MODE_OAUTH_CLIENT, "client_id": "cid-1"}, {"credential": itest.literal("wrong")})
    deps, _ = itest.deps(srv)
    c3 = Jira().new(background(), s, deps)
    itest.expect_code(check(c3, dana, "ADMINISTER", "global"), Code.CREDENTIAL_REJECTED)


def test_oauth_client_expiry_uses_clock(setup: Setup) -> None:
    """The token's expiry is computed from the injected clock, so the
    TokenSource that reads the same clock refreshes 5 minutes before the
    hour expires_in grants, and not before."""
    # A clock years away from wall time: an expiry computed with time.time()
    # would already be in the past by this clock and force a fetch per call.
    mu = threading.Lock()
    now = [datetime.datetime(2031, 3, 1, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp()]

    def clock() -> float:
        with mu:
            return now[0]

    def advance(d: float) -> None:
        with mu:
            now[0] += d

    _, f, c = setup(MODE_OAUTH_CLIENT, None, clock)
    itest.expect_code(check(c, dana, "ADMINISTER", "global"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "ADMINISTER", "global"), Code.ALLOWED)
    assert f.token_calls == 1, f"token endpoint called {f.token_calls} times, want 1"
    advance(54 * 60)  # inside expires_in minus the 5 minute early refresh
    itest.expect_code(check(c, dana, "ADMINISTER", "global"), Code.ALLOWED)
    assert f.token_calls == 1, f"token endpoint called {f.token_calls} times after 54 min, want 1"
    advance(2 * 60)  # 56 min: within 5 minutes of expiry
    itest.expect_code(check(c, dana, "ADMINISTER", "global"), Code.ALLOWED)
    assert f.token_calls == 2, f"token endpoint called {f.token_calls} times after 56 min, want 2"


def test_issue_and_global_checks(setup: Setup) -> None:
    srv, _, c = setup(MODE_BASIC)
    itest.expect_code(check(c, dana, "EDIT_ISSUES", "issue:OPS-1"), Code.ALLOWED)
    calls = srv.calls()
    assert calls[1].path == "/rest/api/3/issue/OPS-1" and calls[1].q("fields") == "project", f"issue lookup {calls[1].path} {calls[1].query}"
    req = calls[2].json()
    pps = req.get("projectPermissions")
    assert isinstance(pps, list) and len(pps) == 1 and pps[0].get("issues") == [10010] and pps[0].get("projects") is None, f"issue body {calls[2].body!r}"
    itest.expect_code(check(c, bob, "EDIT_ISSUES", "issue:OPS-1"), Code.DENIED)
    itest.expect_code(check(c, bob, "BROWSE_PROJECTS", "issue:OPS-1"), Code.ALLOWED)

    srv.reset()
    itest.expect_code(check(c, dana, "ADMINISTER", "global"), Code.ALLOWED)
    calls = srv.calls()
    assert len(calls) == 2, f"global check made {len(calls)} calls, want 2"
    req = calls[1].json()
    assert req.get("accountId") == "acc-dana" and req.get("globalPermissions") == ["ADMINISTER"] and req.get("projectPermissions") is None, (
        f"global body {calls[1].body!r}"
    )
    itest.expect_code(check(c, bob, "ADMINISTER", "global"), Code.DENIED)


def test_statuses(setup: Setup) -> None:
    _, f, c = setup(MODE_BASIC)
    itest.expect_code(check(c, dana, "CREATE_ISSUES", "project:NOPE"), Code.RESOURCE_NOT_VISIBLE)
    itest.expect_code(check(c, dana, "EDIT_ISSUES", "issue:NOPE-1"), Code.RESOURCE_NOT_VISIBLE)
    f.check_status = 403
    d = check(c, dana, "CREATE_ISSUES", "project:OPS")
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)
    assert "Administer Jira" in d.text, d.text
    f.check_status = 400
    itest.expect_code(check(c, dana, "CREATE_ISSUES", "project:OPS"), Code.UNSUPPORTED)
    f.check_status = 0

    srv, _, c2 = setup(MODE_BASIC)
    srv.json("GET", "/rest/api/3/project/OPS", 403, '{"errorMessages":["forbidden"]}')
    itest.expect_code(check(c2, dana, "CREATE_ISSUES", "project:OPS"), Code.CREDENTIAL_REJECTED)


@pytest.mark.parametrize(
    ("action", "resource"),
    [
        ("CREATE_ISSUES", "global"),
        ("ADMINISTER", "project:OPS"),
        ("ADMINISTER", "issue:OPS-1"),
        ("CREATE_ISSUES", "project:ops"),
        ("CREATE_ISSUES", "project:O"),
        ("CREATE_ISSUES", "project:TOOLONGKEY123"),
        ("CREATE_ISSUES", "project:OPS/../x"),
        ("CREATE_ISSUES", "issue:OPS"),
        ("CREATE_ISSUES", "issue:OPS-0"),
        ("CREATE_ISSUES", "issue:ops-1"),
        ("CREATE_ISSUES", "board:1"),
        ("ADMINISTER", "global:x"),
    ],
)
def test_invalid_requests(setup: Setup, action: str, resource: str) -> None:
    srv, _, c = setup(MODE_BASIC)
    srv.reset()
    d = check(c, dana, action, resource)
    assert d.code == Code.INVALID_REQUEST, f"{action} {resource} -> {d.code}: {d.text}"
    for call in srv.calls():
        assert call.path == "/rest/api/3/user/search", f"{action} {resource} reached upstream: {call.path}"


def test_failures(setup: Setup) -> None:
    srv, _, c = setup(MODE_BASIC)
    itest.failure_cases(srv, lambda: check(c, dana, "CREATE_ISSUES", "project:OPS"))


def test_probe(setup: Setup) -> None:
    srv, f, c = setup(MODE_BASIC)
    r = c.probe(background())
    assert "hallpass bot" in r.summary and len(r.warnings) == 0, r
    f.admin = False
    f.known_perms = f.known_perms[:-2]
    r = c.probe(background())
    assert len(r.warnings) == 2, r
    assert "Administer Jira" in r.warnings[0] and "BULK_CHANGE" in r.warnings[1], r.warnings
    srv.fail(itest.Failure.UNAUTHORIZED)
    d = probe_err(c)
    srv.fail(itest.Failure.NONE)
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)


def test_canary_never_logged(setup: Setup) -> None:
    """Drives the error paths whose upstream bodies carry the canary (401,
    400, 403, a rejected token) and checks the log buffer the connection
    writes to. Every other test's teardown checks it too."""
    srv, f, c = setup(MODE_OAUTH_CLIENT)
    f.check_status = 400
    itest.expect_code(check(c, dana, "CREATE_ISSUES", "project:OPS"), Code.UNSUPPORTED)
    f.check_status = 403
    itest.expect_code(check(c, dana, "CREATE_ISSUES", "project:OPS"), Code.CREDENTIAL_REJECTED)
    f.check_status = 0
    srv.fail(itest.Failure.UNAUTHORIZED)
    itest.expect_code(check(c, dana, "CREATE_ISSUES", "project:OPS"), Code.CREDENTIAL_REJECTED)
    srv.fail(itest.Failure.NONE)
    s = itest.settings("j", "jira", {"url": srv.url, "auth_mode": MODE_OAUTH_CLIENT, "client_id": "cid-1"}, {"credential": itest.literal("wrong")})
    deps, logs = itest.deps(srv)
    c2 = Jira().new(background(), s, deps)
    d = check(c2, dana, "CREATE_ISSUES", "project:OPS")
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)
    itest.assert_no_canary(d.text)
    assert f.logs is not None
    itest.assert_no_canary(f.logs.text())
    itest.assert_no_canary(logs.text())
    assert len(f.logs.text()) != 0, "expected http debug lines in the log buffer"


# Allow/deny tests per action (coverage gate). Dana holds everything on
# project OPS, issue OPS-1 and globally; Bob holds only BROWSE_PROJECTS.


def project_allow(setup: Setup, action: str) -> None:
    _, _, c = setup(MODE_BASIC)
    itest.expect_code(check(c, dana, action, "project:OPS"), Code.ALLOWED)
    itest.expect_code(check(c, dana, action, "issue:OPS-1"), Code.ALLOWED)


def project_deny(setup: Setup, action: str) -> None:
    _, _, c = setup(MODE_BASIC)
    itest.expect_code(check(c, bob, action, "project:OPS"), Code.DENIED)
    itest.expect_code(check(c, dana, action, "project:SEC"), Code.DENIED)
    itest.expect_code(check(c, dana, action, "issue:SEC-7"), Code.DENIED)


def global_allow(setup: Setup, action: str) -> None:
    _, _, c = setup(MODE_BASIC)
    itest.expect_code(check(c, dana, action, "global"), Code.ALLOWED)


def global_deny(setup: Setup, action: str) -> None:
    _, _, c = setup(MODE_BASIC)
    itest.expect_code(check(c, bob, action, "global"), Code.DENIED)


def test_action_BROWSE_PROJECTS_allow(setup: Setup) -> None:
    project_allow(setup, "BROWSE_PROJECTS")


def test_action_BROWSE_PROJECTS_deny(setup: Setup) -> None:
    _, _, c = setup(MODE_BASIC)
    itest.expect_code(check(c, bob, "BROWSE_PROJECTS", "project:SEC"), Code.DENIED)
    itest.expect_code(check(c, bob, "BROWSE_PROJECTS", "issue:SEC-7"), Code.DENIED)


def test_action_CREATE_ISSUES_allow(setup: Setup) -> None:
    project_allow(setup, "CREATE_ISSUES")


def test_action_CREATE_ISSUES_deny(setup: Setup) -> None:
    project_deny(setup, "CREATE_ISSUES")


def test_action_EDIT_ISSUES_allow(setup: Setup) -> None:
    project_allow(setup, "EDIT_ISSUES")


def test_action_EDIT_ISSUES_deny(setup: Setup) -> None:
    project_deny(setup, "EDIT_ISSUES")


def test_action_DELETE_ISSUES_allow(setup: Setup) -> None:
    project_allow(setup, "DELETE_ISSUES")


def test_action_DELETE_ISSUES_deny(setup: Setup) -> None:
    project_deny(setup, "DELETE_ISSUES")


def test_action_ASSIGN_ISSUES_allow(setup: Setup) -> None:
    project_allow(setup, "ASSIGN_ISSUES")


def test_action_ASSIGN_ISSUES_deny(setup: Setup) -> None:
    project_deny(setup, "ASSIGN_ISSUES")


def test_action_ASSIGNABLE_USER_allow(setup: Setup) -> None:
    project_allow(setup, "ASSIGNABLE_USER")


def test_action_ASSIGNABLE_USER_deny(setup: Setup) -> None:
    project_deny(setup, "ASSIGNABLE_USER")


def test_action_TRANSITION_ISSUES_allow(setup: Setup) -> None:
    project_allow(setup, "TRANSITION_ISSUES")


def test_action_TRANSITION_ISSUES_deny(setup: Setup) -> None:
    project_deny(setup, "TRANSITION_ISSUES")


def test_action_RESOLVE_ISSUES_allow(setup: Setup) -> None:
    project_allow(setup, "RESOLVE_ISSUES")


def test_action_RESOLVE_ISSUES_deny(setup: Setup) -> None:
    project_deny(setup, "RESOLVE_ISSUES")


def test_action_CLOSE_ISSUES_allow(setup: Setup) -> None:
    project_allow(setup, "CLOSE_ISSUES")


def test_action_CLOSE_ISSUES_deny(setup: Setup) -> None:
    project_deny(setup, "CLOSE_ISSUES")


def test_action_MOVE_ISSUES_allow(setup: Setup) -> None:
    project_allow(setup, "MOVE_ISSUES")


def test_action_MOVE_ISSUES_deny(setup: Setup) -> None:
    project_deny(setup, "MOVE_ISSUES")


def test_action_LINK_ISSUES_allow(setup: Setup) -> None:
    project_allow(setup, "LINK_ISSUES")


def test_action_LINK_ISSUES_deny(setup: Setup) -> None:
    project_deny(setup, "LINK_ISSUES")


def test_action_ADD_COMMENTS_allow(setup: Setup) -> None:
    project_allow(setup, "ADD_COMMENTS")


def test_action_ADD_COMMENTS_deny(setup: Setup) -> None:
    project_deny(setup, "ADD_COMMENTS")


def test_action_EDIT_ALL_COMMENTS_allow(setup: Setup) -> None:
    project_allow(setup, "EDIT_ALL_COMMENTS")


def test_action_EDIT_ALL_COMMENTS_deny(setup: Setup) -> None:
    project_deny(setup, "EDIT_ALL_COMMENTS")


def test_action_DELETE_ALL_COMMENTS_allow(setup: Setup) -> None:
    project_allow(setup, "DELETE_ALL_COMMENTS")


def test_action_DELETE_ALL_COMMENTS_deny(setup: Setup) -> None:
    project_deny(setup, "DELETE_ALL_COMMENTS")


def test_action_CREATE_ATTACHMENTS_allow(setup: Setup) -> None:
    project_allow(setup, "CREATE_ATTACHMENTS")


def test_action_CREATE_ATTACHMENTS_deny(setup: Setup) -> None:
    project_deny(setup, "CREATE_ATTACHMENTS")


def test_action_WORK_ON_ISSUES_allow(setup: Setup) -> None:
    project_allow(setup, "WORK_ON_ISSUES")


def test_action_WORK_ON_ISSUES_deny(setup: Setup) -> None:
    project_deny(setup, "WORK_ON_ISSUES")


def test_action_MANAGE_WATCHERS_allow(setup: Setup) -> None:
    project_allow(setup, "MANAGE_WATCHERS")


def test_action_MANAGE_WATCHERS_deny(setup: Setup) -> None:
    project_deny(setup, "MANAGE_WATCHERS")


def test_action_VIEW_VOTERS_AND_WATCHERS_allow(setup: Setup) -> None:
    project_allow(setup, "VIEW_VOTERS_AND_WATCHERS")


def test_action_VIEW_VOTERS_AND_WATCHERS_deny(setup: Setup) -> None:
    project_deny(setup, "VIEW_VOTERS_AND_WATCHERS")


def test_action_SCHEDULE_ISSUES_allow(setup: Setup) -> None:
    project_allow(setup, "SCHEDULE_ISSUES")


def test_action_SCHEDULE_ISSUES_deny(setup: Setup) -> None:
    project_deny(setup, "SCHEDULE_ISSUES")


def test_action_SET_ISSUE_SECURITY_allow(setup: Setup) -> None:
    project_allow(setup, "SET_ISSUE_SECURITY")


def test_action_SET_ISSUE_SECURITY_deny(setup: Setup) -> None:
    project_deny(setup, "SET_ISSUE_SECURITY")


def test_action_MANAGE_SPRINTS_PERMISSION_allow(setup: Setup) -> None:
    project_allow(setup, "MANAGE_SPRINTS_PERMISSION")


def test_action_MANAGE_SPRINTS_PERMISSION_deny(setup: Setup) -> None:
    project_deny(setup, "MANAGE_SPRINTS_PERMISSION")


def test_action_ADMINISTER_PROJECTS_allow(setup: Setup) -> None:
    project_allow(setup, "ADMINISTER_PROJECTS")


def test_action_ADMINISTER_PROJECTS_deny(setup: Setup) -> None:
    project_deny(setup, "ADMINISTER_PROJECTS")


def test_action_ADMINISTER_allow(setup: Setup) -> None:
    global_allow(setup, "ADMINISTER")


def test_action_ADMINISTER_deny(setup: Setup) -> None:
    global_deny(setup, "ADMINISTER")


def test_action_SYSTEM_ADMIN_allow(setup: Setup) -> None:
    global_allow(setup, "SYSTEM_ADMIN")


def test_action_SYSTEM_ADMIN_deny(setup: Setup) -> None:
    global_deny(setup, "SYSTEM_ADMIN")


def test_action_USER_PICKER_allow(setup: Setup) -> None:
    global_allow(setup, "USER_PICKER")


def test_action_USER_PICKER_deny(setup: Setup) -> None:
    global_deny(setup, "USER_PICKER")


def test_action_CREATE_SHARED_OBJECTS_allow(setup: Setup) -> None:
    global_allow(setup, "CREATE_SHARED_OBJECTS")


def test_action_CREATE_SHARED_OBJECTS_deny(setup: Setup) -> None:
    global_deny(setup, "CREATE_SHARED_OBJECTS")


def test_action_MANAGE_GROUP_FILTER_SUBSCRIPTIONS_allow(setup: Setup) -> None:
    global_allow(setup, "MANAGE_GROUP_FILTER_SUBSCRIPTIONS")


def test_action_MANAGE_GROUP_FILTER_SUBSCRIPTIONS_deny(setup: Setup) -> None:
    global_deny(setup, "MANAGE_GROUP_FILTER_SUBSCRIPTIONS")


def test_action_BULK_CHANGE_allow(setup: Setup) -> None:
    global_allow(setup, "BULK_CHANGE")


def test_action_BULK_CHANGE_deny(setup: Setup) -> None:
    global_deny(setup, "BULK_CHANGE")
