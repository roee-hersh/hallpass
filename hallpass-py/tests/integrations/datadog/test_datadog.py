"""Port of internal/integrations/datadog/datadog_test.go."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from hallpass.core import evidence
from hallpass.core.catalog import Action, Resource
from hallpass.core.context import background
from hallpass.core.decision import Code, Decision
from hallpass.core.integration import CheckRequest, Connection, User, find_action, validate_fields
from hallpass.core.secret import Secret, literal
from hallpass.integrations.datadog import Datadog
from hallpass.integrations.datadog.actions import ACTION_LIST, ASSET_TYPES
from tests import harness as itest
from tests.harness.spec import SpecOptions, any_spec, spec_from_env

ROLE_RO = "11111111-1111-1111-1111-111111111111"
ROLE_STD = "22222222-2222-2222-2222-222222222222"
ROLE_ADMIN = "33333333-3333-3333-3333-333333333333"
ROLE_TEAM_X = "44444444-4444-4444-4444-444444444444"
TEAM_T1 = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
ORG_ID = "99999999-9999-9999-9999-999999999999"
DANA_ID = "d1d1d1d1-0000-0000-0000-000000000001"
BOB_ID = "b0b0b0b0-0000-0000-0000-000000000002"
ROOT_ID = "r00tr00t-0000-0000-0000-000000000003"

dana = User(email="dana@example.com")  # Standard role
bob = User(email="bob@example.com")  # Read Only role
root = User(email="root@example.com")  # Admin role, member of team T1
off = User(email="off@example.com")  # disabled


@dataclass
class DDFakeUser:
    id: str
    email: str
    handle: str
    status: str
    disabled: bool | None
    roles: list[str] = field(default_factory=list)


def _atoi(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return 0


class Fake:
    def __init__(self) -> None:
        self.mu = threading.Lock()
        self.errors: list[str] = []
        self.api_key = itest.CANARY + "api"
        self.app_key = itest.CANARY + "app"
        self.page_size = 100
        self.perms_calls = 0
        self.status = 0
        self.users = [
            DDFakeUser(DANA_ID, "dana@example.com", "dana@example.com", "Active", False, [ROLE_STD]),
            DDFakeUser(BOB_ID, "bob@example.com", "bob@example.com", "Active", False, [ROLE_RO]),
            DDFakeUser(ROOT_ID, "root@example.com", "root@example.com", "Active", False, [ROLE_ADMIN, ROLE_RO]),
            DDFakeUser("0ff00000-0000-0000-0000-000000000004", "off@example.com", "off@example.com", "Disabled", True, [ROLE_STD]),
            DDFakeUser("aaaaaaaa-0000-0000-0000-000000000005", "nostatus@example.com", "nostatus", "Active", None, [ROLE_STD]),
            # Matches "dana@example.com" as a substring; must not count.
            DDFakeUser("eeeeeeee-0000-0000-0000-000000000006", "dana@example.com.au", "dana2", "Active", False, [ROLE_ADMIN]),
        ]
        self.role_perms: dict[str, list[str]] = {
            ROLE_RO: ["monitors_read", "dashboards_read", "slos_read", "notebooks_read", "logs_read_data"],
            ROLE_STD: [
                "monitors_read",
                "dashboards_read",
                "slos_read",
                "notebooks_read",
                "logs_read_data",
                "monitors_write",
                "monitors_downtime",
                "dashboards_write",
                "slos_write",
                "notebooks_write",
                "api_keys_read",
            ],
            ROLE_ADMIN: [
                "monitors_read",
                "monitors_write",
                "monitors_downtime",
                "dashboards_read",
                "dashboards_write",
                "slos_read",
                "slos_write",
                "notebooks_read",
                "notebooks_write",
                "logs_read_data",
                "user_access_manage",
                "api_keys_write",
            ],
            ROLE_TEAM_X: ["monitors_read", "monitors_write"],
        }
        self.monitors: dict[str, dict[str, Any]] = {
            "1": {"id": 1, "name": itest.CANARY, "restricted_roles": None, "creator": {"email": "someone@example.com", "handle": "someone@example.com"}},
            "2": {"id": 2, "name": itest.CANARY, "restricted_roles": [ROLE_TEAM_X]},
            "3": {"id": 3, "name": itest.CANARY, "restricted_roles": None},
            "4": {"id": 4, "name": itest.CANARY, "restricted_roles": None},
        }
        self.dashboards: dict[str, dict[str, Any]] = {
            "abc-def-ghi": {"id": "abc-def-ghi", "title": itest.CANARY, "restricted_roles": [ROLE_TEAM_X], "author_handle": "dana@example.com"},
            "pub-lic": {"id": "pub-lic", "title": itest.CANARY},
        }
        self.slos = {"slo1": True}
        self.notebooks = {"100": True}
        # "type:id" -> bindings
        self.policies: dict[str, list[dict[str, Any]]] = {
            "monitor:3": [{"relation": "editor", "principals": ["team:" + TEAM_T1]}, {"relation": "viewer", "principals": ["org:" + ORG_ID]}],
            "monitor:4": [{"relation": "editor", "principals": ["user:" + DANA_ID]}],
            "slo:slo1": [{"relation": "editor", "principals": ["role:" + ROLE_ADMIN]}],
            "notebook:100": [{"relation": "viewer", "principals": ["user:" + BOB_ID]}],
        }
        # team -> user ids
        self.teams: dict[str, list[str]] = {TEAM_T1: [ROOT_ID]}

    def user_json(self, u: DDFakeUser) -> dict[str, Any]:
        attrs: dict[str, Any] = {"email": u.email, "handle": u.handle, "status": u.status, "name": itest.CANARY + " name"}
        if u.disabled is not None:
            attrs["disabled"] = u.disabled
        roles = [{"id": r, "type": "roles"} for r in u.roles]
        return {"id": u.id, "type": "users", "attributes": attrs, "relationships": {"roles": {"data": roles or None}}}

    def api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        with self.mu:
            self._api(w, r)

    def _api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.header.get("DD-API-KEY") != self.api_key or r.header.get("DD-APPLICATION-KEY") != self.app_key:
            dd_err(w, 403)
            return
        if self.status != 0:
            dd_err(w, self.status)
            return
        p = r.path
        size = _atoi(r.q("page[size]"))
        num = _atoi(r.q("page[number]"))
        if size <= 0 or size > self.page_size:
            size = self.page_size

        def page(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
            start = min(num * size, len(values))
            end = min(start + size, len(values))
            return values[start:end]

        if p == "/api/v1/validate":
            write(w, {"valid": True})
        elif p == "/api/v2/users":
            values = []
            flt, status = r.q("filter"), r.q("filter[status]")
            for u in self.users:
                if flt != "" and flt not in u.email:
                    continue
                if status != "" and u.status not in status:
                    continue
                values.append(self.user_json(u))
            if flt == "dup@example.com":
                values += [
                    self.user_json(DDFakeUser("dup1", "dup@example.com", "d1", "Active", False)),
                    self.user_json(DDFakeUser("dup2", "DUP@example.com", "d2", "Active", False)),
                ]
            write(w, {"data": page(values), "meta": {"page": {"total_count": len(self.users), "total_filtered_count": len(values)}}})
        elif p.startswith("/api/v2/roles/") and p.endswith("/permissions"):
            role = p.removeprefix("/api/v2/roles/").removesuffix("/permissions")
            perms = self.role_perms.get(role)
            if perms is None:
                dd_err(w, 404)
                return
            self.perms_calls += 1
            data = [{"id": f"p{i}", "type": "permissions", "attributes": {"name": name, "description": itest.CANARY}} for i, name in enumerate(perms)]
            write(w, {"data": data or None})
        elif p.startswith("/api/v2/restriction_policy/"):
            pid = p.removeprefix("/api/v2/restriction_policy/")
            bindings = self.policies.get(pid, [])
            write(w, {"data": {"type": "restriction_policy", "id": pid, "attributes": {"bindings": bindings}}})
        elif p.startswith("/api/v2/team/") and p.endswith("/memberships"):
            team = p.removeprefix("/api/v2/team/").removesuffix("/memberships")
            members = self.teams.get(team)
            if members is None:
                dd_err(w, 404)
                return
            kw = r.q("filter[keyword]")
            if kw == "":
                self.errors.append("membership listing without filter[keyword]")
            values = []
            for i, uid in enumerate(members):
                # The keyword narrows by email or name: a member whose email
                # does not contain it is not listed.
                if not any(u.id == uid and kw in u.email for u in self.users):
                    continue
                values.append(
                    {
                        "id": f"TeamMembership-{team}-{i}",
                        "type": "team_memberships",
                        "attributes": {"role": None},
                        "relationships": {"user": {"data": {"id": uid, "type": "users"}}},
                    }
                )
            write(w, {"data": page(values)})
        elif p.startswith("/api/v1/monitor/"):
            m = self.monitors.get(p.removeprefix("/api/v1/monitor/"))
            if m is None:
                dd_err(w, 404)
                return
            write(w, m)
        elif p.startswith("/api/v1/dashboard/"):
            d = self.dashboards.get(p.removeprefix("/api/v1/dashboard/"))
            if d is None:
                dd_err(w, 404)
                return
            write(w, d)
        elif p.startswith("/api/v1/slo/"):
            sid = p.removeprefix("/api/v1/slo/")
            if not self.slos.get(sid):
                dd_err(w, 404)
                return
            write(w, {"data": {"id": sid, "name": itest.CANARY, "creator": {"email": "someone@example.com"}}})
        elif p.startswith("/api/v1/notebooks/"):
            nid = p.removeprefix("/api/v1/notebooks/")
            if not self.notebooks.get(nid):
                dd_err(w, 404)
                return
            write(w, {"data": {"id": _atoi(nid), "type": "notebooks", "attributes": {"name": itest.CANARY, "author": {"email": "someone@example.com"}}}})
        else:
            self.errors.append(f"fake: no route for {r.method} {p}")
            dd_err(w, 404)


def dd_err(w: itest.ResponseWriter, status: int) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write(f'{{"errors":["{itest.CANARY} error"]}}')


def write(w: itest.ResponseWriter, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write(json.dumps(v) + "\n")


Env = tuple[itest.Server, Fake, Connection, Callable[[float], None]]


@pytest.fixture
def setup_clock() -> Iterator[Callable[[], Env]]:
    """setup with the connection's clock, which the test moves."""
    made: list[tuple[itest.Server, Fake]] = []

    def make() -> Env:
        srv = itest.Server()
        srv.use_spec(any_spec(spec_from_env("datadog-v1"), spec_from_env("datadog-v2")), SpecOptions())
        f = Fake()
        srv.handle("GET", "/api/*", f.api)
        made.append((srv, f))
        mu = threading.Lock()
        now = [time.time()]

        def clock() -> float:
            with mu:
                return now[0]

        def tick(d: float) -> None:
            with mu:
                now[0] += d

        deps, _ = itest.deps(srv, now=clock)
        s = itest.settings("dd", "datadog", {"url": srv.url}, {"api_key": literal(f.api_key), "credential": literal(f.app_key)})
        c = Datadog().new(background(), s, deps)
        return srv, f, c, tick

    yield make
    for srv, f in made:
        srv.close()
        assert not f.errors, "\n".join(f.errors)
        assert not srv.spec_errors, "requests did not match the API description:\n" + "\n".join(srv.spec_errors)


@pytest.fixture
def setup(setup_clock: Callable[[], Env]) -> Callable[[], tuple[itest.Server, Fake, Connection]]:
    def make() -> tuple[itest.Server, Fake, Connection]:
        srv, f, c, _ = setup_clock()
        return srv, f, c

    return make


Setup = Callable[[], tuple[itest.Server, Fake, Connection]]


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, Datadog(), u, action, resource)


def expect(d: Decision, code: Code, text: str) -> None:
    itest.expect_code(d, code)
    if text:
        assert text in d.text, f"text {d.text!r} does not contain {text!r}"
    itest.assert_no_canary(d.text)


# --- the action table -------------------------------------------------------


def test_action_monitor_edit_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "monitor.edit", "monitor:1"), Code.ALLOWED, "carries no restriction")
    # A policy naming the user directly.
    expect(check(c, dana, "monitor.edit", "monitor:4"), Code.ALLOWED, "grants editor to dana@example.com")
    # A policy naming a team the user is on.
    expect(check(c, root, "monitor.edit", "monitor:3"), Code.ALLOWED, "team " + TEAM_T1)


def test_action_monitor_edit_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, bob, "monitor.edit", "monitor:1"), Code.DENIED, "no role of bob@example.com carries monitors_write")
    # Legacy restricted_roles the user lacks.
    expect(check(c, dana, "monitor.edit", "monitor:2"), Code.DENIED, "restricted to 1 role(s)")
    # A policy that grants editor to a team the user is not on; the admin
    # role does not help.
    expect(check(c, dana, "monitor.edit", "monitor:3"), Code.DENIED, "grants editor to none")


def test_action_monitor_mute_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "monitor.mute", "monitor:1"), Code.ALLOWED, "monitors_downtime")


def test_action_monitor_mute_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, bob, "monitor.mute", "monitor:1"), Code.DENIED, "")
    expect(check(c, dana, "monitor.mute", "monitor:2"), Code.DENIED, "restricted")


def test_action_monitor_read_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, bob, "monitor.read", "monitor:1"), Code.ALLOWED, "")
    # The org is a viewer of monitor 3.
    expect(check(c, bob, "monitor.read", "monitor:3"), Code.ALLOWED, "whole org")
    # restricted_roles restrict editing only.
    expect(check(c, bob, "monitor.read", "monitor:2"), Code.ALLOWED, "")


def test_editor_only_policy_leaves_viewing_open(setup: Setup) -> None:
    _, _, c = setup()
    # monitor 4's policy names an editor only.
    expect(check(c, bob, "monitor.read", "monitor:4"), Code.ALLOWED, "restricts editing only")
    expect(check(c, bob, "monitor.edit", "monitor:4"), Code.DENIED, "")
    # A viewer binding restricts viewing.
    expect(check(c, dana, "raw:notebooks_read", "notebook:100"), Code.DENIED, "grants viewer to none")
    expect(check(c, bob, "raw:notebooks_read", "notebook:100"), Code.ALLOWED, "grants viewer to bob@example.com")


def test_pending_user(setup: Setup) -> None:
    _, f, c = setup()
    with f.mu:
        f.users.append(DDFakeUser("aaaaaaaa-0000-0000-0000-000000000008", "pending@example.com", "pending", "Pending", False, [ROLE_ADMIN]))
    expect(check(c, User(email="pending@example.com"), "users.manage", "org"), Code.DENIED, "has not accepted")


def test_identity_lookup_is_one_call(setup: Setup) -> None:
    srv, _, c = setup()
    expect(check(c, dana, "logs.read", "org"), Code.ALLOWED, "")
    n = sum(1 for call in srv.calls() if call.path == "/api/v2/users")
    assert n == 1, f"user lookup took {n} calls, want 1"


def test_action_monitor_read_deny(setup: Setup) -> None:
    _, f, c = setup()
    with f.mu:
        f.role_perms[ROLE_RO] = ["dashboards_read"]
    expect(check(c, bob, "monitor.read", "monitor:1"), Code.DENIED, "monitors_read")


def test_action_dashboard_edit_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "dashboard.edit", "dashboard:pub-lic"), Code.ALLOWED, "")
    # The author edits a dashboard restricted to roles they lack.
    expect(check(c, dana, "dashboard.edit", "dashboard:abc-def-ghi"), Code.ALLOWED, "author")


def test_action_dashboard_edit_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, root, "dashboard.edit", "dashboard:abc-def-ghi"), Code.DENIED, "restricted to 1 role(s)")
    expect(check(c, bob, "dashboard.edit", "dashboard:pub-lic"), Code.DENIED, "dashboards_write")


def test_action_dashboard_read_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, bob, "dashboard.read", "dashboard:abc-def-ghi"), Code.ALLOWED, "")


def test_action_dashboard_read_deny(setup: Setup) -> None:
    _, f, c = setup()
    with f.mu:
        f.role_perms[ROLE_RO] = ["monitors_read"]
    expect(check(c, bob, "dashboard.read", "dashboard:pub-lic"), Code.DENIED, "")


def test_action_slo_edit_allow(setup: Setup) -> None:
    _, _, c = setup()
    # The policy grants editor to the admin role.
    expect(check(c, root, "slo.edit", "slo:slo1"), Code.ALLOWED, "grants editor to a role")


def test_action_slo_edit_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "slo.edit", "slo:slo1"), Code.DENIED, "grants editor to none")


def test_action_notebook_edit_allow(setup: Setup) -> None:
    _, f, c = setup()
    with f.mu:
        del f.policies["notebook:100"]
    expect(check(c, dana, "notebook.edit", "notebook:100"), Code.ALLOWED, "")


def test_action_notebook_edit_deny(setup: Setup) -> None:
    _, _, c = setup()
    # A viewer-only policy grants no editing, even to the named user.
    expect(check(c, bob, "notebook.edit", "notebook:100"), Code.DENIED, "")
    expect(check(c, dana, "notebook.edit", "notebook:100"), Code.DENIED, "grants editor to none")


def test_action_logs_read_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, bob, "logs.read", "org"), Code.ALLOWED, "carries logs_read_data")


def test_action_logs_read_deny(setup: Setup) -> None:
    _, f, c = setup()
    with f.mu:
        f.role_perms[ROLE_RO] = ["monitors_read"]
    expect(check(c, bob, "logs.read", "org"), Code.DENIED, "no role of bob@example.com carries logs_read_data")


def test_action_users_manage_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, root, "users.manage", "org"), Code.ALLOWED, "")


def test_action_users_manage_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "users.manage", "org"), Code.DENIED, "")


def test_action_apikeys_manage_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, root, "apikeys.manage", "org"), Code.ALLOWED, "")


def test_action_apikeys_manage_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "apikeys.manage", "org"), Code.DENIED, "api_keys_write")


# --- semantics ------------------------------------------------------------------


def test_raw_actions(setup: Setup) -> None:
    srv, _, c = setup()
    expect(check(c, dana, "raw:api_keys_read", "org"), Code.ALLOWED, "")
    expect(check(c, bob, "raw:api_keys_read", "org"), Code.DENIED, "")
    # The asset's write permission is checked against its restrictions.
    expect(check(c, dana, "raw:monitors_write", "monitor:2"), Code.DENIED, "restricted")
    # monitors_downtime changes a monitor: the same answer as monitor.mute.
    expect(check(c, dana, "raw:monitors_downtime", "monitor:3"), Code.DENIED, "grants editor to none")
    # A read permission on an asset is a read as far as restrictions go.
    expect(check(c, dana, "raw:monitors_read", "monitor:3"), Code.ALLOWED, "whole org")
    n = len(srv.calls())
    for bad in ("raw:", "raw:Monitors_Write", "raw:a", "raw:monitors write", "monitors_write"):
        assert Datadog().match_action(bad) is None, f"{bad!r} matched"
    assert len(srv.calls()) == n, "a rejected action reached the upstream"


def test_permissions_cached(setup_clock: Callable[[], Env]) -> None:
    _, f, c, tick = setup_clock()
    expect(check(c, dana, "logs.read", "org"), Code.ALLOWED, "")
    expect(check(c, dana, "monitor.edit", "monitor:1"), Code.ALLOWED, "")
    expect(check(c, dana, "users.manage", "org"), Code.DENIED, "")
    with f.mu:
        assert f.perms_calls == 1, f"role permissions read {f.perms_calls} times, want 1"
    # A fresh check reads the role's permissions again inside the window
    # (once they are more than a second old).
    tick(2.0)
    ident = c.resolve_identity(background(), dana)
    d = c.check(
        evidence.with_fresh(background()),
        CheckRequest(user=dana, identity=ident, action=Action("logs.read"), action_name="logs.read", resource=Resource(raw="", type="org")),
    )
    assert d.code == Code.ALLOWED, f"fresh: {d}"
    with f.mu:
        assert f.perms_calls == 2, f"role permissions read {f.perms_calls} times after a fresh check, want 2"


def test_team_membership_paged(setup: Setup) -> None:
    srv, f, c = setup()
    with f.mu:
        f.page_size = 1
        # A second member whose email also contains "root@example.com".
        f.users.append(DDFakeUser("f00tf00t-0000-0000-0000-000000000007", "notroot@example.com", "nr", "Active", False))
        f.teams[TEAM_T1] = ["f00tf00t-0000-0000-0000-000000000007", ROOT_ID]
    expect(check(c, root, "monitor.edit", "monitor:3"), Code.ALLOWED, "team")
    pages = 0
    for call in srv.calls():
        if call.path.endswith("/memberships"):
            pages += 1
            assert call.q("filter[keyword]") == "root@example.com", f"membership keyword {call.q('filter[keyword]')!r}"
    # Two one-member pages; root is on the second.
    assert pages == 2, f"read {pages} membership pages, want 2"
    # A team the policy names but hallpass cannot see is unknown, not deny.
    with f.mu:
        del f.teams[TEAM_T1]
    expect(check(c, root, "monitor.edit", "monitor:3"), Code.RESOURCE_NOT_VISIBLE, "team " + TEAM_T1)


def test_identity(setup: Setup) -> None:
    srv, _, c = setup()
    expect(check(c, User(email=" Dana@Example.com "), "logs.read", "org"), Code.ALLOWED, "")
    lookup = None
    for call in srv.calls():
        if call.path == "/api/v2/users":
            lookup = call
    assert lookup is not None and lookup.q("filter") == "dana@example.com" and "Disabled" in lookup.q("filter[status]"), f"lookup {lookup}"
    expect(check(c, User(email="ghost@example.com"), "logs.read", "org"), Code.USER_NOT_FOUND, "")
    expect(check(c, User(email="dup@example.com"), "logs.read", "org"), Code.USER_AMBIGUOUS, "")
    expect(check(c, off, "logs.read", "org"), Code.DENIED, "disabled")
    expect(check(c, User(email="nostatus@example.com"), "logs.read", "org"), Code.UNSUPPORTED, "did not report")
    expect(check(c, User(email="not an email"), "logs.read", "org"), Code.INVALID_REQUEST, "")


def test_missing_assets_and_errors(setup: Setup) -> None:
    _, f, c = setup()
    expect(check(c, dana, "monitor.edit", "monitor:999"), Code.RESOURCE_NOT_VISIBLE, "does not exist or hallpass cannot see it")
    expect(check(c, dana, "dashboard.edit", "dashboard:nope"), Code.RESOURCE_NOT_VISIBLE, "")
    expect(check(c, dana, "slo.edit", "slo:nope"), Code.RESOURCE_NOT_VISIBLE, "")
    expect(check(c, dana, "notebook.edit", "notebook:1"), Code.RESOURCE_NOT_VISIBLE, "")
    # Even a user without the permission gets unknown on a missing asset.
    expect(check(c, bob, "monitor.edit", "monitor:999"), Code.RESOURCE_NOT_VISIBLE, "")
    # A role hallpass cannot read.
    with f.mu:
        f.users[0].roles = ["55555555-5555-5555-5555-555555555555"]
    expect(check(c, dana, "logs.read", "org"), Code.RESOURCE_NOT_VISIBLE, "role 55555555")
    with f.mu:
        f.users[0].roles = [ROLE_STD]
        f.status = 403
    expect(check(c, dana, "logs.read", "org"), Code.CREDENTIAL_REJECTED, "invalid, or the application key lacks the scope")


def test_rejects_bad_resources(setup: Setup) -> None:
    srv, _, c = setup()
    expect(check(c, dana, "logs.read", "org"), Code.ALLOWED, "")
    n = len(srv.calls())
    cases = [
        ("monitor.edit", "dashboard:abc"),
        ("logs.read", "monitor:1"),
        ("logs.read", "org:1"),
        ("monitor.edit", "monitor:"),
        ("monitor.edit", "monitor:1/2"),
        ("monitor.edit", "monitor:1?x=1"),
        ("monitor.edit", "monitor:-1"),
        ("monitor.edit", "synthetic:1"),
    ]
    errors = []
    for action, resource in cases:
        d = check(c, dana, action, resource)
        if d.code != Code.INVALID_REQUEST:
            errors.append(f"{action} {resource}: {d.code} ({d.text}), want invalid_request")
    for call in srv.calls()[n:]:
        if call.path != "/api/v2/users":
            errors.append(f"rejected resource reached {call.path}")
    assert not errors, "\n".join(errors)


def test_failures(setup: Setup) -> None:
    srv, _, c = setup()
    expect(check(c, dana, "monitor.edit", "monitor:1"), Code.ALLOWED, "")
    itest.failure_cases(srv, lambda: check(c, dana, "monitor.edit", "monitor:1"))


def test_probe(setup: Setup) -> None:
    _, f, c = setup()
    r = c.probe(background())
    assert "reads users" in r.summary, r.summary
    itest.assert_no_canary(r.summary)
    assert "teams_read" in "\n".join(r.warnings), f"warnings {r.warnings}"
    with f.mu:
        f.status = 403
    with pytest.raises(Exception) as ei:
        c.probe(background())
    itest.assert_no_canary(str(ei.value))


def test_new_rejects_bad_settings(srv: itest.Server) -> None:
    deps, _ = itest.deps(srv)
    cases: list[dict[str, Secret]] = [{}, {"api_key": itest.literal("a")}, {"credential": itest.literal("b")}]
    for secrets in cases:
        s = itest.settings("dd", "datadog", {}, secrets)
        with pytest.raises(ValueError):
            Datadog().new(background(), s, deps)
    validate_fields(Datadog().fields())


def test_catalog() -> None:
    seen: set[str] = set()
    for a in Datadog().actions():
        assert a.name not in seen and a.description != "", f"action {a.name} duplicated or undescribed"
        seen.add(a.name)
    assert find_action(Datadog(), "raw:monitors_write") is not None, "raw:monitors_write not matched"
    for da in ACTION_LIST:
        assert da.resource in ASSET_TYPES or da.resource == "org", f"action {da.name} names unknown resource {da.resource}"
        assert (da.resource == "org") == (da.relation == ""), f"action {da.name}: org actions carry no relation, asset actions do"
