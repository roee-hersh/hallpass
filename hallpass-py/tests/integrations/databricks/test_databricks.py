"""Port of internal/integrations/databricks/databricks_test.go."""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from hallpass.core.context import background
from hallpass.core.decision import Code, Decision
from hallpass.core.integration import Connection, User, find_action, validate_fields
from hallpass.core.secret import literal
from hallpass.integrations.databricks import Databricks
from hallpass.integrations.databricks.actions import ACTION_LIST, UC_TYPES, WS_TYPES
from hallpass.integrations.databricks.databricks import MODE_TOKEN, SCIM_ME, SCIM_USERS, SCOPE_ALL_APIS, UC_COLLECTIONS
from tests import harness as itest

CLIENT_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
TABLE_RN = "table:main.sales.orders"

dana = User(email="dana@example.com")  # groups: users, data-readers
bob = User(email="bob@example.com")  # groups: users
eve = User(email="eve@example.com")  # no groups
sam = User(email="sam@example.com")  # groups: users, admins


@dataclass(frozen=True)
class Privilege:
    """One effective privilege entry as the fake serves it."""

    name: str
    from_type: str = ""
    from_name: str = ""


@dataclass
class Assignment:
    """One principal's privileges on a securable."""

    principal: str
    privileges: list[Privilege]


@dataclass
class ACLEntry:
    """One Permissions API entry."""

    user: str = ""
    group: str = ""
    levels: list[str] = field(default_factory=list)


def user(id: str, name: str, active: bool | None, *groups: str) -> dict[str, Any]:
    m: dict[str, Any] = {"id": id, "userName": name, "displayName": itest.CANARY + "name", "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"]}
    if active is not None:
        m["active"] = active
    gs = [{"display": g, "value": str(1000 + i), "type": "direct"} for i, g in enumerate(groups)]
    m["groups"] = gs or None
    return m


def inh(name: str, from_type: str, from_name: str) -> Privilege:
    return Privilege(name, from_type, from_name)


def direct(name: str) -> Privilege:
    return Privilege(name)


class FakeWorkspace:
    def __init__(self) -> None:
        self.mu = threading.Lock()
        self.errors: list[str] = []
        self.tokens: dict[str, bool] = {}
        self.minted = 0
        # the personal access token the fake accepts
        self.pat = itest.CANARY + "dapi123"
        # when set, every API call fails with it
        self.status = 0
        self.error_code = ""
        # userName -> SCIM record
        self.users: dict[str, dict[str, Any]] = {
            "dana@example.com": user("100", "dana@example.com", True, "users", "data-readers"),
            "bob@example.com": user("101", "bob@example.com", True, "users"),
            "eve@example.com": user("102", "eve@example.com", True),
            "sam@example.com": user("103", "sam@example.com", True, "users", "admins"),
            "off@example.com": user("104", "off@example.com", False, "users"),
            "nostatus@example.com": user("105", "nostatus@example.com", None, "users"),
        }
        # "<securable>/<name>" -> assignments
        self.grants: dict[str, list[Assignment]] = {
            "catalog/main": [
                Assignment("dana@example.com", [direct("USE_CATALOG"), direct("CREATE_SCHEMA")]),
                Assignment("bob@example.com", [direct("BROWSE")]),
            ],
            "schema/main.sales": [
                Assignment("dana@example.com", [direct("CREATE_TABLE"), direct("USE_SCHEMA"), inh("USE_CATALOG", "CATALOG", "main")]),
                Assignment("bob@example.com", [inh("BROWSE", "CATALOG", "main")]),
            ],
            "table/main.sales.orders": [
                Assignment(
                    "data-readers",
                    [inh("SELECT", "SCHEMA", "main.sales"), inh("USE_SCHEMA", "SCHEMA", "main.sales"), inh("USE_CATALOG", "CATALOG", "main")],
                ),
                Assignment("dana@example.com", [direct("MODIFY")]),
                Assignment("bob@example.com", [inh("BROWSE", "CATALOG", "main")]),
            ],
            "volume/main.sales.files": [
                Assignment(
                    "dana@example.com",
                    [direct("READ_VOLUME"), direct("WRITE_VOLUME"), inh("USE_SCHEMA", "SCHEMA", "main.sales"), inh("USE_CATALOG", "CATALOG", "main")],
                ),
            ],
            "function/main.sales.fn": [
                Assignment("dana@example.com", [direct("EXECUTE"), inh("USE_SCHEMA", "SCHEMA", "main.sales"), inh("USE_CATALOG", "CATALOG", "main")]),
            ],
            "model/main.sales.churn": [Assignment("dana@example.com", [direct("EXECUTE")])],
            # ALL_PRIVILEGES on the catalog covers everything below it.
            "table/legacy.s.t": [Assignment("data-readers", [inh("ALL_PRIVILEGES", "CATALOG", "legacy")])],
            # The legacy USAGE stands for USE_CATALOG and USE_SCHEMA.
            "table/old.s.t": [
                Assignment("dana@example.com", [direct("SELECT")]),
                Assignment("data-readers", [inh("USAGE", "CATALOG", "old"), inh("USAGE", "SCHEMA", "old.s")]),
            ],
            # A quoted-looking name that is still a plain identifier.
            "table/main.sales.q_1": [Assignment("dana@example.com", [direct("SELECT"), direct("USE_SCHEMA"), direct("USE_CATALOG")])],
        }
        # paginated override
        self.pages: dict[str, list[list[Assignment]]] = {
            "table/big.s.t": [
                [Assignment("bob@example.com", [direct("BROWSE")])],
                [],  # an empty page that still carries a token
                [Assignment("dana@example.com", [direct("SELECT"), inh("USE_SCHEMA", "SCHEMA", "big.s"), inh("USE_CATALOG", "CATALOG", "big")])],
            ],
        }
        # "<securable>/<name>" -> owner
        self.owners: dict[str, str] = {
            "table/main.sales.orders": "dana@example.com",
            "catalog/main": "data-owners",
            "schema/main.sales": "data-readers",
            "volume/main.sales.files": "someone@example.com",
            "function/main.sales.fn": "someone@example.com",
            "model/main.sales.churn": "someone@example.com",
            "table/legacy.s.t": "someone@example.com",
            "table/old.s.t": "someone@example.com",
            "table/big.s.t": "someone@example.com",
            "table/main.sales.q_1": "someone@example.com",
        }
        # "<object>/<id>" -> entries
        self.acls: dict[str, list[ACLEntry]] = {
            "clusters/0123-456789-abcde1f2": [ACLEntry(group="users", levels=["CAN_ATTACH_TO"]), ACLEntry(user="dana@example.com", levels=["CAN_RESTART"])],
            "jobs/42": [ACLEntry(user="dana@example.com", levels=["CAN_MANAGE_RUN"]), ACLEntry(user="bob@example.com", levels=["CAN_VIEW"])],
            "jobs/43": [ACLEntry(user="dana@example.com", levels=["IS_OWNER"])],
            "warehouses/abc123def456": [ACLEntry(user="dana@example.com", levels=["CAN_USE"]), ACLEntry(user="bob@example.com", levels=["CAN_MONITOR"])],
            "notebooks/1234567890": [ACLEntry(group="data-readers", levels=["CAN_EDIT"])],
            "directories/222": [ACLEntry(group="data-readers", levels=["CAN_READ"])],
            "repos/333": [ACLEntry(user="dana@example.com", levels=["CAN_RUN"])],
            "pipelines/p-1": [ACLEntry(user="dana@example.com", levels=["CAN_RUN"])],
            "serving-endpoints/churn-v2": [ACLEntry(user="dana@example.com", levels=["CAN_QUERY"]), ACLEntry(user="bob@example.com", levels=["CAN_VIEW"])],
            "cluster-policies/pol": [ACLEntry(group="users", levels=["CAN_USE"])],
        }

    def token(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        """POST /oidc/v1/token with HTTP Basic client credentials."""
        with self.mu:

            def fail(status: int, code: str) -> None:
                w.header().set("Content-Type", "application/json")
                w.write_header(status)
                w.write('{"error":"' + code + '","error_description":"' + itest.CANARY + 'desc"}')

            ba = r.basic_auth()
            if ba is None or ba[0] != CLIENT_ID or ba[1] != itest.CANARY + "secret":
                fail(401, "invalid_client")
                return
            form = {k: v[0] for k, v in {**r.query, **r.form()}.items()}
            if form.get("grant_type") != "client_credentials" or form.get("scope") != SCOPE_ALL_APIS:
                self.errors.append(f"token form {form}")
                fail(400, "invalid_request")
                return
            if form.get("client_secret") or form.get("client_id"):
                self.errors.append("client credentials sent in the form body, not the Basic header")
            self.minted += 1
            tok = f"{itest.CANARY}token{self.minted}"
            self.tokens[tok] = True
            write(w, {"access_token": tok, "token_type": "Bearer", "expires_in": 3600, "scope": SCOPE_ALL_APIS})

    def api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        """The workspace APIs."""
        with self.mu:
            self._api(w, r)

    def _api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        bearer = r.header.get("Authorization").removeprefix("Bearer ")
        if not self.tokens.get(bearer) and bearer != self.pat:
            api_err(w, 401, "UNAUTHENTICATED")
            return
        if self.status != 0:
            api_err(w, self.status, self.error_code)
            return
        p = r.path
        if p == SCIM_USERS:
            flt = r.q("filter")
            if not flt.startswith('userName eq "') or not flt.endswith('"'):
                self.errors.append(f"SCIM filter {flt!r}")
                api_err(w, 400, "INVALID_PARAMETER_VALUE")
                return
            if r.q("attributes") == "":
                self.errors.append("SCIM search without attributes")
            email = flt.removeprefix('userName eq "').removesuffix('"')
            res = [u for name, u in self.users.items() if name.lower() == email.lower()]
            if email == "dup@example.com":
                res += [user("200", "dup@example.com", True), user("201", "Dup@example.com", True)]
            write(
                w,
                {
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                    "totalResults": len(res),
                    "startIndex": 1,
                    "itemsPerPage": len(res),
                    "Resources": res,
                },
            )
        elif p == SCIM_ME:
            if bearer == self.pat:
                write(w, user("7", "hallpass-bot@example.com", True, "users"))
                return
            write(w, user("8", CLIENT_ID, True, "users", "admins"))
        elif p.startswith("/api/2.1/unity-catalog/effective-permissions/"):
            key = p.removeprefix("/api/2.1/unity-catalog/effective-permissions/")
            if r.q("max_results") != "0":
                self.errors.append(f"effective-permissions without max_results=0: {r.query}")
            if key in self.pages:
                pages = self.pages[key]
                i = 0
                tok = r.q("page_token")
                if tok:
                    m = re.match(r"page-(\d+)", tok)
                    i = int(m.group(1)) if m else 0
                if i >= len(pages):
                    api_err(w, 400, "INVALID_PARAMETER_VALUE")
                    return
                body: dict[str, Any] = {"privilege_assignments": render_assignments(pages[i])}
                if i + 1 < len(pages):
                    body["next_page_token"] = f"page-{i + 1}"
                write(w, body)
                return
            if key not in self.grants:
                api_err(w, 404, "RESOURCE_DOES_NOT_EXIST")
                return
            write(w, {"privilege_assignments": render_assignments(self.grants[key])})
        elif p.startswith("/api/2.1/unity-catalog/"):
            rest = p.removeprefix("/api/2.1/unity-catalog/")
            coll, _, name = rest.partition("/")
            typ = ""
            for t, c in UC_COLLECTIONS.items():
                if c == coll:
                    typ = t
            owner = self.owners.get(typ + "/" + name)
            if owner is None:
                api_err(w, 404, "RESOURCE_DOES_NOT_EXIST")
                return
            write(w, {"name": name, "full_name": name, "owner": owner, "comment": itest.CANARY + "comment"})
        elif p.startswith("/api/2.0/permissions/"):
            key = p.removeprefix("/api/2.0/permissions/")
            if key not in self.acls:
                api_err(w, 404, "RESOURCE_DOES_NOT_EXIST")
                return
            lst: list[dict[str, Any]] = []
            for e in self.acls[key]:
                perms = [{"permission_level": lv, "inherited": e.group != "", "inherited_from_object": ["/" + key]} for lv in e.levels]
                m2: dict[str, Any] = {"all_permissions": perms or None, "display_name": itest.CANARY + "display"}
                if e.user != "":
                    m2["user_name"] = e.user
                else:
                    m2["group_name"] = e.group
                lst.append(m2)
            # A service principal entry is always present and never matches a user.
            lst.append({"service_principal_name": CLIENT_ID, "all_permissions": [{"permission_level": "CAN_MANAGE", "inherited": False}]})
            write(w, {"object_id": "/" + key, "object_type": key.split("/")[0].removesuffix("s"), "access_control_list": lst})
        else:
            self.errors.append(f"fake: no route for {r.method} {p}")
            api_err(w, 404, "NOT_FOUND")


def api_err(w: itest.ResponseWriter, status: int, code: str) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write(f'{{"error_code":"{code}","message":"{itest.CANARY}message"}}')


def write(w: itest.ResponseWriter, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write(json.dumps(v) + "\n")


def render_assignments(asg: list[Assignment]) -> list[dict[str, Any]]:
    out = []
    for a in asg:
        ps = []
        for p in a.privileges:
            m: dict[str, Any] = {"privilege": p.name}
            if p.from_type != "":
                m["inherited_from_type"] = p.from_type
                m["inherited_from_name"] = p.from_name
            ps.append(m)
        out.append({"principal": a.principal, "privileges": ps or None})
    return out


class Env:
    """Makes fake workspaces and connections, and checks them when the test ends."""

    def __init__(self) -> None:
        self.made: list[tuple[itest.Server, FakeWorkspace | None]] = []

    def server(self, fake: bool = True) -> tuple[itest.Server, FakeWorkspace]:
        srv = itest.Server()
        f = FakeWorkspace()
        if fake:
            srv.handle("POST", "/oidc/v1/token", f.token)
            srv.handle("GET", "/api/*", f.api)
        self.made.append((srv, f if fake else None))
        return srv, f

    def setup(self, values: dict[str, str] | None = None) -> tuple[itest.Server, FakeWorkspace, Connection]:
        srv, f = self.server()
        deps, _ = itest.deps(srv)
        v = {"url": srv.url, "client_id": CLIENT_ID}
        v.update(values or {})
        sec = itest.literal("secret")
        if v.get("auth_mode") == MODE_TOKEN:
            sec = literal(f.pat)
            del v["client_id"]
        s = itest.settings("dbx", "databricks", v, {"credential": sec})
        c = Databricks().new(background(), s, deps)
        return srv, f, c

    def close(self) -> None:
        for srv, f in self.made:
            srv.close()
            if f is not None:
                assert not f.errors, "\n".join(f.errors)
            assert not srv.spec_errors, "requests did not match the API description:\n" + "\n".join(srv.spec_errors)


@pytest.fixture
def env() -> Iterator[Env]:
    e = Env()
    yield e
    e.close()


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, Databricks(), u, action, resource)


# -- the action table ------------------------------------------------------------


def allow_deny(env: Env, u: User, action: str, resource: str, want: Code, text: str) -> None:
    _, _, c = env.setup()
    d = check(c, u, action, resource)
    itest.expect_code(d, want)
    if text != "":
        assert text in d.text, f"text {d.text!r} does not contain {text!r}"
    itest.assert_no_canary(d.text)


def test_action_table_read_allow(env: Env) -> None:
    allow_deny(env, dana, "table.read", TABLE_RN, Code.ALLOWED, "via group data-readers on schema main.sales")


def test_action_table_read_deny(env: Env) -> None:
    allow_deny(env, bob, "table.read", TABLE_RN, Code.DENIED, "lacks SELECT, USE_SCHEMA, USE_CATALOG")


def test_action_table_write_allow(env: Env) -> None:
    allow_deny(env, dana, "table.write", TABLE_RN, Code.ALLOWED, "granted directly")


def test_action_table_write_deny(env: Env) -> None:
    allow_deny(env, bob, "table.write", TABLE_RN, Code.DENIED, "lacks MODIFY")


def test_action_table_create_allow(env: Env) -> None:
    allow_deny(env, dana, "table.create", "schema:main.sales", Code.ALLOWED, "")


def test_action_table_create_deny(env: Env) -> None:
    allow_deny(env, bob, "table.create", "schema:main.sales", Code.DENIED, "")


def test_action_schema_create_allow(env: Env) -> None:
    allow_deny(env, dana, "schema.create", "catalog:main", Code.ALLOWED, "")


def test_action_schema_create_deny(env: Env) -> None:
    allow_deny(env, bob, "schema.create", "catalog:main", Code.DENIED, "")


def test_action_catalog_use_allow(env: Env) -> None:
    allow_deny(env, dana, "catalog.use", "catalog:main", Code.ALLOWED, "")


def test_action_catalog_use_deny(env: Env) -> None:
    allow_deny(env, bob, "catalog.use", "catalog:main", Code.DENIED, "lacks USE_CATALOG")


def test_action_volume_read_allow(env: Env) -> None:
    allow_deny(env, dana, "volume.read", "volume:main.sales.files", Code.ALLOWED, "")


def test_action_volume_read_deny(env: Env) -> None:
    allow_deny(env, bob, "volume.read", "volume:main.sales.files", Code.DENIED, "")


def test_action_volume_write_allow(env: Env) -> None:
    allow_deny(env, dana, "volume.write", "volume:main.sales.files", Code.ALLOWED, "")


def test_action_volume_write_deny(env: Env) -> None:
    allow_deny(env, bob, "volume.write", "volume:main.sales.files", Code.DENIED, "")


def test_action_function_execute_allow(env: Env) -> None:
    allow_deny(env, dana, "function.execute", "function:main.sales.fn", Code.ALLOWED, "")


def test_action_function_execute_deny(env: Env) -> None:
    allow_deny(env, bob, "function.execute", "function:main.sales.fn", Code.DENIED, "")


def test_action_uc_manage_allow(env: Env) -> None:
    # dana has no MANAGE grant but owns the table.
    allow_deny(env, dana, "uc.manage", TABLE_RN, Code.ALLOWED, "owns table main.sales.orders")


def test_action_uc_manage_deny(env: Env) -> None:
    allow_deny(env, bob, "uc.manage", TABLE_RN, Code.DENIED, "lacks MANAGE")


def test_action_cluster_attach_allow(env: Env) -> None:
    allow_deny(env, bob, "cluster.attach", "cluster:0123-456789-abcde1f2", Code.ALLOWED, "via group users")


def test_action_cluster_attach_deny(env: Env) -> None:
    allow_deny(env, eve, "cluster.attach", "cluster:0123-456789-abcde1f2", Code.DENIED, "no permission")


def test_action_cluster_restart_allow(env: Env) -> None:
    allow_deny(env, dana, "cluster.restart", "cluster:0123-456789-abcde1f2", Code.ALLOWED, "granted directly")


def test_action_cluster_restart_deny(env: Env) -> None:
    allow_deny(env, bob, "cluster.restart", "cluster:0123-456789-abcde1f2", Code.DENIED, "holds only CAN_ATTACH_TO")


def test_action_cluster_manage_allow(env: Env) -> None:
    allow_deny(env, sam, "cluster.manage", "cluster:0123-456789-abcde1f2", Code.ALLOWED, "workspace admin")


def test_action_cluster_manage_deny(env: Env) -> None:
    allow_deny(env, dana, "cluster.manage", "cluster:0123-456789-abcde1f2", Code.DENIED, "not CAN_MANAGE")


def test_action_job_view_allow(env: Env) -> None:
    allow_deny(env, bob, "job.view", "job:42", Code.ALLOWED, "")


def test_action_job_view_deny(env: Env) -> None:
    allow_deny(env, eve, "job.view", "job:42", Code.DENIED, "")


def test_action_job_run_allow(env: Env) -> None:
    allow_deny(env, dana, "job.run", "job:42", Code.ALLOWED, "")


def test_action_job_run_deny(env: Env) -> None:
    allow_deny(env, bob, "job.run", "job:42", Code.DENIED, "holds only CAN_VIEW")


def test_action_job_manage_allow(env: Env) -> None:
    allow_deny(env, dana, "job.manage", "job:43", Code.ALLOWED, "IS_OWNER, which implies CAN_MANAGE")


def test_action_job_manage_deny(env: Env) -> None:
    allow_deny(env, dana, "job.manage", "job:42", Code.DENIED, "")


def test_action_warehouse_use_allow(env: Env) -> None:
    allow_deny(env, dana, "warehouse.use", "warehouse:abc123def456", Code.ALLOWED, "")


def test_action_warehouse_use_deny(env: Env) -> None:
    # CAN_MONITOR does not imply CAN_USE.
    allow_deny(env, bob, "warehouse.use", "warehouse:abc123def456", Code.DENIED, "holds only CAN_MONITOR")


def test_action_warehouse_manage_allow(env: Env) -> None:
    allow_deny(env, sam, "warehouse.manage", "warehouse:abc123def456", Code.ALLOWED, "")


def test_action_warehouse_manage_deny(env: Env) -> None:
    allow_deny(env, dana, "warehouse.manage", "warehouse:abc123def456", Code.DENIED, "")


def test_action_notebook_read_allow(env: Env) -> None:
    allow_deny(env, dana, "notebook.read", "directory:222", Code.ALLOWED, "")


def test_action_notebook_read_deny(env: Env) -> None:
    allow_deny(env, eve, "notebook.read", "notebook:1234567890", Code.DENIED, "")


def test_action_notebook_run_allow(env: Env) -> None:
    allow_deny(env, dana, "notebook.run", "repo:333", Code.ALLOWED, "")


def test_action_notebook_run_deny(env: Env) -> None:
    allow_deny(env, dana, "notebook.run", "directory:222", Code.DENIED, "holds only CAN_READ")


def test_action_notebook_edit_allow(env: Env) -> None:
    allow_deny(env, dana, "notebook.edit", "notebook:1234567890", Code.ALLOWED, "CAN_EDIT")


def test_action_notebook_edit_deny(env: Env) -> None:
    allow_deny(env, dana, "notebook.edit", "repo:333", Code.DENIED, "")


def test_action_pipeline_run_allow(env: Env) -> None:
    allow_deny(env, dana, "pipeline.run", "pipeline:p-1", Code.ALLOWED, "")


def test_action_pipeline_run_deny(env: Env) -> None:
    allow_deny(env, bob, "pipeline.run", "pipeline:p-1", Code.DENIED, "")


def test_action_endpoint_query_allow(env: Env) -> None:
    allow_deny(env, dana, "endpoint.query", "endpoint:churn-v2", Code.ALLOWED, "")


def test_action_endpoint_query_deny(env: Env) -> None:
    allow_deny(env, bob, "endpoint.query", "endpoint:churn-v2", Code.DENIED, "holds only CAN_VIEW")


# -- Unity Catalog semantics -----------------------------------------------------


def test_all_privileges_and_usage(env: Env) -> None:
    _, f, c = env.setup()
    itest.expect_code(check(c, dana, "table.read", "table:legacy.s.t"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "table.write", "table:legacy.s.t"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "raw:CREATE_VOLUME", "table:legacy.s.t"), Code.ALLOWED)
    itest.expect_code(check(c, eve, "table.read", "table:legacy.s.t"), Code.DENIED)
    # ALL_PRIVILEGES never includes MANAGE.
    itest.expect_code(check(c, dana, "uc.manage", "table:legacy.s.t"), Code.DENIED)
    # ALL_PRIVILEGES on the table itself, or on the schema, does not carry
    # USE_CATALOG on the catalog.
    with f.mu:
        f.grants["table/legacy.s.t"] = [Assignment("dana@example.com", [Privilege("ALL_PRIVILEGES")])]
    d = check(c, dana, "table.read", "table:legacy.s.t")
    itest.expect_code(d, Code.DENIED)
    assert "lacks USE_SCHEMA, USE_CATALOG" in d.text, d.text
    itest.expect_code(check(c, dana, "raw:SELECT", "table:legacy.s.t"), Code.ALLOWED)
    with f.mu:
        f.grants["table/legacy.s.t"] = [Assignment("dana@example.com", [Privilege("ALL_PRIVILEGES", "SCHEMA", "legacy.s")])]
    d = check(c, dana, "table.read", "table:legacy.s.t")
    itest.expect_code(d, Code.DENIED)
    assert "lacks USE_CATALOG" in d.text and "USE_SCHEMA" not in d.text, d.text
    itest.expect_code(check(c, dana, "table.read", "table:old.s.t"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "table.write", "table:old.s.t"), Code.DENIED)


def test_effective_permissions_paginate(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "table.read", "table:big.s.t"), Code.ALLOWED)
    pages = sum(1 for call in srv.calls() if "effective-permissions/table/big.s.t" in call.path)
    assert pages == 3, f"read {pages} pages, want 3"
    itest.expect_code(check(c, bob, "table.read", "table:big.s.t"), Code.DENIED)


def test_owner_by_group_and_missing_object(env: Env) -> None:
    _, f, c = env.setup()
    # The schema is owned by dana's group; bob is in neither.
    d = check(c, dana, "uc.manage", "schema:main.sales")
    itest.expect_code(d, Code.ALLOWED)
    assert "owner data-readers" in d.text, d.text
    itest.expect_code(check(c, bob, "uc.manage", "schema:main.sales"), Code.DENIED)
    # Missing securable: unknown, not deny.
    itest.expect_code(check(c, dana, "table.read", "table:main.sales.nothing"), Code.RESOURCE_NOT_VISIBLE)
    # Grants readable but the object itself vanished between the two calls.
    with f.mu:
        del f.owners["table/main.sales.orders"]
    itest.expect_code(check(c, bob, "table.read", TABLE_RN), Code.RESOURCE_NOT_VISIBLE)
    itest.expect_code(check(c, dana, "table.read", TABLE_RN), Code.ALLOWED)


def test_owner_needs_parent_privileges(env: Env) -> None:
    _, f, c = env.setup()
    # dana owns the table but her group's USE_SCHEMA and USE_CATALOG are gone.
    with f.mu:
        f.grants["table/main.sales.orders"] = [Assignment("bob@example.com", [Privilege("BROWSE")])]
    d = check(c, dana, "table.read", TABLE_RN)
    itest.expect_code(d, Code.DENIED)
    assert "lacks USE_SCHEMA, USE_CATALOG on its parents" in d.text, d.text
    # Owning the schema does stand for USE_SCHEMA, and the catalog's owner
    # holds USE_CATALOG.
    with f.mu:
        f.grants["schema/main.sales"] = [Assignment("bob@example.com", [Privilege("BROWSE")])]
        f.owners["catalog/main"] = "data-readers"
        f.grants["catalog/main"] = [Assignment("bob@example.com", [Privilege("BROWSE")])]
    itest.expect_code(check(c, dana, "table.create", "schema:main.sales"), Code.DENIED)
    itest.expect_code(check(c, dana, "schema.create", "catalog:main"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "uc.manage", "schema:main.sales"), Code.ALLOWED)


def test_filtered_listing_is_unknown(env: Env) -> None:
    srv, f, c = env.setup()
    # Unity Catalog shows a non-owner only its own grants, with a 200.
    with f.mu:
        f.grants["table/main.sales.orders"] = [Assignment(CLIENT_ID, [Privilege("BROWSE")])]
    d = check(c, bob, "table.read", TABLE_RN)
    itest.expect_code(d, Code.RESOURCE_NOT_VISIBLE)
    assert "hallpass itself" in d.text, d.text
    # The owner is still recognised through the metadata call.
    itest.expect_code(check(c, dana, "uc.manage", TABLE_RN), Code.ALLOWED)
    # An empty listing is the same story.
    with f.mu:
        f.grants["table/main.sales.orders"] = []
    itest.expect_code(check(c, bob, "table.read", TABLE_RN), Code.RESOURCE_NOT_VISIBLE)
    # hallpass's own name was read once and cached.
    me = sum(1 for call in srv.calls() if call.path == SCIM_ME)
    assert me == 1, f"SCIM /Me read {me} times, want 1"


# -- workspace object semantics --------------------------------------------------


def test_admins_rule(env: Env) -> None:
    _, _, c = env.setup({"admins_manage_all": "false"})
    itest.expect_code(check(c, sam, "cluster.manage", "cluster:0123-456789-abcde1f2"), Code.DENIED)
    # Admins get no free pass on Unity Catalog data.
    _, _, c = env.setup()
    itest.expect_code(check(c, sam, "table.read", TABLE_RN), Code.DENIED)
    # And no free pass on an object that does not exist.
    itest.expect_code(check(c, sam, "cluster.manage", "cluster:nope"), Code.RESOURCE_NOT_VISIBLE)


def test_raw_actions(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "raw:CAN_RESTART", "cluster:0123-456789-abcde1f2"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "raw:CAN_MANAGE", "cluster:0123-456789-abcde1f2"), Code.DENIED)
    itest.expect_code(check(c, bob, "raw:CAN_USE", "policy:pol"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "raw:MODIFY", TABLE_RN), Code.ALLOWED)
    itest.expect_code(check(c, dana, "raw:CREATE_VOLUME", "table:main.sales.q_1"), Code.DENIED)
    # The owner holds every privilege, raw ones included.
    itest.expect_code(check(c, dana, "raw:CREATE_VOLUME", TABLE_RN), Code.ALLOWED)
    itest.expect_code(check(c, dana, "raw:EXECUTE", "model:main.sales.churn"), Code.ALLOWED)
    # A level that does not exist for the type is a bad request, not a deny.
    itest.expect_code(check(c, dana, "raw:CAN_FOO", "cluster:0123-456789-abcde1f2"), Code.INVALID_REQUEST)
    itest.expect_code(check(c, dana, "raw:CAN_USE", "cluster:0123-456789-abcde1f2"), Code.INVALID_REQUEST)
    itest.expect_code(check(c, dana, "raw:IS_OWNER", "cluster:0123-456789-abcde1f2"), Code.DENIED)
    # IS_OWNER names the one owner: CAN_MANAGE and admin status do not imply it.
    itest.expect_code(check(c, dana, "raw:IS_OWNER", "job:43"), Code.ALLOWED)
    itest.expect_code(check(c, sam, "raw:IS_OWNER", "job:43"), Code.DENIED)
    itest.expect_code(check(c, dana, "raw:CAN_MANAGE", "job:43"), Code.ALLOWED)
    n = len(srv.calls())
    for bad in ("raw:", "raw:select", "raw:SELECT x", "raw:S", "raw:1SELECT", "SELECT"):
        assert Databricks().match_action(bad) is None, f"{bad!r} matched"
    assert len(srv.calls()) == n, "a rejected action reached the upstream"


def non_scim(srv: itest.Server) -> int:
    """The calls that are not identity lookups: itest.check resolves the
    identity before every check, where the engine would cache it."""
    return sum(1 for call in srv.calls() if call.path != SCIM_USERS)


BAD_RESOURCES = [
    ("table.read", "table:main.sales"),
    ("table.read", "table:main.sales.orders.extra"),
    ("table.read", "table:main.sales.or ders"),
    ("table.read", "table:main.sales.`orders`"),
    ("table.read", "table:main..orders"),
    ("table.read", "table:main.sales.orders?x=1"),
    ("table.read", "schema:main.sales"),
    ("table.read", "cluster:abc"),
    ("catalog.use", "catalog:main/x"),
    ("cluster.attach", "cluster:"),
    ("cluster.attach", "cluster:a/b"),
    ("cluster.attach", "cluster:-abc"),
    ("cluster.attach", "job:42"),
    ("notebook.read", "table:main.sales.orders"),
    ("uc.manage", "cluster:abc"),
    ("job.view", "user:dana@example.com"),
    ("raw:SELECT", "thing:1"),
]


def test_rejects_bad_resources(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "catalog.use", "catalog:main"), Code.ALLOWED)
    n = non_scim(srv)
    for action, resource in BAD_RESOURCES:
        d = check(c, dana, action, resource)
        assert d.code == Code.INVALID_REQUEST, f"{action} {resource}: {d.code} ({d.text}), want invalid_request"
    assert non_scim(srv) == n, "a rejected resource reached the upstream"


def test_names_are_escaped_in_paths(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "table.read", "table:main.sales.q_1"), Code.ALLOWED)
    found = any(call.path == "/api/2.1/unity-catalog/effective-permissions/table/main.sales.q_1" for call in srv.calls())
    assert found, "effective-permissions path not as expected"


# -- identity --------------------------------------------------------------------


def test_identity(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, User(email=" Dana@Example.com "), "catalog.use", "catalog:main"), Code.ALLOWED)
    lookup = None
    for call in srv.calls():
        if call.path == SCIM_USERS:
            lookup = call
    assert lookup is not None and lookup.q("filter") == 'userName eq "dana@example.com"' and lookup.q("attributes") == "id,userName,active,groups", (
        f"SCIM lookup {lookup}"
    )
    itest.expect_code(check(c, User(email="nobody@example.com"), "catalog.use", "catalog:main"), Code.USER_NOT_FOUND)
    itest.expect_code(check(c, User(email="dup@example.com"), "catalog.use", "catalog:main"), Code.USER_AMBIGUOUS)
    itest.expect_code(check(c, User(email='da"na@example.com'), "catalog.use", "catalog:main"), Code.INVALID_REQUEST)
    itest.expect_code(check(c, User(email="not an email"), "catalog.use", "catalog:main"), Code.INVALID_REQUEST)
    n = len(srv.calls())
    d = check(c, User(email="off@example.com"), "catalog.use", "catalog:main")
    itest.expect_code(d, Code.DENIED)
    assert "deactivated" in d.text, d.text
    itest.expect_code(check(c, User(email="nostatus@example.com"), "catalog.use", "catalog:main"), Code.UNSUPPORTED)
    # Neither reached the grants: the SCIM lookup is the only call each.
    assert len(srv.calls()) == n + 2, f"{len(srv.calls()) - n} calls for a deactivated and a status-less user, want 2"


# -- errors and auth -------------------------------------------------------------


def test_api_errors(env: Env) -> None:
    _, f, c = env.setup()

    def set_(status: int, code: str) -> None:
        with f.mu:
            f.status, f.error_code = status, code

    itest.expect_code(check(c, dana, "catalog.use", "catalog:main"), Code.ALLOWED)
    set_(403, "PERMISSION_DENIED")
    d = check(c, dana, "catalog.use", "catalog:main")
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)
    assert "PERMISSION_DENIED" in d.text, d.text
    set_(400, "INVALID_PARAMETER_VALUE")
    itest.expect_code(check(c, dana, "catalog.use", "catalog:main"), Code.INVALID_REQUEST)
    set_(404, "RESOURCE_DOES_NOT_EXIST")
    itest.expect_code(check(c, dana, "catalog.use", "catalog:main"), Code.UPSTREAM_ERROR)
    set_(0, "")
    itest.expect_code(check(c, dana, "catalog.use", "catalog:main"), Code.ALLOWED)


def test_failures(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "catalog.use", "catalog:main"), Code.ALLOWED)
    itest.failure_cases(srv, lambda: check(c, dana, "catalog.use", "catalog:main"))


def test_failures_at_token_endpoint(env: Env) -> None:
    srv, _, c = env.setup()
    itest.failure_cases(srv, lambda: check(c, dana, "catalog.use", "catalog:main"))


def test_token_cached_and_basic_auth(env: Env) -> None:
    srv, f, c = env.setup()
    itest.expect_code(check(c, dana, "catalog.use", "catalog:main"), Code.ALLOWED)
    itest.expect_code(check(c, bob, "catalog.use", "catalog:main"), Code.DENIED)
    with f.mu:
        assert f.minted == 1, f"minted {f.minted} tokens, want 1"
    for call in srv.calls():
        if call.path.startswith("/api/"):
            assert call.header.get("Authorization").startswith("Bearer " + itest.CANARY + "token"), (
                f"API call without the minted bearer: {call.header.get('Authorization')!r}"
            )


def test_token_refreshed_on401(env: Env) -> None:
    _, f, c = env.setup()
    itest.expect_code(check(c, dana, "catalog.use", "catalog:main"), Code.ALLOWED)
    # The token is revoked server-side: the next call gets 401, hallpass
    # mints a new one and retries once.
    with f.mu:
        f.tokens = {}
    itest.expect_code(check(c, dana, "catalog.use", "catalog:main"), Code.ALLOWED)
    with f.mu:
        assert f.minted == 2, f"minted {f.minted} tokens, want 2"
    # A token the endpoint keeps refusing is credential_rejected.
    with f.mu:
        f.tokens = {}
        f.status, f.error_code = 401, "UNAUTHENTICATED"
    itest.expect_code(check(c, dana, "catalog.use", "catalog:main"), Code.CREDENTIAL_REJECTED)


def test_bad_secret(env: Env) -> None:
    srv, _ = env.server()
    deps, _ = itest.deps(srv)
    s = itest.settings("dbx", "databricks", {"url": srv.url, "client_id": CLIENT_ID}, {"credential": itest.literal("wrong")})
    c = Databricks().new(background(), s, deps)
    d = check(c, dana, "catalog.use", "catalog:main")
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)
    itest.assert_no_canary(d.text)


def test_personal_access_token(env: Env) -> None:
    srv, f, c = env.setup({"auth_mode": MODE_TOKEN})
    itest.expect_code(check(c, dana, "catalog.use", "catalog:main"), Code.ALLOWED)
    with f.mu:
        assert f.minted == 0, "PAT mode minted a token"
    for call in srv.calls():
        assert call.path != "/oidc/v1/token", "PAT mode called the token endpoint"
        if call.path.startswith("/api/"):
            assert call.header.get("Authorization") == "Bearer " + f.pat, f"Authorization {call.header.get('Authorization')!r}"
    r = c.probe(background())
    assert "hallpass-bot@example.com" in r.summary and "workspace admin: false" in r.summary, r.summary
    assert "not a workspace admin" in "\n".join(r.warnings), f"warnings {r.warnings!r}"


def test_new_rejects_bad_settings(env: Env) -> None:
    srv, _ = env.server(fake=False)
    deps, _ = itest.deps(srv)
    cases: list[dict[str, str]] = [
        {},
        {"url": srv.url},  # no client_id in oauth mode
        {"url": srv.url, "client_id": "x"},  # too short
        {"url": srv.url, "client_id": "a b c d e f g h"},  # spaces
        {"url": srv.url, "client_id": CLIENT_ID, "auth_mode": "magic"},
    ]
    for v in cases:
        s = itest.settings("dbx", "databricks", v, {"credential": itest.literal("x")})
        with pytest.raises(Exception):  # noqa: B017 - Go: any error
            Databricks().new(background(), s, deps)
    s = itest.settings("dbx", "databricks", {"url": srv.url, "client_id": CLIENT_ID}, None)
    with pytest.raises(Exception):  # noqa: B017 - Go: any error
        Databricks().new(background(), s, deps)
    validate_fields(Databricks().fields())
    for fld in Databricks().fields():
        if fld.validate is not None:
            fld.validate("")  # the empty value is accepted


# -- probe -----------------------------------------------------------------------


def test_probe(env: Env) -> None:
    srv, f, c = env.setup()
    r = c.probe(background())
    assert CLIENT_ID in r.summary and "workspace admin: true" in r.summary, r.summary
    assert "no read-only admin role" in "\n".join(r.warnings), f"warnings {r.warnings!r}"
    last = srv.last_call()
    assert last.path == SCIM_ME, f"probe called {last.path}"
    with f.mu:
        f.status, f.error_code = 403, "PERMISSION_DENIED"
    with pytest.raises(Exception) as ei:
        c.probe(background())
    itest.assert_no_canary(str(ei.value))


def test_catalog() -> None:
    seen: set[str] = set()
    for a in Databricks().actions():
        assert a.name not in seen, f"action {a.name} listed twice"
        seen.add(a.name)
        assert a.description != "", f"action {a.name} has no description"
    assert find_action(Databricks(), "raw:SELECT") is not None, "raw:SELECT not matched"
    # Every named action's types resolve to a known resource type.
    for a in ACTION_LIST:
        for typ in a.types:
            assert typ in UC_TYPES or typ in WS_TYPES, f"action {a.name} names unknown type {typ}"
        assert (a.level == "") != (len(a.privileges) == 0), f"action {a.name} must set exactly one of level and privileges"
