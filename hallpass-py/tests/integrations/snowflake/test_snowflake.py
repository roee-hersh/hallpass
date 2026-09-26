"""Port of internal/integrations/snowflake/snowflake_test.go."""

from __future__ import annotations

import base64
import copy
import json
import re
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from hallpass.authx.jwt import RS256, decode_jwt_claims, verify
from hallpass.core.context import background
from hallpass.core.decision import Code, Decision, HallpassError
from hallpass.core.errors import as_error
from hallpass.core.integration import Connection, User
from hallpass.core.secret import literal as secret_literal
from hallpass.integrations.snowflake import Snowflake
from hallpass.integrations.snowflake.snowflake import USER_PAGE, equal_fold, fingerprint
from hallpass.integrations.snowflake.sql import like_literal, parse_identifier, quote, quote_name
from tests import harness as itest
from tests.harness.spec import SpecOptions, spec_from_env

_KEY_LOCK = threading.Lock()
_KEY: list[tuple[rsa.RSAPrivateKey, str]] = []


def _pkcs8(k: rsa.RSAPrivateKey) -> str:
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def signing_key() -> tuple[rsa.RSAPrivateKey, str]:
    with _KEY_LOCK:
        if not _KEY:
            k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            _KEY.append((k, _pkcs8(k)))
        return _KEY[0]


dana = User(email="dana@example.com")  # DANA: ANALYST
bob = User(email="bob@example.com")  # named by email: DEV (owns DEV.PLAY), inherits READER
ops = User(email="ops@example.com")  # OPS: OPS_ADMIN -> DEV -> READER, database role PROD.DBROLE
none = User(email="none@example.com")  # NOROLE


@dataclass
class FakeUser:
    name: str
    login: str = ""
    email: str = ""
    disabled: bool = False
    roles: list[str] = field(default_factory=list)


USER_COLS = [
    "name",
    "created_on",
    "login_name",
    "display_name",
    "first_name",
    "last_name",
    "email",
    "mins_to_unlock",
    "days_to_expiry",
    "comment",
    "disabled",
    "must_change_password",
    "snowflake_lock",
    "default_warehouse",
    "default_namespace",
    "default_role",
    "default_secondary_roles",
    "ext_authn_duo",
    "ext_authn_uid",
    "mins_to_bypass_mfa",
    "owner",
    "last_success_login",
    "expires_at_time",
    "locked_until_time",
    "has_password",
    "has_rsa_public_key",
    "type",
]
GRANT_COLS = ["created_on", "privilege", "granted_on", "name", "granted_to", "grantee_name", "grant_option", "granted_by_role_type", "granted_by"]

LIKE_RE = re.compile(r"SHOW USERS LIKE '(.*)'")
LIMIT_RE = re.compile(r"SHOW USERS LIMIT ([0-9]+)(?: FROM '(.*)')?")
TO_USER_RE = re.compile(r'SHOW GRANTS TO USER "((?:[^"]|"")+)"')
TO_ROLE_RE = re.compile(r'SHOW GRANTS TO ROLE "((?:[^"]|"")+)"')
TO_DB_ROLE = re.compile(r'SHOW GRANTS TO DATABASE ROLE ("(?:[^"]|"")+"\."(?:[^"]|"")+")')


def unquote_sql(s: str) -> str:
    return s.strip('"').replace('""', '"')


def replace_all(s: str, pairs: list[tuple[str, str]]) -> str:
    """Go's strings.NewReplacer(pairs...).Replace: at each position the
    first old string (in argument order) that matches is replaced."""
    out = []
    i = 0
    while i < len(s):
        for old, new in pairs:
            if s.startswith(old, i):
                out.append(new)
                i += len(old)
                break
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def table(cols: list[str], rows: list[list[str]] | None) -> dict[str, Any]:
    """A result set from column names and rows, shaped as Go's resultSet
    marshals."""
    return {
        "code": "090001",
        "sqlState": "00000",
        "message": "Statement executed successfully.",
        "statementHandle": "01b0f0f0-0000-0000-0000-000000000002",
        "data": rows,
        "resultSetMetaData": {"numRows": len(rows or []), "rowType": [{"name": c} for c in cols], "partitionInfo": None},
    }


def empty_result() -> dict[str, Any]:
    return {
        "code": "",
        "sqlState": "",
        "message": "",
        "statementHandle": "",
        "data": None,
        "resultSetMetaData": {"numRows": 0, "rowType": None, "partitionInfo": None},
    }


def write(w: itest.ResponseWriter, status: int, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write(json.dumps(v) + "\n")


def sql_err(w: itest.ResponseWriter, code: str) -> None:
    write(
        w,
        422,
        {
            "code": code,
            "sqlState": "42501",
            "message": "SQL access control error: " + itest.CANARY,
            "statementHandle": "01b0f0f0-0000-0000-0000-000000000001",
            "createdOn": 1700000000000,
            "statementStatusUrl": "/api/v2/statements/x",
        },
    )


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Fake:
    def __init__(self) -> None:
        self.mu = threading.Lock()
        self.errs: list[str] = []  # Go: t.Errorf from a handler
        self.pub: Any = None
        self.users: list[FakeUser] = [
            FakeUser("HALLPASS", "hallpass", "", False, ["SECADMIN"]),
            FakeUser("DANA", "dana@example.com", "dana@example.com", False, ["ANALYST"]),
            FakeUser("bob@example.com", "bob@example.com", "bob@example.com", False, ["DEV"]),
            FakeUser("OPS", "ops", "ops@example.com", False, ["OPS_ADMIN"]),
            FakeUser("OFF", "off", "off@example.com", True, ["ANALYST"]),
            FakeUser("NOROLE", "norole", "none@example.com", False, []),
            FakeUser("DUP1", "dup1", "dup@example.com", False, []),
            FakeUser("DUP2", "dup@example.com", "other@example.com", False, []),
            FakeUser("TWICE1", "twice1", "twice@example.com", False, []),
            FakeUser("TWICE2", "twice2", "twice@example.com", False, []),
            # An email that contains another; matching is exact.
            FakeUser("DANAAU", "danaau", "dana@example.com.au", False, ["OPS_ADMIN"]),
        ]
        # role -> rows of privilege, granted_on, name, granted_by
        self.role_grants: dict[str, list[tuple[str, str, str, str]] | None] = {
            "ANALYST": [
                ("USAGE", "DATABASE", "PROD", "SYSADMIN"),
                ("USAGE", "SCHEMA", "PROD.SALES", "SYSADMIN"),
                ("SELECT", "TABLE", "PROD.SALES.ORDERS", "SYSADMIN"),
                ("SELECT", "VIEW", "PROD.SALES.V_ORDERS", "SYSADMIN"),
                ("SELECT", "TABLE", 'PROD.SALES."Mixed Case"', "SYSADMIN"),
                ("SELECT", "TABLE", "PROD.HR.SALARIES", "SYSADMIN"),  # no USAGE on PROD.HR
                ("USAGE", "WAREHOUSE", "ANALYTICS_WH", "SYSADMIN"),
            ],
            "DEV": [
                ("USAGE", "DATABASE", "DEV", "SYSADMIN"),
                ("OWNERSHIP", "SCHEMA", "DEV.PLAY", "SYSADMIN"),
                ("INSERT", "TABLE", "DEV.PLAY.T", "SYSADMIN"),
                ("USAGE", "ROLE", "READER", "SECURITYADMIN"),
            ],
            "READER": [
                ("USAGE", "DATABASE", "DEV", "SYSADMIN"),
                ("USAGE", "SCHEMA", "DEV.PLAY", "SYSADMIN"),
                ("SELECT", "TABLE", "DEV.PLAY.T", "SYSADMIN"),
                ("USAGE", "ROLE", '"mixed role"', "SECURITYADMIN"),
            ],
            "mixed role": [
                ("USAGE", "WAREHOUSE", "SMALL_WH", "SYSADMIN"),
            ],
            "OPS_ADMIN": [
                ("USAGE", "ROLE", "DEV", "SECURITYADMIN"),
                ("OPERATE", "WAREHOUSE", "ANALYTICS_WH", "SYSADMIN"),
                ("MODIFY", "WAREHOUSE", "ANALYTICS_WH", "SYSADMIN"),
                ("CREATE DATABASE", "ACCOUNT", "MYORG-MYACCOUNT", "SYSADMIN"),
                ("USAGE", "DATABASE_ROLE", "PROD.DBROLE", "SYSADMIN"),
                ("USAGE", "ROLE", "OPS_ADMIN", "SECURITYADMIN"),  # a cycle, must not loop
            ],
            "SECADMIN": [
                ("MANAGE GRANTS", "ACCOUNT", "MYORG-MYACCOUNT", "ACCOUNTADMIN"),
            ],
            "PUBLIC": [
                ("USAGE", "DATABASE", "PUB", "SYSADMIN"),
            ],
        }
        # "DB"."ROLE" -> rows
        self.db_roles: dict[str, list[tuple[str, str, str, str]]] = {
            '"PROD"."DBROLE"': [
                ("USAGE", "DATABASE", "PROD", "SYSADMIN"),
                ("USAGE", "SCHEMA", "PROD.SALES", "SYSADMIN"),
                ("SELECT", "TABLE", "PROD.SALES.ORDERS", "SYSADMIN"),
            ],
        }
        self.hidden: dict[str, bool] = {}  # roles hallpass's role may not see
        self.new_shape = False  # SHOW GRANTS TO USER in the 2025 shape
        self.statements: list[str] = []
        self.status = 0
        self.pending = 0  # answer this many statements with 202 first
        self.partitions = 1  # split result sets into this many partitions
        self.results: dict[str, dict[str, Any]] = {}

    def error(self, msg: str) -> None:
        self.errs.append(msg)

    def verify_jwt(self, r: itest.Request) -> bool:
        if r.header.get("X-Snowflake-Authorization-Token-Type") != "KEYPAIR_JWT":
            return False
        tok = r.header.get("Authorization").removeprefix("Bearer ")
        parts = tok.split(".")
        if len(parts) != 3:
            return False
        try:
            sig = _b64url_decode(parts[2])
            verify(self.pub, RS256, (parts[0] + "." + parts[1]).encode(), sig)
            claims = decode_jwt_claims(tok)
        except ValueError:
            return False
        fp = fingerprint(self.pub)
        if (
            claims.get("sub") != "MYORG-MYACCOUNT.HALLPASS"
            or claims.get("iss") != "MYORG-MYACCOUNT.HALLPASS." + fp
            or not claims.get("exp", 0) > claims.get("iat", 0)
        ):
            self.error(f"jwt claims {claims}")
            return False
        return True

    def user_row(self, u: FakeUser) -> list[str]:
        r = []
        for c in USER_COLS:
            if c == "name":
                r.append(u.name)
            elif c == "login_name":
                r.append(u.login)
            elif c == "email":
                r.append(u.email)
            elif c == "disabled":
                r.append("true" if u.disabled else "false")
            elif c == "default_role":
                r.append(u.roles[0] if u.roles else "")
            elif c == "default_secondary_roles":
                r.append('["ALL"]')
            elif c in ("comment", "display_name"):
                r.append(itest.CANARY)
            elif c == "type":
                r.append("PERSON")
            else:
                r.append("null")
        return r

    def execute(self, stmt: str) -> tuple[dict[str, Any], str]:
        m = LIKE_RE.fullmatch(stmt)
        if m:
            # In SQL text the LIKE escapes are \\_ and \\% and a literal
            # backslash is \\\\.
            pat = replace_all(m.group(1), [("\\\\%", "%"), ("\\\\_", "_"), ("''", "'"), ("\\\\\\\\", "\\")])
            rows = [self.user_row(u) for u in self.users if equal_fold(u.name, pat)]
            return table(USER_COLS, rows or None), ""
        m = LIMIT_RE.fullmatch(stmt)
        if m:
            limit = int(m.group(1))
            after = (m.group(2) or "").replace("''", "'")
            rows: list[list[str]] = []
            started = after == ""
            for u in self.users:
                if not started:
                    if u.name == after:
                        started = True
                    continue
                rows.append(self.user_row(u))
                if len(rows) >= limit:
                    break
            return table(USER_COLS, rows or None), ""
        m = TO_USER_RE.fullmatch(stmt)
        if m:
            name = unquote_sql(m.group(1))
            for u in self.users:
                if u.name != name:
                    continue
                rows = []
                for role in u.roles:
                    if self.new_shape:
                        rows.append(["2026-01-01", "USAGE", "ROLE", role, "USER", u.name, "false", "ROLE", "SECURITYADMIN"])
                    else:
                        rows.append(["2026-01-01", role, "USER", u.name, "SECURITYADMIN"])
                if self.new_shape:
                    return table(GRANT_COLS, rows or None), ""
                return table(["created_on", "role", "granted_to", "grantee_name", "granted_by"], rows or None), ""
            return empty_result(), "002003"
        m = TO_ROLE_RE.fullmatch(stmt)
        if m:
            role = unquote_sql(m.group(1))
            if role not in self.role_grants or self.hidden.get(role):
                return empty_result(), "002003"
            rows = [["2026-01-01", g[0], g[1], g[2], "ROLE", role, "false", "ROLE", g[3]] for g in self.role_grants[role] or []]
            return table(GRANT_COLS, rows or None), ""
        m = TO_DB_ROLE.fullmatch(stmt)
        if m:
            grants = self.db_roles.get(m.group(1))
            if grants is None:
                return empty_result(), "002003"
            rows = [["2026-01-01", g[0], g[1], g[2], "DATABASE_ROLE", "PROD.DBROLE", "false", "ROLE", g[3]] for g in grants]
            return table(GRANT_COLS, rows or None), ""
        self.error(f"fake: unexpected statement {stmt!r}")
        return empty_result(), "000001"

    def api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        with self.mu:
            if not self.verify_jwt(r):
                write(w, 401, {"code": "390144", "message": "JWT token is invalid. " + itest.CANARY, "sqlState": "08001"})
                return
            if self.status != 0:
                write(w, self.status, {"code": "000000", "message": itest.CANARY})
                return
            p = r.path
            if p == "/api/v2/statements" and r.method == "POST":
                try:
                    body = r.json()
                except ValueError as e:
                    self.error(f"bad body: {e}")
                    body = {}
                if body.get("role") != "SECADMIN":
                    self.error(f"statement without the configured role: {body}")
                self.statements.append(body.get("statement", ""))
                rs, code = self.execute(body.get("statement", ""))
                if code != "":
                    sql_err(w, code)
                    return
                handle = f"01b0f0f0-0000-0000-0000-{len(self.statements):012d}"
                rs["statementHandle"] = handle
                self.results[handle] = rs  # the full result; views are cut per request
                if self.pending > 0:
                    self.pending -= 1
                    write(
                        w,
                        202,
                        {
                            "code": "333334",
                            "sqlState": "00000",
                            "message": "Asynchronous execution in progress.",
                            "statementHandle": handle,
                            "createdOn": 1700000000000,
                            "statementStatusUrl": "/api/v2/statements/" + handle,
                        },
                    )
                    return
                write(w, 200, self.partition(rs, 0))
            elif p.startswith("/api/v2/statements/") and r.method == "GET":
                handle = p.removeprefix("/api/v2/statements/")
                rs = self.results.get(handle)
                if rs is None:
                    write(w, 404, {"code": "000000", "message": itest.CANARY})
                    return
                n = 0
                part = r.q("partition")
                if part != "":
                    n = int(part)
                page = self.partition(rs, n)
                if n > 0:
                    page["resultSetMetaData"]["rowType"] = None
                write(w, 200, page)
            else:
                self.error(f"fake: no route for {r.method} {p}")
                write(w, 404, {"message": itest.CANARY})

    def partition(self, rs: dict[str, Any], n: int) -> dict[str, Any]:
        """Partition n of a result set: the whole set when the fake is not
        partitioning or the set is small, else its n-th slice with the
        partition table attached."""
        data = rs["data"] or []
        if self.partitions <= 1 or len(data) < self.partitions:
            return copy.deepcopy(rs)
        per = (len(data) + self.partitions - 1) // self.partitions
        page = copy.deepcopy(rs)
        info = []
        for i in range(self.partitions):
            lo, hi = i * per, min((i + 1) * per, len(data))
            info.append({"rowCount": hi - lo})
        page["resultSetMetaData"]["partitionInfo"] = info
        lo, hi = n * per, min((n + 1) * per, len(data))
        lo = min(lo, hi)
        page["data"] = data[lo:hi]
        return page


class Env:
    def __init__(self) -> None:
        self.made: list[tuple[itest.Server, Fake | None]] = []

    def new_server(self) -> tuple[itest.Server, Fake]:
        srv = itest.Server()
        srv.use_spec(spec_from_env("snowflake-sqlapi"), SpecOptions(allow_query=["partition"]))
        f = Fake()
        key, _ = signing_key()
        f.pub = key.public_key()
        srv.handle("", "/api/*", f.api)
        self.made.append((srv, f))
        return srv, f

    def plain_server(self) -> itest.Server:
        srv = itest.Server()
        self.made.append((srv, None))
        return srv

    def setup(self) -> tuple[itest.Server, Fake, Connection]:
        srv, f = self.new_server()
        deps, _ = itest.deps(srv)
        _, pem = signing_key()
        s = itest.settings(
            "sf", "snowflake", {"account": "myorg-myaccount", "user": "hallpass", "role": "secadmin", "url": srv.url}, {"credential": secret_literal(pem)}
        )
        return srv, f, Snowflake().new(background(), s, deps)

    def close(self) -> None:
        for srv, _ in self.made:
            srv.close()
        for srv, f in self.made:
            if f is not None:
                assert not f.errs, "\n".join(f.errs)
            assert not srv.spec_errors, "requests did not match the API description:\n" + "\n".join(srv.spec_errors)


@pytest.fixture
def env() -> Iterator[Env]:
    e = Env()
    yield e
    e.close()


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, Snowflake(), u, action, resource)


def expect(d: Decision, code: Code, text: str) -> None:
    itest.expect_code(d, code)
    assert text == "" or text in d.text, f"text {d.text!r} does not contain {text!r}"
    itest.assert_no_canary(d.text)


# -- the action table -------------------------------------------------------------


def test_action_table_select_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(
        check(c, dana, "table.select", "table:prod.sales.orders"),
        Code.ALLOWED,
        'role "ANALYST" holds SELECT on table "PROD"."SALES"."ORDERS"; dana@example.com has it directly',
    )
    # A view, and a quoted case-sensitive name.
    expect(check(c, dana, "table.select", "table:PROD.SALES.V_ORDERS"), Code.ALLOWED, "")
    expect(check(c, dana, "table.select", 'table:prod.sales."Mixed Case"'), Code.ALLOWED, '"Mixed Case"')
    # Through the role hierarchy: bob -> DEV -> READER.
    expect(check(c, bob, "table.select", "table:dev.play.t"), Code.ALLOWED, 'through "DEV" -> "READER"')
    # Through a database role: OPS -> OPS_ADMIN -> PROD.DBROLE.
    expect(check(c, ops, "table.select", "table:prod.sales.orders"), Code.ALLOWED, 'through "OPS_ADMIN" -> "PROD"."DBROLE"')


def test_action_table_select_deny(env: Env) -> None:
    _, _, c = env.setup()
    # ANALYST and PUBLIC.
    expect(check(c, dana, "table.select", "table:dev.play.t"), Code.DENIED, "none of the 2 role(s) dana@example.com holds carries SELECT")
    # SELECT without USAGE on the schema.
    expect(check(c, dana, "table.select", "table:prod.hr.salaries"), Code.DENIED, 'no role holds USAGE on schema "PROD"."HR"')
    # Case matters for quoted names.
    expect(check(c, dana, "table.select", 'table:prod.sales."mixed case"'), Code.DENIED, "")
    # Only PUBLIC, which every user holds.
    expect(check(c, none, "table.select", "table:prod.sales.orders"), Code.DENIED, "none of the 1 role(s)")


def test_action_table_insert_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "table.insert", "table:dev.play.t"), Code.ALLOWED, "INSERT")


def test_action_table_insert_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "table.insert", "table:prod.sales.orders"), Code.DENIED, "")
    # READER alone has SELECT only; ops reaches DEV, which has INSERT.
    expect(check(c, ops, "table.insert", "table:dev.play.t"), Code.ALLOWED, 'through "OPS_ADMIN" -> "DEV"')


def _grant(f: Fake, role: str, *rows: tuple[str, str, str, str]) -> None:
    with f.mu:
        f.role_grants[role] = [*(f.role_grants.get(role) or []), *rows]


def test_action_table_update_allow(env: Env) -> None:
    _, f, c = env.setup()
    _grant(f, "DEV", ("UPDATE", "TABLE", "DEV.PLAY.T", "SYSADMIN"))
    expect(check(c, bob, "table.update", "table:dev.play.t"), Code.ALLOWED, "UPDATE")


def test_action_table_update_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "table.update", "table:dev.play.t"), Code.DENIED, "")


def test_action_table_delete_allow(env: Env) -> None:
    _, f, c = env.setup()
    # OWNERSHIP of the table answers everything on it.
    _grant(f, "DEV", ("OWNERSHIP", "TABLE", "DEV.PLAY.OWNED", "SYSADMIN"))
    expect(check(c, bob, "table.delete", "table:dev.play.owned"), Code.ALLOWED, "OWNERSHIP")


def test_action_table_delete_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "table.delete", "table:dev.play.t"), Code.DENIED, "")


def test_action_table_truncate_allow(env: Env) -> None:
    _, f, c = env.setup()
    _grant(f, "DEV", ("TRUNCATE", "TABLE", "DEV.PLAY.T", "SYSADMIN"))
    expect(check(c, bob, "table.truncate", "table:dev.play.t"), Code.ALLOWED, "")


def test_action_table_truncate_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "table.truncate", "table:dev.play.t"), Code.DENIED, "")


def test_action_schema_usage_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "schema.usage", "schema:prod.sales"), Code.ALLOWED, "USAGE")
    # The owner of the schema.
    expect(check(c, bob, "schema.usage", "schema:dev.play"), Code.ALLOWED, "OWNERSHIP")


def test_action_schema_usage_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "schema.usage", "schema:prod.hr"), Code.DENIED, "")
    expect(check(c, bob, "schema.usage", "schema:prod.sales"), Code.DENIED, "")


def test_action_schema_create_table_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "schema.create_table", "schema:dev.play"), Code.ALLOWED, "OWNERSHIP")


def test_action_schema_create_table_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "schema.create_table", "schema:prod.sales"), Code.DENIED, "")


def test_action_schema_create_view_allow(env: Env) -> None:
    _, f, c = env.setup()
    _grant(f, "ANALYST", ("CREATE VIEW", "SCHEMA", "PROD.SALES", "SYSADMIN"))
    expect(check(c, dana, "schema.create_view", "schema:prod.sales"), Code.ALLOWED, "CREATE VIEW")


def test_action_schema_create_view_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "schema.create_view", "schema:prod.sales"), Code.DENIED, "")


def test_action_database_usage_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "database.usage", "database:prod"), Code.ALLOWED, "")


def test_action_database_usage_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "database.usage", "database:dev"), Code.DENIED, "")


def test_public_role(env: Env) -> None:
    _, _, c = env.setup()
    # A grant to PUBLIC reaches a user with no role of their own.
    expect(check(c, none, "database.usage", "database:pub"), Code.ALLOWED, 'role "PUBLIC" holds USAGE')
    expect(check(c, none, "role.use", "role:public"), Code.ALLOWED, "")


def test_action_database_create_schema_allow(env: Env) -> None:
    _, f, c = env.setup()
    _grant(f, "DEV", ("CREATE SCHEMA", "DATABASE", "DEV", "SYSADMIN"))
    expect(check(c, bob, "database.create_schema", "database:dev"), Code.ALLOWED, "")


def test_action_database_create_schema_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "database.create_schema", "database:dev"), Code.DENIED, "")


def test_action_warehouse_usage_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "warehouse.usage", "warehouse:analytics_wh"), Code.ALLOWED, "")


def test_action_warehouse_usage_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "warehouse.usage", "warehouse:analytics_wh"), Code.DENIED, "")
    expect(check(c, ops, "warehouse.usage", "warehouse:analytics_wh"), Code.DENIED, "")


def test_action_warehouse_operate_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, ops, "warehouse.operate", "warehouse:analytics_wh"), Code.ALLOWED, "OPERATE")


def test_action_warehouse_operate_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "warehouse.operate", "warehouse:analytics_wh"), Code.DENIED, "")


def test_action_warehouse_modify_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, ops, "warehouse.modify", "warehouse:analytics_wh"), Code.ALLOWED, "")


def test_action_warehouse_modify_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "warehouse.modify", "warehouse:analytics_wh"), Code.DENIED, "")


def test_action_role_use_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "role.use", "role:analyst"), Code.ALLOWED, "directly")
    expect(check(c, ops, "role.use", "role:reader"), Code.ALLOWED, 'through "OPS_ADMIN" -> "DEV" -> "READER"')


def test_quoted_role_name(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, bob, "role.use", 'role:"mixed role"'), Code.ALLOWED, '"mixed role"')
    expect(check(c, bob, "warehouse.usage", "warehouse:small_wh"), Code.ALLOWED, 'role "mixed role"')
    expect(check(c, bob, "role.use", "role:mixed_role"), Code.DENIED, "")


def test_action_role_use_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "role.use", "role:dev"), Code.DENIED, "not granted")


def test_action_account_create_database_allow(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, ops, "account.create_database", "account"), Code.ALLOWED, "CREATE DATABASE")


def test_action_account_create_database_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, dana, "account.create_database", "account"), Code.DENIED, "")


def test_action_account_manage_grants_allow(env: Env) -> None:
    _, f, c = env.setup()
    _grant(f, "OPS_ADMIN", ("MANAGE GRANTS", "ACCOUNT", "MYORG-MYACCOUNT", "ACCOUNTADMIN"))
    expect(check(c, ops, "account.manage_grants", "account"), Code.ALLOWED, "")


def test_action_account_manage_grants_deny(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, ops, "account.manage_grants", "account"), Code.DENIED, "")


def test_raw_privileges(env: Env) -> None:
    _, f, c = env.setup()
    _grant(f, "ANALYST", ("REFERENCES", "TABLE", "PROD.SALES.ORDERS", "SYSADMIN"), ("CREATE STAGE", "SCHEMA", "PROD.SALES", "SYSADMIN"))
    expect(check(c, dana, "raw:REFERENCES", "table:prod.sales.orders"), Code.ALLOWED, "REFERENCES")
    expect(check(c, dana, "raw:CREATE_STAGE", "schema:prod.sales"), Code.ALLOWED, "CREATE STAGE")
    expect(check(c, dana, "raw:MONITOR", "warehouse:analytics_wh"), Code.DENIED, "")
    expect(check(c, dana, "raw:USAGE", "role:analyst"), Code.INVALID_REQUEST, "role.use")
    for bad in ("raw:OWNERSHIP", "raw:select", "raw:CREATE__STAGE", "raw:CREATE STAGE", "raw:X", "raw:"):
        assert Snowflake().match_action(bad) is None, f"{bad!r} accepted"


# -- identity -------------------------------------------------------------------------


def test_identity(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, User(email="nobody@example.com"), "database.usage", "database:prod"), Code.USER_NOT_FOUND, "no Snowflake user")
    # DUP2 has the address as login name, DUP1 only as email: the login name,
    # set by the user's owner, wins.
    id = c.resolve_identity(background(), User(email="dup@example.com"))
    assert id.id == "DUP2", f"dup resolved to {id}"
    expect(check(c, User(email="twice@example.com"), "database.usage", "database:prod"), Code.USER_AMBIGUOUS, "2 Snowflake users")
    expect(check(c, User(email="off@example.com"), "database.usage", "database:prod"), Code.DENIED, "disabled")
    expect(check(c, User(email="not an email"), "database.usage", "database:prod"), Code.INVALID_REQUEST, "")
    # dana@example.com.au must not match dana@example.com.
    expect(check(c, dana, "warehouse.operate", "warehouse:analytics_wh"), Code.DENIED, "")


def test_identity_lookup_statements(env: Env) -> None:
    _, f, c = env.setup()
    # bob is named by the address: one LIKE, no scan.
    check(c, bob, "database.usage", "database:dev")
    with f.mu:
        stmts = list(f.statements)
    assert len(stmts) >= 2 and stmts[0] == "SHOW USERS LIKE 'bob@example.com'" and stmts[1] == 'SHOW GRANTS TO USER "bob@example.com"', f"statements {stmts!r}"
    # dana is found by the scan; the LIKE escapes wildcards.
    with f.mu:
        f.statements = []
    check(c, User(email="d_a%a@example.com"), "database.usage", "database:dev")
    with f.mu:
        stmts = list(f.statements)
    assert len(stmts) >= 2 and stmts[0] == r"SHOW USERS LIKE 'd\\_a\\%a@example.com'" and stmts[1] == "SHOW USERS LIMIT 10000", f"statements {stmts!r}"


def test_identity_attrs(env: Env) -> None:
    _, _, c = env.setup()
    id = c.resolve_identity(background(), dana)
    assert id.id == "DANA" and id.attr("disabled") == "false" and id.attr("default_role") == "ANALYST" and len(id.groups) == 1 and id.groups[0] == "ANALYST", (
        f"identity {id}"
    )
    for k, v in id.attrs.items():
        itest.assert_no_canary(k + "=" + v)


def test_new_grant_shape(env: Env) -> None:
    _, f, c = env.setup()
    with f.mu:
        f.new_shape = True
    expect(check(c, dana, "table.select", "table:prod.sales.orders"), Code.ALLOWED, "")


def test_user_scan_paging(env: Env) -> None:
    _, f, c = env.setup()
    with f.mu:
        for i in range(USER_PAGE + 5):
            f.users.append(FakeUser(name=f"U{i:06d}", login=f"u{i:06d}"))
        f.users.append(FakeUser(name="LAST", login="last", email="last@example.com", roles=["ANALYST"]))
    expect(check(c, User(email="last@example.com"), "database.usage", "database:prod"), Code.ALLOWED, "")
    with f.mu:
        pages = sum(1 for s in f.statements if s.startswith("SHOW USERS LIMIT"))
    assert pages == 2, f"{pages} scan pages, want 2"


def test_caller_groups_ignored(env: Env) -> None:
    _, _, c = env.setup()
    expect(check(c, User(email="none@example.com", groups=("ANALYST", "ACCOUNTADMIN")), "database.usage", "database:prod"), Code.DENIED, "")


# -- transport ---------------------------------------------------------------------------


def test_hidden_role(env: Env) -> None:
    _, f, c = env.setup()
    with f.mu:
        f.hidden["READER"] = True
    expect(
        check(c, bob, "table.select", "table:dev.play.t"), Code.RESOURCE_NOT_VISIBLE, 'role "READER" is granted but hallpass\'s role may not read its grants'
    )


def test_insufficient_privileges(env: Env) -> None:
    srv, _, c = env.setup()
    srv.handle("POST", "/api/v2/statements", lambda w, r: sql_err(w, "003001"))
    expect(check(c, dana, "database.usage", "database:prod"), Code.CREDENTIAL_REJECTED, "MANAGE GRANTS")


def test_async_and_partitions(env: Env) -> None:
    srv, f, c = env.setup()
    with f.mu:
        f.pending = 2
        f.partitions = 3
    expect(check(c, dana, "table.select", "table:prod.sales.orders"), Code.ALLOWED, "")
    polls = parts = 0
    for call in srv.calls():
        if call.method == "GET":
            if call.q("partition") != "":
                parts += 1
            else:
                polls += 1
    assert polls == 2 and parts >= 2, f"{polls} polls and {parts} partition reads"


def test_grants_are_cached(env: Env) -> None:
    _, f, c = env.setup()
    check(c, ops, "table.select", "table:prod.sales.orders")
    check(c, ops, "warehouse.operate", "warehouse:analytics_wh")
    with f.mu:
        n = sum(1 for s in f.statements if s.startswith("SHOW GRANTS TO ROLE") or s.startswith("SHOW GRANTS TO DATABASE ROLE"))
    # OPS_ADMIN, DEV, READER, "mixed role", PROD.DBROLE and PUBLIC once each.
    assert n == 6, f"{n} role grant listings, want 6 (cached)"


def test_invalid_requests(env: Env) -> None:
    _, _, c = env.setup()
    for action, resource in (
        ("table.select", "table:orders"),
        ("table.select", "table:prod.sales"),
        ("table.select", "table:prod.sales.orders.x"),
        ("table.select", 'table:prod.sales."unterminated'),
        ("table.select", 'table:prod.sales.""'),
        ("table.select", "table:prod.sales.or ders"),
        ("table.select", "table:prod.sales.orders?x=1"),
        ("table.select", "table:1abc.sales.orders"),
        ("table.select", "schema:prod.sales"),
        ("schema.usage", "database:prod"),
        ("account.create_database", "account:x"),
        ("role.use", "role:a.b"),
        ("table.select", "table:prod.sales.o;drop"),
        ("table.select", 'table:prod.sales."a"b"'),
    ):
        d = check(c, dana, action, resource)
        assert d.code == Code.INVALID_REQUEST, f"{action} {resource}: {d.code} {d.text}"


@pytest.mark.parametrize(
    ("inp", "want", "ok"),
    [
        ("orders", "ORDERS", True),
        ("_x$1", "_X$1", True),
        ('"Mixed Case"', "Mixed Case", True),
        ('"a""b"', 'a"b', True),
        ('"a"b"', "", False),
        ('""', "", False),
        ("1abc", "", False),
        ("a-b", "", False),
        ("a b", "", False),
        ("", "", False),
    ],
)
def test_identifiers(inp: str, want: str, ok: bool) -> None:
    try:
        got = parse_identifier(inp)
    except ValueError:
        got = None
    assert (got is not None) == ok and (got or "") == want, f"parse_identifier({inp!r}) = {got!r}"


def test_identifiers_quoting() -> None:
    """Go: TestIdentifiers, the quoting half."""
    assert quote('a"b') == '"a""b"' and quote_name(["A", "b c"]) == '"A"."b c"', "quoting"
    got = like_literal("d_a%a'\\b")
    assert got == "'d\\\\_a\\\\%a''\\\\\\\\b'", f"like_literal {got!r}"


def test_failures(env: Env) -> None:
    srv, _, c = env.setup()
    itest.failure_cases(srv, lambda: check(c, dana, "database.usage", "database:prod"))


def test_bad_key(env: Env) -> None:
    srv, _ = env.new_server()
    deps, _ = itest.deps(srv)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    s = itest.settings(
        "sf",
        "snowflake",
        {"account": "myorg-myaccount", "user": "hallpass", "role": "secadmin", "url": srv.url},
        {"credential": secret_literal(_pkcs8(other))},
    )
    c = Snowflake().new(background(), s, deps)
    # The fake reports the claims mismatch as a test error only when the
    # signature verifies; a foreign key fails the signature first.
    expect(check(c, dana, "database.usage", "database:prod"), Code.CREDENTIAL_REJECTED, "key-pair token")
    s = itest.settings("sf", "snowflake", {"account": "myorg-myaccount", "user": "hallpass", "url": srv.url}, {"credential": secret_literal("not a key")})
    c = Snowflake().new(background(), s, deps)
    expect(check(c, dana, "database.usage", "database:prod"), Code.CREDENTIAL_REJECTED, "RSA private key")


def test_new_validation(env: Env) -> None:
    srv = env.plain_server()
    deps, _ = itest.deps(srv)
    for values, with_secret in (
        ({"account": "myorg-myaccount", "user": "hallpass"}, False),
        ({"user": "hallpass"}, True),
        ({"account": "myorg-myaccount"}, True),
        ({"account": "myorg-myaccount", "user": "bad user"}, True),
        ({"account": "myorg-myaccount", "user": "hallpass", "role": "1bad"}, True),
        ({"account": "bad account", "user": "hallpass"}, True),
        ({"account": "myorg-myaccount", "user": "hallpass", "url": "ftp://x"}, True),
        ({"account": "myorg-myaccount", "user": "hallpass", "url": "http://proxy.internal"}, True),
        ({"account": "myorg-myaccount", "user": "hallpass", "url": "https://u:p@host"}, True),
    ):
        secrets = {"credential": secret_literal("x")} if with_secret else {}
        with pytest.raises(ValueError):
            Snowflake().new(background(), itest.settings("sf", "snowflake", values, secrets), deps)
    # The default URL follows the account.
    Snowflake().new(
        background(), itest.settings("sf", "snowflake", {"account": "xy12345.us-east-1", "user": "hallpass"}, {"credential": secret_literal("x")}), deps
    )


def test_probe(env: Env) -> None:
    _, _, c = env.setup()
    res = c.probe(background())
    assert '"HALLPASS" with roles SECADMIN' in res.summary and len(res.warnings) == 1, f"probe {res}"
    itest.assert_no_canary(res.summary)
    _, f2, c = env.setup()
    with f2.mu:
        f2.role_grants["SECADMIN"] = None
    res = c.probe(background())
    assert len(res.warnings) == 2, f"probe without MANAGE GRANTS: {res}"
    srv, _ = env.new_server()
    deps, _ = itest.deps(srv)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bad = Snowflake().new(
        background(),
        itest.settings(
            "sf",
            "snowflake",
            {"account": "myorg-myaccount", "user": "hallpass", "role": "secadmin", "url": srv.url},
            {"credential": secret_literal(_pkcs8(other))},
        ),
        deps,
    )
    with pytest.raises(Exception) as ei:
        bad.probe(background())
    ie = as_error(ei.value, HallpassError)
    assert ie is not None and ie.code == Code.CREDENTIAL_REJECTED, f"bad key: {ei.value}"


def test_no_secret_in_logs(env: Env) -> None:
    srv, _ = env.new_server()
    deps, logs = itest.deps(srv)
    _, pem = signing_key()
    s = itest.settings(
        "sf", "snowflake", {"account": "myorg-myaccount", "user": "hallpass", "role": "secadmin", "url": srv.url}, {"credential": secret_literal(pem)}
    )
    c = Snowflake().new(background(), s, deps)
    check(c, dana, "table.select", "table:prod.sales.orders")
    check(c, User(email="nobody@example.com"), "table.select", "table:prod.sales.orders")
    itest.assert_no_canary(logs.text())
    assert "PRIVATE KEY" not in logs.text(), "the key reached the log"
