"""Port of internal/integrations/microsoft365/microsoft365_test.go."""

from __future__ import annotations

import base64
import dataclasses
import datetime
import json
import os
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from hallpass.authx.jwt import PS256, cert_thumbprint_sha256, decode_jwt_claims, verify
from hallpass.core.context import background
from hallpass.core.decision import Code, Decision, to_decision
from hallpass.core.integration import Connection, Identity, User, find_action, validate_fields
from hallpass.core.secret import literal as secret_literal
from hallpass.integrations.microsoft365 import Microsoft365, Microsoft365Connection
from hallpass.integrations.microsoft365.actions import ACTION_LIST
from hallpass.integrations.microsoft365.microsoft365 import USER_SELECT, GraphUser, error_code
from tests import harness as itest
from tests.harness.spec import SpecOptions, spec_from_env

TENANT_ID = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
DANA_ID = "aaaaaaaa-0000-0000-0000-000000000001"
BOB_ID = "aaaaaaaa-0000-0000-0000-000000000002"
GUEST_ID = "aaaaaaaa-0000-0000-0000-000000000003"
OFF_ID = "aaaaaaaa-0000-0000-0000-000000000004"
GROUP_A = "bbbbbbbb-0000-0000-0000-000000000001"
GROUP_B = "bbbbbbbb-0000-0000-0000-000000000002"
ROLE_A = "cccccccc-0000-0000-0000-000000000001"
TEAM_A = "dddddddd-0000-0000-0000-000000000001"
CHAN_STD = "19:std@thread.tacv2"
CHAN_PRIV = "19:priv@thread.tacv2"
CHAN_SHR = "19:shared@thread.tacv2"
CHAN_MOD = "19:mod@thread.tacv2"
# CHAN_NO_TYPE reports no membershipType at all.
CHAN_NO_TYPE = "19:notype@thread.tacv2"
# GROUP_HIDDEN has visibility HiddenMembership; GROUP_MISSING does not exist.
GROUP_HIDDEN = "bbbbbbbb-0000-0000-0000-000000000003"
GROUP_MISSING = "bbbbbbbb-0000-0000-0000-000000000099"
# NOSTATE_ID is a user whose accountEnabled Graph does not report.
NOSTATE_ID = "aaaaaaaa-0000-0000-0000-000000000005"
DRIVE = "b!drive1"
GRAPH_SP = "eeeeeeee-0000-0000-0000-000000000001"
OWN_SP = "eeeeeeee-0000-0000-0000-000000000002"

SPEC_OPTIONS = SpecOptions(strip_prefix=(r"/v1\.0",), ignore_paths=(r"/oauth2/v2\.0/token$",))


def graph_err(w: itest.ResponseWriter, status: int, code: str) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write('{"error":{"code":"' + code + '","message":"' + itest.CANARY + 'upstream message"}}')


def write(w: itest.ResponseWriter, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write(json.dumps(v) + "\n")


@dataclasses.dataclass
class ChannelDef:
    membership_type: str = ""
    moderation: str = ""
    members: dict[str, list[str]] = dataclasses.field(default_factory=dict)


class FakeGraph:
    """An in-memory Graph."""

    def __init__(self) -> None:
        self.mu = threading.Lock()
        self.errors: list[str] = []
        # The current valid access token; "" means every token is invalid.
        self.tok = ""
        # Token endpoint calls.
        self.tokens_issued = 0
        # Makes the next n Graph calls answer 401.
        self.expire401 = 0
        self.users: dict[str, GraphUser] = {
            DANA_ID: GraphUser(DANA_ID, "dana@example.com", "dana@example.com", True, "Member", "Dana"),
            BOB_ID: GraphUser(BOB_ID, "bob@example.com", "bob@example.com", True, "Member", "Bob"),
            GUEST_ID: GraphUser(GUEST_ID, "guest_gmail.com#EXT#@example.onmicrosoft.com", "guest@gmail.com", True, "Guest", "Guest"),
            OFF_ID: GraphUser(OFF_ID, "off@example.com", "off@example.com", False, "Member", "Off"),
            # nostate: accountEnabled absent from the response.
            NOSTATE_ID: GraphUser(NOSTATE_ID, "nostate@example.com", "nostate@example.com", None, "Member", "No State"),
        }
        self.by_upn = {
            "dana@example.com": DANA_ID,
            "bob@example.com": BOB_ID,
            "guest_gmail.com#EXT#@example.onmicrosoft.com": GUEST_ID,
            "off@example.com": OFF_ID,
            "nostate@example.com": NOSTATE_ID,
            "a%b@example.com": DANA_ID,
            "a/b@example.com": BOB_ID,
        }
        self.by_mail = {"guest@gmail.com": GUEST_ID, "dana.alias@example.com": DANA_ID}
        self.by_proxy = {"smtp:dana.old@example.com": [DANA_ID], "smtp:shared@example.com": [DANA_ID, BOB_ID]}
        self.groups: dict[str, list[str]] = {DANA_ID: [GROUP_A], NOSTATE_ID: [GROUP_A]}
        self.roles: dict[str, list[str]] = {DANA_ID: [ROLE_A]}
        self.teams: dict[str, dict[str, list[str]]] = {TEAM_A: {DANA_ID: ["owner"], BOB_ID: []}}
        self.channels = {
            CHAN_STD: ChannelDef("standard"),
            CHAN_PRIV: ChannelDef("private", members={DANA_ID: []}),
            CHAN_SHR: ChannelDef("shared", members={DANA_ID: ["owner"]}),
            CHAN_MOD: ChannelDef("standard", moderation="moderators"),
            CHAN_NO_TYPE: ChannelDef(),
        }
        # group id -> visibility ("" = null); absent = 404
        self.group_vis = {GROUP_A: "Private", GROUP_B: "", GROUP_HIDDEN: "HiddenMembership"}
        # item -> permissions
        self.perms: dict[str, list[dict[str, Any]]] = {}
        # drive owner user id
        self.owner = ""
        # granted app role values
        self.app_roles = ["User.Read.All", "GroupMember.Read.All", "TeamMember.Read.All", "ChannelMember.Read.All", "Files.Read.All"]
        self.sp_denied = False
        # Makes members collections return the whole roster, as an upstream
        # that does not apply the userId $filter would.
        self.ignore_filter = False
        # Makes GET /drives/{id} answer 404 while the item's permissions stay
        # readable.
        self.drive_hidden = False
        # The escaped path of the most recent Graph call, for asserting path
        # escaping (Call.path records the decoded path).
        self.last_escaped = ""

    def escaped_path(self) -> str:
        with self.mu:
            return self.last_escaped

    def token(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        form = r.form()

        def fv(k: str) -> str:
            return (form.get(k) or [""])[0]

        with self.mu:
            if r.path != "/" + TENANT_ID + "/oauth2/v2.0/token" or fv("grant_type") != "client_credentials" or fv("client_id") != CLIENT_ID:
                w.write_header(400)
                w.write('{"error":"invalid_request","error_description":"' + itest.CANARY + 'bad request"}')
                return
            if fv("client_secret") != itest.CANARY + "secret":
                w.write_header(401)
                w.write('{"error":"invalid_client","error_description":"' + itest.CANARY + 'bad secret"}')
                return
            self.tokens_issued += 1
            self.tok = f"{itest.CANARY}tok{self.tokens_issued}"
            write(w, {"access_token": self.tok, "token_type": "Bearer", "expires_in": 3599})

    def user_json(self, u: GraphUser) -> dict[str, Any]:
        out: dict[str, Any] = {"id": u.id, "userPrincipalName": u.user_principal_name, "mail": u.mail, "userType": u.user_type, "displayName": u.display_name}
        if u.account_enabled is not None:
            out["accountEnabled"] = u.account_enabled
        return out

    def member_list(self, members: dict[str, list[str]], user_id: str) -> list[dict[str, Any]]:
        return [
            {"@odata.type": "#microsoft.graph.aadUserConversationMember", "userId": id, "roles": roles}
            for id, roles in members.items()
            if self.ignore_filter or id == user_id
        ]

    def filter_user(self, r: itest.Request) -> str:
        """The user id from the members $filter."""
        fl = r.q("$filter")
        want = "(microsoft.graph.aadUserConversationMember/userId eq '"
        if not fl.startswith(want) or not fl.endswith("')"):
            self.errors.append(f"unexpected members filter {fl!r}")
            return ""
        return fl[len(want) : -2]

    def graph(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        with self.mu:
            self._graph(w, r)

    def _graph(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        if self.expire401 > 0 or self.tok == "" or r.header.get("Authorization") != "Bearer " + self.tok:
            if self.expire401 > 0:
                self.expire401 -= 1
            graph_err(w, 401, "InvalidAuthenticationToken")
            return
        # Split on the escaped path so an escaped "/" inside a segment (a
        # user principal name) stays in that segment, then decode each
        # segment.
        self.last_escaped = r.raw_path
        seg = [urllib.parse.unquote(s) for s in r.raw_path.removeprefix("/v1.0/").split("/")]
        p = "/".join(seg)
        q = r.q
        if p == "organization":
            write(w, {"value": [{"id": TENANT_ID, "displayName": "Example Ltd"}]})
        elif p == "users" and q("$filter") != "":
            if q("$select") != USER_SELECT:
                self.errors.append(f"users filter without select: {r.query}")
            fl = q("$filter")
            ids: list[str] = []
            if fl.startswith("mail eq '"):
                addr = fl.removeprefix("mail eq '").removesuffix("'")
                if addr.replace("''", "'") in self.by_mail:
                    ids = [self.by_mail[addr.replace("''", "'")]]
            elif fl.startswith("proxyAddresses/any(p:p eq '"):
                if r.header.get("ConsistencyLevel") != "eventual" or q("$count") != "true":
                    self.errors.append(f"proxyAddresses query needs ConsistencyLevel eventual and $count=true: {r.header} {r.query}")
                addr = fl.removeprefix("proxyAddresses/any(p:p eq '").removesuffix("')")
                ids = self.by_proxy.get(addr, [])
            else:
                graph_err(w, 400, "Request_UnsupportedQuery")
                return
            write(w, {"value": [self.user_json(self.users[id]) for id in ids]})
        elif seg[0] == "users" and len(seg) == 2:
            key = seg[1]
            id = key if key in self.users else self.by_upn.get(key, "")
            u = self.users.get(id)
            if u is None:
                graph_err(w, 404, "Request_ResourceNotFound")
                return
            if q("$select") != USER_SELECT:
                self.errors.append(f"user lookup without select: {r.query}")
            write(w, self.user_json(u))
        elif seg[0] == "users" and len(seg) == 3 and seg[2] == "checkMemberGroups":
            try:
                group_ids = json.loads(r.body).get("groupIds") or []
            except ValueError:
                group_ids = []
            if len(group_ids) > 20:
                graph_err(w, 400, "Request_BadRequest")
                return
            if seg[1] not in self.users:
                graph_err(w, 404, "Request_ResourceNotFound")
                return
            out = [have for g in group_ids for have in self.groups.get(seg[1], []) if g.lower() == have.lower()]
            write(w, {"value": out})
        elif seg[0] == "groups" and len(seg) == 2:
            if q("$select") != "id,visibility":
                self.errors.append(f"group lookup without select: {r.query}")
            if seg[1] not in self.group_vis:
                graph_err(w, 404, "Request_ResourceNotFound")
                return
            vis = self.group_vis[seg[1]]
            write(w, {"id": seg[1], "visibility": vis if vis != "" else None})
        elif seg[0] == "users" and len(seg) == 4 and seg[2] == "transitiveMemberOf" and seg[3] == "microsoft.graph.directoryRole":
            if q("$select") != "roleTemplateId":
                self.errors.append(f"roles without select: {r.query}")
            if self.sp_denied:
                graph_err(w, 403, "Authorization_RequestDenied")
                return
            write(w, {"value": [{"roleTemplateId": id} for id in self.roles.get(seg[1], [])]})
        elif seg[0] == "teams" and len(seg) == 3 and seg[2] == "members":
            members = self.teams.get(seg[1])
            if members is None:
                graph_err(w, 404, "NotFound")
                return
            write(w, {"value": self.member_list(members, self.filter_user(r))})
        elif seg[0] == "teams" and len(seg) >= 4 and seg[2] == "channels":
            ch = self.channels.get(seg[3])
            if ch is None or self.teams.get(seg[1]) is None:
                graph_err(w, 404, "NotFound")
                return
            if len(seg) == 4:
                out: dict[str, Any] = {"id": seg[3]}
                if ch.membership_type != "":
                    out["membershipType"] = ch.membership_type
                if ch.moderation != "":
                    out["moderationSettings"] = {"userNewMessageRestriction": ch.moderation}
                write(w, out)
                return
            if (seg[4] == "members" and ch.membership_type == "private") or (seg[4] == "allMembers" and ch.membership_type == "shared"):
                write(w, {"value": self.member_list(ch.members, self.filter_user(r))})
            else:
                graph_err(w, 400, "BadRequest")
        elif seg[0] == "drives" and len(seg) == 2:
            if seg[1] != DRIVE or self.drive_hidden:
                graph_err(w, 404, "itemNotFound")
                return
            out = {"id": DRIVE}
            if self.owner != "":
                out["owner"] = {"user": {"id": self.owner}}
            write(w, out)
        elif seg[0] == "drives" and len(seg) == 5 and seg[2] == "items" and seg[4] == "permissions":
            perms = self.perms.get(seg[3])
            if seg[1] != DRIVE or perms is None:
                graph_err(w, 404, "itemNotFound")
                return
            write(w, {"value": perms})
        elif p == "servicePrincipals":
            if self.sp_denied:
                graph_err(w, 403, "Authorization_RequestDenied")
                return
            if q("$filter") != "appId eq '" + CLIENT_ID + "'":
                graph_err(w, 400, "BadRequest")
                return
            write(w, {"value": [{"id": OWN_SP}]})
        elif p == "servicePrincipals/" + OWN_SP + "/appRoleAssignments":
            write(w, {"value": [{"appRoleId": f"ffffffff-0000-0000-0000-{i:012d}", "resourceId": GRAPH_SP} for i in range(len(self.app_roles))]})
        elif p == "servicePrincipals/" + GRAPH_SP:
            write(w, {"appRoles": [{"id": f"ffffffff-0000-0000-0000-{i:012d}", "value": v} for i, v in enumerate(self.app_roles)]})
        else:
            self.errors.append(f"fake graph: no route for {r.method} {r.target}")
            graph_err(w, 404, "Request_ResourceNotFound")


# -- drive permissions as the fake serves them --------------------------------

PermOpt = Callable[[dict[str, Any]], None]


def perm(roles: list[str], *opts: PermOpt) -> dict[str, Any]:
    p: dict[str, Any] = {"roles": roles}
    for o in opts:
        o(p)
    return p


def to_user(id: str) -> PermOpt:
    def f(p: dict[str, Any]) -> None:
        p["grantedToV2"] = {"user": {"id": id}}

    return f


def to_group(id: str) -> PermOpt:
    def f(p: dict[str, Any]) -> None:
        p.setdefault("grantedToIdentitiesV2", []).append({"group": {"id": id}})

    return f


def to_site_group() -> PermOpt:
    def f(p: dict[str, Any]) -> None:
        p["grantedToV2"] = {"siteGroup": {"id": "5"}}

    return f


def link(scope: str) -> PermOpt:
    def f(p: dict[str, Any]) -> None:
        p["link"] = {"scope": scope}

    return f


# -- setup -----------------------------------------------------------------------


class Env:
    """Servers and fakes made by one test, checked when it ends."""

    def __init__(self) -> None:
        self.servers: list[itest.Server] = []
        self.fakes: list[FakeGraph] = []

    def server(self) -> itest.Server:
        srv = itest.Server()
        srv.use_spec(spec_from_env("msgraph"), SPEC_OPTIONS)
        self.servers.append(srv)
        return srv

    def fake(self) -> FakeGraph:
        f = FakeGraph()
        self.fakes.append(f)
        return f

    def setup(self, values: dict[str, str] | None = None) -> tuple[itest.Server, FakeGraph, Connection]:
        srv = self.server()
        f = self.fake()
        srv.handle("POST", "/" + TENANT_ID + "/oauth2/v2.0/token", f.token)
        srv.handle("", "/v1.0/*", f.graph)
        deps, _ = itest.deps(srv)
        v = {"tenant_id": TENANT_ID, "client_id": CLIENT_ID, "authority_url": srv.url, "url": srv.url}
        v.update(values or {})
        s = itest.settings("m365", "microsoft365", v, {"credential": itest.literal("secret")})
        c = Microsoft365().new(background(), s, deps)
        return srv, f, c

    def close(self) -> None:
        for srv in self.servers:
            srv.close()
        for srv in self.servers:
            assert not srv.spec_errors, "requests did not match the API description:\n" + "\n".join(srv.spec_errors)
        for f in self.fakes:
            assert not f.errors, "\n".join(f.errors)


@pytest.fixture
def env() -> Iterator[Env]:
    e = Env()
    yield e
    e.close()


dana = User(email="dana@example.com")
bob = User(email="bob@example.com")
guest = User(email="guest_gmail.com#EXT#@example.onmicrosoft.com")
off = User(email="off@example.com")


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, Microsoft365(), u, action, resource)


def resolve(c: Connection, u: User) -> tuple[Identity | None, BaseException | None]:
    try:
        return c.resolve_identity(background(), u), None
    except Exception as e:
        return None, e


def resolve_decision(c: Connection, u: User) -> Decision:
    _, err = resolve(c, u)
    assert err is not None, f"{u.email} resolved"
    return to_decision(err)


# -- authentication ---------------------------------------------------------


def test_client_secret_token_and_caching(env: Env) -> None:
    srv, f, c = env.setup()
    itest.expect_code(check(c, dana, "group.member", "group:" + GROUP_A), Code.ALLOWED)
    itest.expect_code(check(c, dana, "group.member", "group:" + GROUP_B), Code.DENIED)
    assert f.tokens_issued == 1, f"token fetched {f.tokens_issued} times, want 1 (cached)"
    token_calls = 0
    for call in srv.calls():
        if call.path.endswith("/oauth2/v2.0/token"):
            token_calls += 1
            body = call.body.decode()
            assert "scope=" + urllib.parse.quote_plus(srv.url + "/.default", safe="-_.~") in body, f"token form scope: {body}"
            assert call.header.get("Content-Type") == "application/x-www-form-urlencoded", f"token content type {call.header.get('Content-Type')!r}"
    assert token_calls == 1, f"{token_calls} token calls"


def test_wrong_secret_is_credential_rejected(env: Env) -> None:
    srv = env.server()
    f = env.fake()
    srv.handle("POST", "/" + TENANT_ID + "/oauth2/v2.0/token", f.token)
    srv.handle("", "/v1.0/*", f.graph)
    deps, _ = itest.deps(srv)
    s = itest.settings(
        "m365",
        "microsoft365",
        {"tenant_id": TENANT_ID, "client_id": CLIENT_ID, "authority_url": srv.url, "url": srv.url},
        {"credential": itest.literal("wrong")},
    )
    c = Microsoft365().new(background(), s, deps)
    itest.expect_code(check(c, dana, "group.member", "group:" + GROUP_A), Code.CREDENTIAL_REJECTED)


def test_retry_once_after401(env: Env) -> None:
    _, f, c = env.setup()
    itest.expect_code(check(c, dana, "group.member", "group:" + GROUP_A), Code.ALLOWED)
    with f.mu:
        f.expire401 = 1
    itest.expect_code(check(c, dana, "group.member", "group:" + GROUP_A), Code.ALLOWED)
    assert f.tokens_issued == 2, f"token fetched {f.tokens_issued} times, want 2 (refreshed after 401)"
    # A 401 that persists after one refresh is credential_rejected.
    with f.mu:
        f.expire401 = 10
    itest.expect_code(check(c, dana, "group.member", "group:" + GROUP_A), Code.CREDENTIAL_REJECTED)
    with f.mu:
        n = f.tokens_issued
    assert n == 3, f"token fetched {n} times, want 3 (one refresh, then the identity lookup gives up)"


def make_test_cert(tmp: str) -> tuple[Any, str, str, Any]:
    """A key and a self-signed certificate; the certificate is written to a
    file and the key returned as PEM."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hallpass-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    cert_file = os.path.join(tmp, "cert.pem")
    with open(cert_file, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode()
    return key, key_pem, cert_file, cert


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def test_certificate_assertion(env: Env, tmp_path: Any) -> None:
    key, key_pem, cert_file, cert = make_test_cert(str(tmp_path))
    srv = env.server()
    f = env.fake()
    token_url = srv.url + "/" + TENANT_ID + "/oauth2/v2.0/token"
    assertions = [0]
    errors: list[str] = []

    def token(w: itest.ResponseWriter, r: itest.Request) -> None:
        form = r.form()

        def fv(k: str) -> str:
            return (form.get(k) or [""])[0]

        if fv("client_secret") != "":
            errors.append("certificate mode sent a client_secret")
        if fv("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" or fv("grant_type") != "client_credentials":
            errors.append(f"form {form}")
        a = fv("client_assertion")
        parts = a.split(".")
        if len(parts) != 3:
            errors.append(f"assertion {a!r}")
            w.write_header(400)
            return
        hdr = json.loads(_b64url_decode(parts[0]))
        if hdr.get("alg") != "PS256" or hdr.get("typ") != "JWT" or hdr.get("x5t#S256") != cert_thumbprint_sha256(cert):
            errors.append(f"header {hdr}")
        try:
            verify(key.public_key(), PS256, (parts[0] + "." + parts[1]).encode(), _b64url_decode(parts[2]))
        except ValueError as e:
            errors.append(f"signature: {e}")
        claims = decode_jwt_claims(a)
        now = int(time.time())
        if (
            claims.get("aud") != token_url
            or claims.get("iss") != CLIENT_ID
            or claims.get("sub") != CLIENT_ID
            or not claims.get("jti")
            or claims.get("nbf", 0) > now
            or claims.get("iat", 0) > now
            or claims.get("exp", 0) < now + 4 * 60
            or claims.get("exp", 0) > now + 6 * 60
        ):
            errors.append(f"claims {claims}")
        assertions[0] += 1
        with f.mu:
            f.tokens_issued += 1
            f.tok = itest.CANARY + "certtok"
        write(w, {"access_token": itest.CANARY + "certtok", "expires_in": "3599"})

    srv.handle("POST", "/" + TENANT_ID + "/oauth2/v2.0/token", token)
    srv.handle("", "/v1.0/*", f.graph)
    deps, _ = itest.deps(srv)
    s = itest.settings(
        "m365",
        "microsoft365",
        {"tenant_id": TENANT_ID, "client_id": CLIENT_ID, "authority_url": srv.url, "url": srv.url, "certificate_file": cert_file},
        {"credential": secret_literal(key_pem)},
    )
    c = Microsoft365().new(background(), s, deps)
    itest.expect_code(check(c, dana, "group.member", "group:" + GROUP_A), Code.ALLOWED)
    itest.expect_code(check(c, dana, "team.owner", "team:" + TEAM_A), Code.ALLOWED)
    assert assertions[0] == 1, f"{assertions[0]} assertions, want 1 (token cached)"
    assert not errors, "\n".join(errors)

    # A missing certificate file is credential_rejected, not a crash.
    s = itest.settings(
        "m365",
        "microsoft365",
        {"tenant_id": TENANT_ID, "client_id": CLIENT_ID, "authority_url": srv.url, "url": srv.url, "certificate_file": cert_file + ".missing"},
        {"credential": secret_literal(key_pem)},
    )
    c2 = Microsoft365().new(background(), s, deps)
    itest.expect_code(check(c2, dana, "group.member", "group:" + GROUP_A), Code.CREDENTIAL_REJECTED)


def test_new_validation(env: Env) -> None:
    srv = env.server()
    deps, _ = itest.deps(srv)
    cases: list[dict[str, str]] = [
        {"client_id": CLIENT_ID},
        {"tenant_id": TENANT_ID},
        {"tenant_id": "not a tenant", "client_id": CLIENT_ID},
        {"tenant_id": TENANT_ID, "client_id": "abc"},
    ]
    for v in cases:
        s = itest.settings("m365", "microsoft365", v, {"credential": itest.literal("x")})
        with pytest.raises(Exception):  # noqa: B017 - Go only checks err != nil
            Microsoft365().new(background(), s, deps)
    s = itest.settings("m365", "microsoft365", {"tenant_id": "contoso.onmicrosoft.com", "client_id": CLIENT_ID})
    with pytest.raises(Exception):  # noqa: B017
        Microsoft365().new(background(), s, deps)
    s = itest.settings("m365", "microsoft365", {"tenant_id": "contoso.onmicrosoft.com", "client_id": CLIENT_ID}, {"credential": itest.literal("x")})
    c = Microsoft365().new(background(), s, deps)
    assert isinstance(c, Microsoft365Connection)
    assert c.token_url == "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token", c.token_url
    assert c.scope == "https://graph.microsoft.com/.default", c.scope
    validate_fields(Microsoft365().fields())


# -- identity ---------------------------------------------------------------


def test_resolve_identity(env: Env) -> None:
    srv, _, c = env.setup()
    id, err = resolve(c, dana)
    assert err is None and id is not None, err
    assert id.id == DANA_ID and id.attr("account_enabled") == "true" and id.attr("guest") == "false" and id.attr("mail") == "dana@example.com", id
    assert len(srv.calls()) == 2, f"direct lookup made {len(srv.calls())} calls"  # token + direct lookup
    last = srv.last_call()
    assert last.path == "/v1.0/users/dana@example.com" and last.q("$select") == USER_SELECT, f"direct lookup {last.path} {last.query}"

    # Guest UPN: #EXT# path-escaped, flagged.
    srv.reset()
    id, err = resolve(c, guest)
    assert err is None and id is not None and id.id == GUEST_ID and id.attr("guest") == "true", f"guest: {id} {err}"
    assert srv.last_call().path == "/v1.0/users/guest_gmail.com#EXT#@example.onmicrosoft.com", f"guest path {srv.last_call().path!r}"

    # mail filter fallback.
    srv.reset()
    id, err = resolve(c, User(email="dana.alias@example.com"))
    assert err is None and id is not None and id.id == DANA_ID, f"mail fallback: {id} {err}"
    calls = srv.calls()
    assert len(calls) == 2 and calls[1].q("$filter") == "mail eq 'dana.alias@example.com'", f"mail fallback calls: {calls}"

    # proxyAddresses fallback.
    srv.reset()
    id, err = resolve(c, User(email="dana.old@example.com"))
    assert err is None and id is not None and id.id == DANA_ID, f"proxy fallback: {id} {err}"
    calls = srv.calls()
    assert (
        len(calls) == 3
        and calls[2].q("$filter") == "proxyAddresses/any(p:p eq 'smtp:dana.old@example.com')"
        and calls[2].header.get("ConsistencyLevel") == "eventual"
    ), f"proxy fallback calls: {calls}"

    # Ambiguous, not found, disabled, bad address, quote escaping.
    itest.expect_code(resolve_decision(c, User(email="shared@example.com")), Code.USER_AMBIGUOUS)
    itest.expect_code(resolve_decision(c, User(email="nobody@example.com")), Code.USER_NOT_FOUND)
    id, err = resolve(c, off)
    assert err is None and id is not None and id.attr("account_enabled") == "false", f"disabled: {id} {err}"
    itest.expect_code(resolve_decision(c, User(email="not an email")), Code.INVALID_REQUEST)
    srv.reset()
    itest.expect_code(resolve_decision(c, User(email="o'neil@example.com")), Code.USER_NOT_FOUND)
    calls = srv.calls()
    assert calls[1].q("$filter") == "mail eq 'o''neil@example.com'", f"quote escaping: {calls[1].query}"


def test_disabled_account_denies_everything(env: Env) -> None:
    _, _, c = env.setup()
    d = check(c, off, "group.member", "group:" + GROUP_A)
    itest.expect_code(d, Code.DENIED)
    assert "disabled" in d.text, d.text
    itest.expect_code(check(c, off, "user.active", "user:off@example.com"), Code.DENIED)


def test_missing_account_enabled_is_unknown(env: Env) -> None:
    """A user whose accountEnabled Graph does not report is unknown for
    every action, never treated as enabled."""
    _, _, c = env.setup()
    nostate = User(email="nostate@example.com")
    id, err = resolve(c, nostate)
    assert err is None and id is not None and id.attr("account_enabled") == "unknown", f"{id} {err}"
    # nostate is in GROUP_A, so only the enabled state keeps this from allow.
    d = check(c, nostate, "group.member", "group:" + GROUP_A)
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "enabled" in d.text, d.text
    itest.expect_code(check(c, nostate, "user.active", "user:nostate@example.com"), Code.UNSUPPORTED)
    itest.expect_code(check(c, nostate, "mail.send_as_self", "mailbox:nostate@example.com"), Code.UNSUPPORTED)


def test_email_path_escaping(env: Env) -> None:
    """Email local parts may contain "%" and "/"; both must be path-escaped
    so the lookup stays one segment. The fake routes on the escaped path, so
    an unescaped "/" would miss the users route and "%" would not build a URL."""
    srv, f, c = env.setup()
    cases = [
        ("a%b@example.com", DANA_ID, "/v1.0/users/a%25b@example.com"),
        ("a/b@example.com", BOB_ID, "/v1.0/users/a%2Fb@example.com"),
        ("guest_gmail.com#EXT#@example.onmicrosoft.com", GUEST_ID, "/v1.0/users/guest_gmail.com%23EXT%23@example.onmicrosoft.com"),
    ]
    for email, id, path in cases:
        srv.reset()
        got, err = resolve(c, User(email=email))
        assert err is None and got is not None and got.id == id, f"{email}: {got} {err}"
        # The token is cached after the first case; the lookup must be
        # direct (one Graph call), never fall back to the mail filter.
        graph_calls = [call for call in srv.calls() if call.path.startswith("/v1.0/")]
        assert len(graph_calls) == 1, f"{email}: {len(graph_calls)} Graph calls, want 1 direct lookup"
        assert f.escaped_path() == path, f"{email}: escaped path {f.escaped_path()!r}, want {path!r}"


def test_guest_flagged_in_reason(env: Env) -> None:
    _, f, c = env.setup()
    f.groups[GUEST_ID] = [GROUP_A]
    d = check(c, guest, "group.member", "group:" + GROUP_A)
    itest.expect_code(d, Code.ALLOWED)
    assert "guest account" in d.text, d.text


# -- actions ----------------------------------------------------------------


def test_action_user_active_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "user.active", "user:dana@example.com"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "user.active", "user:" + DANA_ID), Code.ALLOWED)
    itest.expect_code(check(c, dana, "user.active", "mailbox:DANA@example.com"), Code.ALLOWED)


def test_action_user_active_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, off, "user.active", "user:off@example.com"), Code.DENIED)
    itest.expect_code(check(c, dana, "user.active", "user:bob@example.com"), Code.UNSUPPORTED)


def test_action_group_member_allow(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "group.member", "group:" + GROUP_A), Code.ALLOWED)
    last = srv.last_call()
    assert last.method == "POST" and last.path == "/v1.0/users/" + DANA_ID + "/checkMemberGroups", f"{last.method} {last.path}"
    body = last.json()
    assert body.get("groupIds") == [GROUP_A], f"body {body}"


def test_action_group_member_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "group.member", "group:" + GROUP_B), Code.DENIED)
    itest.expect_code(check(c, bob, "group.member", "group:" + GROUP_A), Code.DENIED)


def test_group_missing_or_hidden(env: Env) -> None:
    """A group that does not exist is not visible, and a hidden-membership
    group the user is not seen in is unknown: checkMemberGroups omits both."""
    srv, f, c = env.setup()
    itest.expect_code(check(c, dana, "group.member", "group:" + GROUP_MISSING), Code.RESOURCE_NOT_VISIBLE)
    d = check(c, dana, "group.member", "group:" + GROUP_HIDDEN)
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "Member.Read.Hidden" in d.text, d.text
    # Proven membership in a hidden group is still an allow.
    f.groups[DANA_ID] = [*f.groups[DANA_ID], GROUP_HIDDEN]
    itest.expect_code(check(c, dana, "group.member", "group:" + GROUP_HIDDEN), Code.ALLOWED)
    # The visibility lookup precedes checkMemberGroups.
    srv.reset()
    itest.expect_code(check(c, dana, "group.member", "group:" + GROUP_A), Code.ALLOWED)
    paths = [call.method + " " + call.path for call in srv.calls()]
    want = ["GET /v1.0/users/dana@example.com", "GET /v1.0/groups/" + GROUP_A, "POST /v1.0/users/" + DANA_ID + "/checkMemberGroups"]
    assert paths == want, f"calls {paths}"


def test_membership_ignores_unfiltered_roster(env: Env) -> None:
    """The members $filter is never trusted: when the upstream returns the
    whole roster, only the caller's own record counts."""
    _, f, c = env.setup()
    f.ignore_filter = True
    itest.expect_code(check(c, guest, "team.member", "team:" + TEAM_A), Code.DENIED)
    itest.expect_code(check(c, bob, "team.owner", "team:" + TEAM_A), Code.DENIED)
    itest.expect_code(check(c, bob, "channel.read", "team:" + TEAM_A + "/channel/" + CHAN_PRIV), Code.DENIED)
    itest.expect_code(check(c, bob, "channel.owner", "team:" + TEAM_A + "/channel/" + CHAN_SHR), Code.DENIED)
    # Real members are still found in the roster.
    itest.expect_code(check(c, bob, "team.member", "team:" + TEAM_A), Code.ALLOWED)
    itest.expect_code(check(c, dana, "team.owner", "team:" + TEAM_A), Code.ALLOWED)
    itest.expect_code(check(c, dana, "channel.read", "team:" + TEAM_A + "/channel/" + CHAN_PRIV), Code.ALLOWED)


def test_channel_without_membership_type_is_unknown(env: Env) -> None:
    """A channel without a membershipType is not assumed to be standard."""
    srv, _, c = env.setup()
    d = check(c, bob, "channel.read", "team:" + TEAM_A + "/channel/" + CHAN_NO_TYPE)
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "membership type" in d.text, d.text
    assert not srv.last_call().path.endswith("/members"), "consulted the team roster for a channel of unknown type"
    itest.expect_code(check(c, bob, "channel.message.post", "team:" + TEAM_A + "/channel/" + CHAN_NO_TYPE), Code.UNSUPPORTED)
    itest.expect_code(check(c, dana, "channel.owner", "team:" + TEAM_A + "/channel/" + CHAN_NO_TYPE), Code.UNSUPPORTED)


def test_check_member_groups_batching(env: Env) -> None:
    srv, f, c = env.setup()
    ids = [f"bbbbbbbb-1111-0000-0000-{i:012d}" for i in range(45)]
    f.perms["item1"] = [perm(["read"], to_group(g)) for g in ids]
    f.groups[DANA_ID] = [ids[44]]
    srv.reset()
    itest.expect_code(check(c, dana, "file.read", "drive:" + DRIVE + "/item/item1"), Code.ALLOWED)
    batches = [len(call.json()["groupIds"]) for call in srv.calls() if call.path.endswith("/checkMemberGroups")]
    assert batches == [20, 20, 5], f"batches {batches}"


def test_action_role_member_allow(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "role.member", "role:" + ROLE_A.upper()), Code.ALLOWED)
    assert srv.last_call().path.endswith("/transitiveMemberOf/microsoft.graph.directoryRole"), srv.last_call().path


def test_action_role_member_deny(env: Env) -> None:
    _, f, c = env.setup()
    itest.expect_code(check(c, bob, "role.member", "role:" + ROLE_A), Code.DENIED)
    f.sp_denied = True
    d = check(c, bob, "role.member", "role:" + ROLE_A)
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)
    assert "RoleManagement.Read.Directory" in d.text, d.text


def test_action_team_member_allow(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, bob, "team.member", "team:" + TEAM_A), Code.ALLOWED)
    last = srv.last_call()
    assert (
        last.path == "/v1.0/teams/" + TEAM_A + "/members" and last.q("$filter") == "(microsoft.graph.aadUserConversationMember/userId eq '" + BOB_ID + "')"
    ), f"{last.path} {last.query}"


def test_action_team_member_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, guest, "team.member", "team:" + TEAM_A), Code.DENIED)
    itest.expect_code(check(c, dana, "team.member", "team:dddddddd-0000-0000-0000-000000000099"), Code.RESOURCE_NOT_VISIBLE)


def test_action_team_owner_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "team.owner", "team:" + TEAM_A), Code.ALLOWED)


def test_action_team_owner_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, bob, "team.owner", "team:" + TEAM_A), Code.DENIED)


def test_action_channel_read_allow(env: Env) -> None:
    srv, _, c = env.setup()
    # Standard channel: team membership.
    itest.expect_code(check(c, bob, "channel.read", "team:" + TEAM_A + "/channel/" + CHAN_STD), Code.ALLOWED)
    assert srv.last_call().path == "/v1.0/teams/" + TEAM_A + "/members", srv.last_call().path
    # Private channel: channel membership.
    itest.expect_code(check(c, dana, "channel.read", "team:" + TEAM_A + "/channel/" + CHAN_PRIV), Code.ALLOWED)
    assert srv.last_call().path == "/v1.0/teams/" + TEAM_A + "/channels/" + CHAN_PRIV + "/members", srv.last_call().path
    # Shared channel: allMembers.
    itest.expect_code(check(c, dana, "channel.read", "team:" + TEAM_A + "/channel/" + CHAN_SHR), Code.ALLOWED)
    assert srv.last_call().path == "/v1.0/teams/" + TEAM_A + "/channels/" + CHAN_SHR + "/allMembers", srv.last_call().path


def test_action_channel_read_deny(env: Env) -> None:
    _, _, c = env.setup()
    # Bob is in the team but not in the private channel.
    itest.expect_code(check(c, bob, "channel.read", "team:" + TEAM_A + "/channel/" + CHAN_PRIV), Code.DENIED)
    itest.expect_code(check(c, guest, "channel.read", "team:" + TEAM_A + "/channel/" + CHAN_STD), Code.DENIED)
    itest.expect_code(check(c, dana, "channel.read", "team:" + TEAM_A + "/channel/19:missing@thread.tacv2"), Code.RESOURCE_NOT_VISIBLE)


def test_action_channel_owner_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "channel.owner", "team:" + TEAM_A + "/channel/" + CHAN_STD), Code.ALLOWED)
    itest.expect_code(check(c, dana, "channel.owner", "team:" + TEAM_A + "/channel/" + CHAN_SHR), Code.ALLOWED)


def test_action_channel_owner_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, bob, "channel.owner", "team:" + TEAM_A + "/channel/" + CHAN_STD), Code.DENIED)
    itest.expect_code(check(c, dana, "channel.owner", "team:" + TEAM_A + "/channel/" + CHAN_PRIV), Code.DENIED)


def test_action_channel_message_post_allow(env: Env) -> None:
    _, _, c = env.setup()
    d = check(c, bob, "channel.message.post", "team:" + TEAM_A + "/channel/" + CHAN_STD)
    itest.expect_code(d, Code.ALLOWED)
    assert "moderation" in d.text, d.text


def test_action_channel_message_post_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, bob, "channel.message.post", "team:" + TEAM_A + "/channel/" + CHAN_PRIV), Code.DENIED)
    # Moderated channel: unknown even for a member.
    itest.expect_code(check(c, bob, "channel.message.post", "team:" + TEAM_A + "/channel/" + CHAN_MOD), Code.UNSUPPORTED)


def file_res(item: str) -> str:
    return "drive:" + DRIVE + "/item/" + item


def test_action_file_read_allow(env: Env) -> None:
    _, f, c = env.setup()
    f.perms["direct"] = [perm(["read"], to_user(DANA_ID))]
    itest.expect_code(check(c, dana, "file.read", file_res("direct")), Code.ALLOWED)
    f.perms["group"] = [perm(["write"], to_group(GROUP_A))]
    d = check(c, dana, "file.read", file_res("group"))
    itest.expect_code(d, Code.ALLOWED)
    assert "group" in d.text, d.text
    f.perms["orglink"] = [perm(["read"], link("organization"))]
    d = check(c, bob, "file.read", file_res("orglink"))
    itest.expect_code(d, Code.ALLOWED)
    assert "organization-wide sharing link" in d.text, d.text
    # Drive owner.
    f.perms["owned"] = []
    f.owner = BOB_ID
    itest.expect_code(check(c, bob, "file.read", file_res("owned")), Code.ALLOWED)


def test_action_file_read_deny(env: Env) -> None:
    _, f, c = env.setup()
    f.perms["other"] = [perm(["owner"], to_user(BOB_ID)), perm(["read"], to_group(GROUP_B))]
    itest.expect_code(check(c, dana, "file.read", file_res("other")), Code.DENIED)
    f.perms["none"] = []
    itest.expect_code(check(c, dana, "file.read", file_res("none")), Code.DENIED)
    itest.expect_code(check(c, dana, "file.read", file_res("missing")), Code.RESOURCE_NOT_VISIBLE)
    # siteGroup-only grants and anonymous links cannot be evaluated.
    f.perms["sitegroup"] = [perm(["read"], to_site_group())]
    itest.expect_code(check(c, dana, "file.read", file_res("sitegroup")), Code.UNSUPPORTED)
    f.perms["anon"] = [perm(["read"], link("anonymous"))]
    itest.expect_code(check(c, dana, "file.read", file_res("anon")), Code.UNSUPPORTED)


def test_guest_cannot_use_organization_link(env: Env) -> None:
    """A guest cannot redeem an organization-scope link, so it is not
    credited; other grants still apply."""
    _, f, c = env.setup()
    f.perms["orglink"] = [perm(["write"], link("organization"))]
    d = check(c, guest, "file.read", file_res("orglink"))
    itest.expect_code(d, Code.DENIED)
    assert "guest" in d.text, d.text
    # A direct grant or a group grant on the same item is still evaluated.
    f.perms["orglink-direct"] = [perm(["write"], link("organization")), perm(["read"], to_user(GUEST_ID))]
    itest.expect_code(check(c, guest, "file.read", file_res("orglink-direct")), Code.ALLOWED)
    itest.expect_code(check(c, guest, "file.edit", file_res("orglink-direct")), Code.DENIED)
    f.groups[GUEST_ID] = [GROUP_A]
    f.perms["orglink-group"] = [perm(["write"], link("organization")), perm(["write"], to_group(GROUP_A))]
    itest.expect_code(check(c, guest, "file.edit", file_res("orglink-group")), Code.ALLOWED)
    # Members still use the link.
    itest.expect_code(check(c, bob, "file.edit", file_res("orglink")), Code.ALLOWED)


def test_drive_owner_lookup404_is_ignored(env: Env) -> None:
    """A 404 on the drive-owner lookup does not end the evaluation: group
    and link rules still run."""
    srv, f, c = env.setup()
    f.drive_hidden = True
    f.perms["group"] = [perm(["write"], to_group(GROUP_A))]
    itest.expect_code(check(c, dana, "file.edit", file_res("group")), Code.ALLOWED)
    f.perms["orglink"] = [perm(["read"], link("organization"))]
    itest.expect_code(check(c, bob, "file.read", file_res("orglink")), Code.ALLOWED)
    f.perms["none"] = [perm(["owner"], to_user(BOB_ID))]
    itest.expect_code(check(c, dana, "file.read", file_res("none")), Code.DENIED)
    # The lookup was attempted and answered 404.
    assert any(call.path == "/v1.0/drives/" + DRIVE for call in srv.calls()), "drive owner was not looked up"
    # Other failures on the lookup still surface.
    srv.json("GET", "/v1.0/drives/" + DRIVE, 500, '{"error":{"code":"x","message":"' + itest.CANARY + 'm"}}')
    itest.expect_code(check(c, dana, "file.read", file_res("none")), Code.UPSTREAM_ERROR)


def test_unknown_role_or_link_scope_is_unknown(env: Env) -> None:
    """Unrecognised role strings on a grant that reaches the caller, and
    sharing links with an unmodelled scope, are unknown rather than deny."""
    _, f, c = env.setup()
    f.perms["custom"] = [perm(["sp.full control"], to_user(DANA_ID))]
    d = check(c, dana, "file.edit", file_res("custom"))
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "does not model" in d.text, d.text
    # Read plus a custom level: the custom level may include write.
    f.perms["read-custom"] = [perm(["read", "sp.views"], to_user(DANA_ID))]
    itest.expect_code(check(c, dana, "file.edit", file_res("read-custom")), Code.UNSUPPORTED)
    itest.expect_code(check(c, dana, "file.read", file_res("read-custom")), Code.ALLOWED)
    # Via a group the caller is in.
    f.perms["group-custom"] = [perm(["sp.full control"], to_group(GROUP_A))]
    itest.expect_code(check(c, dana, "file.delete", file_res("group-custom")), Code.UNSUPPORTED)
    # Via a group the caller is not in, or on another user: still deny.
    f.perms["other-custom"] = [perm(["sp.full control"], to_user(BOB_ID)), perm(["sp.views"], to_group(GROUP_B))]
    itest.expect_code(check(c, dana, "file.read", file_res("other-custom")), Code.DENIED)
    # On an organization link, for a member but not for a guest.
    f.perms["link-custom"] = [perm(["sp.views"], link("organization"))]
    itest.expect_code(check(c, dana, "file.read", file_res("link-custom")), Code.UNSUPPORTED)
    itest.expect_code(check(c, guest, "file.read", file_res("link-custom")), Code.DENIED)
    # A link scope hallpass does not model.
    f.perms["scope"] = [perm(["read"], link("existingAccess"))]
    d = check(c, dana, "file.read", file_res("scope"))
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "existingAccess" in d.text, d.text
    # A "users" link lists its people in grantedToIdentitiesV2: handled there.
    f.perms["users"] = [perm(["read"], link("users"), to_group(GROUP_A))]
    itest.expect_code(check(c, dana, "file.read", file_res("users")), Code.ALLOWED)
    itest.expect_code(check(c, bob, "file.read", file_res("users")), Code.DENIED)


def test_action_file_edit_allow(env: Env) -> None:
    _, f, c = env.setup()
    f.perms["w"] = [perm(["write"], to_user(DANA_ID))]
    itest.expect_code(check(c, dana, "file.edit", file_res("w")), Code.ALLOWED)
    f.perms["o"] = [perm(["owner"], to_group(GROUP_A))]
    itest.expect_code(check(c, dana, "file.edit", file_res("o")), Code.ALLOWED)


def test_action_file_edit_deny(env: Env) -> None:
    _, f, c = env.setup()
    f.perms["r"] = [perm(["read"], to_user(DANA_ID)), perm(["read"], link("organization"))]
    d = check(c, dana, "file.edit", file_res("r"))
    itest.expect_code(d, Code.DENIED)
    assert "read access" in d.text, d.text
    # A read grant plus a siteGroup write grant: unknown, not deny.
    f.perms["sg"] = [perm(["read"], to_user(DANA_ID)), perm(["write"], to_site_group())]
    itest.expect_code(check(c, dana, "file.edit", file_res("sg")), Code.UNSUPPORTED)


def test_action_file_share_allow(env: Env) -> None:
    _, f, c = env.setup()
    f.perms["own"] = [perm(["owner"], to_user(DANA_ID))]
    itest.expect_code(check(c, dana, "file.share", file_res("own")), Code.ALLOWED)


def test_action_file_share_deny(env: Env) -> None:
    _, f, c = env.setup()
    f.perms["none"] = [perm(["owner"], to_user(BOB_ID))]
    itest.expect_code(check(c, dana, "file.share", file_res("none")), Code.DENIED)
    f.perms["w"] = [perm(["write"], to_user(DANA_ID))]
    d = check(c, dana, "file.share", file_res("w"))
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "site settings" in d.text, d.text


def test_action_file_delete_allow(env: Env) -> None:
    _, f, c = env.setup()
    f.perms["w"] = [perm(["write"], to_user(DANA_ID))]
    itest.expect_code(check(c, dana, "file.delete", file_res("w")), Code.ALLOWED)


def test_action_file_delete_deny(env: Env) -> None:
    _, f, c = env.setup()
    f.perms["r"] = [perm(["read"], to_user(DANA_ID))]
    itest.expect_code(check(c, dana, "file.delete", file_res("r")), Code.DENIED)


def test_action_mail_send_as_self_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "mail.send_as_self", "mailbox:Dana@Example.com"), Code.ALLOWED)


def test_action_mail_send_as_self_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, off, "mail.send_as_self", "mailbox:off@example.com"), Code.DENIED)
    itest.expect_code(check(c, dana, "mail.send_as_self", "mailbox:bob@example.com"), Code.UNSUPPORTED)


def test_send_as_self_without_mail_is_unknown(env: Env) -> None:
    """An empty mail attribute does not prove there is no mailbox: unknown."""
    _, f, c = env.setup()
    f.users[BOB_ID] = dataclasses.replace(f.users[BOB_ID], mail="")
    d = check(c, bob, "mail.send_as_self", "mailbox:bob@example.com")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "mail attribute" in d.text, d.text


def always_unknown(env: Env, action: str) -> None:
    """Exchange delegation and calendar access on another mailbox are always
    unknown; both the allow and the deny tests assert that."""
    srv, _, c = env.setup()
    d = check(c, dana, action, "mailbox:bob@example.com")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "Graph API" in d.text, d.text
    itest.expect_code(check(c, dana, action, "mailbox:dana@example.com"), Code.UNSUPPORTED)
    for call in srv.calls():
        assert "mail" not in call.path and "calendar" not in call.path, f"unexpected call {call.path}"
    # A disabled account is still a deny.
    itest.expect_code(check(c, off, action, "mailbox:bob@example.com"), Code.DENIED)


def test_action_mail_send_as_allow(env: Env) -> None:
    always_unknown(env, "mail.send_as")


def test_action_mail_send_as_deny(env: Env) -> None:
    always_unknown(env, "mail.send_as")


def test_action_mail_send_on_behalf_allow(env: Env) -> None:
    always_unknown(env, "mail.send_on_behalf")


def test_action_mail_send_on_behalf_deny(env: Env) -> None:
    always_unknown(env, "mail.send_on_behalf")


def test_action_mailbox_full_access_allow(env: Env) -> None:
    always_unknown(env, "mailbox.full_access")


def test_action_mailbox_full_access_deny(env: Env) -> None:
    always_unknown(env, "mailbox.full_access")


def test_action_calendar_read_allow(env: Env) -> None:
    always_unknown(env, "calendar.read")


def test_action_calendar_read_deny(env: Env) -> None:
    always_unknown(env, "calendar.read")


def test_action_calendar_write_allow(env: Env) -> None:
    always_unknown(env, "calendar.write")


def test_action_calendar_write_deny(env: Env) -> None:
    always_unknown(env, "calendar.write")


# -- resources and errors ---------------------------------------------------

BAD_RESOURCES = [
    ("group.member", "group:not-a-guid"),
    ("group.member", "team:" + TEAM_A),
    ("role.member", "role:" + ROLE_A + "?x=1"),
    ("team.member", "team:" + TEAM_A + "/channel/" + CHAN_STD),
    ("channel.read", "team:" + TEAM_A),
    ("channel.read", "team:" + TEAM_A + "/chan/" + CHAN_STD),
    ("channel.read", "team:" + TEAM_A + "/channel/bad channel"),
    ("file.read", "drive:" + DRIVE),
    ("file.read", "drive:" + DRIVE + "/items/x"),
    ("file.read", "drive:bad/drive/item/x"),
    ("file.read", "drive:" + DRIVE + "/item/a b"),
    ("user.active", "group:" + GROUP_A),
    ("mail.send_as_self", "mailbox:nope"),
]


def test_bad_resources(env: Env) -> None:
    _, _, c = env.setup()
    for action, resource in BAD_RESOURCES:
        d = check(c, dana, action, resource)
        assert d.code == Code.INVALID_REQUEST, f"{action} {resource} -> {d.code}: {d.text}"


def test_graph_errors_never_leak_message(env: Env) -> None:
    srv, f, c = env.setup()
    f.sp_denied = True
    d = check(c, dana, "role.member", "role:" + ROLE_A)
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)
    itest.assert_no_canary(d.text)
    srv.json("POST", "/v1.0/users/" + DANA_ID + "/checkMemberGroups", 403, '{"error":{"code":"Other","message":"' + itest.CANARY + 'm"}}')
    d = check(c, dana, "group.member", "group:" + GROUP_A)
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)
    itest.assert_no_canary(d.text)
    assert error_code(None) == "", "nil error has a code"


def test_failures(env: Env) -> None:
    srv, _, c = env.setup()
    # Warm the token cache so the failure modes hit Graph, then the token
    # endpoint on refresh.
    itest.expect_code(check(c, dana, "group.member", "group:" + GROUP_A), Code.ALLOWED)
    itest.failure_cases(srv, lambda: check(c, dana, "group.member", "group:" + GROUP_A))


def test_failures_at_token_endpoint(env: Env) -> None:
    srv, _, c = env.setup()
    itest.failure_cases(srv, lambda: check(c, dana, "group.member", "group:" + GROUP_A))


def test_pagination(env: Env) -> None:
    srv, _, c = env.setup()
    srv.json(
        "GET",
        "/v1.0/users/" + DANA_ID + "/transitiveMemberOf/microsoft.graph.directoryRole",
        200,
        '{"value":[{"roleTemplateId":"' + GROUP_B + '"}],"@odata.nextLink":"' + srv.url + '/v1.0/page2"}',
    )
    srv.json("GET", "/v1.0/page2", 200, '{"value":[{"roleTemplateId":"' + ROLE_A + '"}]}')
    itest.expect_code(check(c, dana, "role.member", "role:" + ROLE_A), Code.ALLOWED)
    srv.json("GET", "/v1.0/page2", 200, '{"value":[],"@odata.nextLink":"https://evil.example/v1.0/x"}')
    itest.expect_code(check(c, dana, "role.member", "role:" + ROLE_A), Code.UPSTREAM_ERROR)


# -- probe ------------------------------------------------------------------


def test_probe(env: Env) -> None:
    _, f, c = env.setup()
    r = c.probe(background())
    assert "Example Ltd" in r.summary and CLIENT_ID in r.summary, r.summary
    joined = "\n".join(r.warnings)
    assert "Files.Read.All" in joined and "Member.Read.Hidden" in joined, f"warnings: {joined!r}"
    assert "allows writes" not in joined, f"no write role granted but warned: {joined!r}"

    f.app_roles = ["User.Read.All", "Directory.ReadWrite.All", "Mail.Send"]
    r = c.probe(background())
    joined = "\n".join(r.warnings)
    for want in ("Directory.ReadWrite.All allows writes", "Mail.Send allows writes", "GroupMember.Read.All is not granted", "Files.Read.All is not granted"):
        assert want in joined, f"missing {want!r} in {joined!r}"

    f.sp_denied = True
    r = c.probe(background())
    assert len(r.warnings) == 1 and "could not verify permissions" in r.warnings[0], r


def test_probe_bad_credential(env: Env) -> None:
    srv, f, c = env.setup()
    with f.mu:
        f.tok = "x"
    srv.json("POST", "/" + TENANT_ID + "/oauth2/v2.0/token", 401, '{"error":"invalid_client","error_description":"' + itest.CANARY + 'nope"}')
    with pytest.raises(Exception) as ei:
        c.probe(background())
    itest.expect_code(to_decision(ei.value), Code.CREDENTIAL_REJECTED)
    itest.assert_no_canary(str(ei.value))


def test_actions_listed() -> None:
    for a in ACTION_LIST:
        assert find_action(Microsoft365(), a.name) is not None, f"{a.name} not found"
    assert len(Microsoft365().actions()) == 18, f"{len(Microsoft365().actions())} actions"
