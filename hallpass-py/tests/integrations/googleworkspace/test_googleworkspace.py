"""Port of internal/integrations/googleworkspace/googleworkspace_test.go."""

from __future__ import annotations

import base64
import functools
import json
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest

from hallpass.authx.jwt import RS256, Header, decode_jwt_claims, sign_jwt, verify
from hallpass.core.context import background
from hallpass.core.decision import Code, Decision, to_decision
from hallpass.core.integration import Connection, Identity, User, find_action, validate_fields
from hallpass.core.secret import Secret
from hallpass.core.secret import literal as secret_literal
from hallpass.integrations.googleworkspace import GoogleWorkspace, GoogleWorkspaceConnection
from hallpass.integrations.googleworkspace.actions import ACTION_LIST
from hallpass.integrations.googleworkspace.googleworkspace import (
    DEFAULT_API,
    MAX_SOURCES,
    MODE_KEY,
    MODE_KEYLESS,
    SCOPE_CALENDAR,
    SCOPE_DIRECTORY_GROUP,
    SCOPE_DIRECTORY_USER,
    SCOPE_DRIVE,
    SCOPE_GMAIL_SETTINGS,
    validate_http_url,
)
from tests import harness as itest
from tests.harness.spec import SpecOptions, any_spec, spec_from_env

ADMIN_EMAIL = "hallpass-admin@example.com"
SA_EMAIL = "hallpass@proj.iam.gserviceaccount.com"
FILE_A = "1AbCdEfGhIjKlMnOpQrStUvWxYz"
FILE_B = "1BbCdEfGhIjKlMnOpQrStUvWxYz"
FILE_NO_CAPS = "1CbCdEfGhIjKlMnOpQrStUvWxYz"

SPEC_OPTIONS = SpecOptions(ignore_paths=(r"^/token$", "/computeMetadata/", r":signJwt$"))


def specs() -> Any:
    return any_spec(spec_from_env("google-directory"), spec_from_env("google-drive"), spec_from_env("google-calendar"), spec_from_env("google-gmail"))


@functools.cache
def signing_key() -> Any:
    """Generated once per module; the tests only need it to be a valid RSA
    key that the fake token endpoint can verify against."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def api_err(w: itest.ResponseWriter, status: int, reason: str) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write(f'{{"error":{{"code":{status},"message":"{itest.CANARY}msg","errors":[{{"domain":"global","reason":"{reason}"}}]}}}}')


def write(w: itest.ResponseWriter, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write(json.dumps(v) + "\n")


class FakeUser:
    """A Directory user as the fake serves it; a None suspended or archived
    is left out of the body."""

    def __init__(self, id: str, primary_email: str, suspended: bool | None = None, archived: bool | None = None) -> None:
        self.id, self.primary_email, self.suspended, self.archived = id, primary_email, suspended, archived


class FakeGoogle:
    """An in-memory token endpoint plus the API subset hallpass uses."""

    def __init__(self) -> None:
        self.key = signing_key()
        self.kid = itest.CANARY + "kid"
        self.mu = threading.Lock()
        self.errors: list[str] = []
        self.tokens: dict[str, tuple[str, str]] = {}  # access token -> (sub, scope)
        self.minted: dict[tuple[str, str], int] = {}  # per pair count
        self.bad_grant: dict[str, bool] = {"nodelegation@example.com": True}  # sub -> invalid_grant
        self.expire401 = 0  # next n API calls answer 401
        self.meta_calls = 0
        self.sign_calls = 0
        self.keyless_iss = ""
        tr, fl = True, False
        self.users = {
            "dana@example.com": FakeUser("100", "dana@example.com", False, False),
            "bob@example.com": FakeUser("101", "bob@example.com", False, False),
            "sus@example.com": FakeUser("102", "sus@example.com", True, False),
            "arch@example.com": FakeUser("103", "arch@example.com", False, True),
            "nodelegation@example.com": FakeUser("104", "nodelegation@example.com", False, False),
            # nostatus comes without suspended and archived.
            "nostatus@example.com": FakeUser("105", "nostatus@example.com"),
            # noarch has suspended but no archived.
            "noarch@example.com": FakeUser("106", "noarch@example.com", False),
        }
        self.aliases = {"d.alias@example.com": "dana@example.com"}
        caps = ["canDownload", "canEdit", "canComment", "canShare", "canTrash", "canDelete", "canRename", "canCopy", "canAddChildren", "canListChildren"]
        self.files: dict[str, dict[str, Any]] = {
            FILE_A: {"capabilities": dict.fromkeys(caps, tr), "trashed": fl},
            FILE_B: {"capabilities": dict.fromkeys(caps, fl), "trashed": tr},
            FILE_NO_CAPS: {"capabilities": {}},
        }
        self.visible = {FILE_A: ["dana@example.com"], FILE_B: ["dana@example.com", "bob@example.com"], FILE_NO_CAPS: ["dana@example.com"]}
        self.calendars = {
            "dana@example.com": {
                "team@group.calendar.google.com": "writer",
                "fb@example.com": "freeBusyReader",
                "ro@example.com": "reader",
                "wwpa@example.com": "writerWithoutPrivateAccess",
                "mine@example.com": "owner",
                "odd@example.com": "editor",
            },
        }
        self.send_as: dict[str, list[dict[str, Any]]] = {
            # The primary entry carries no verificationStatus, like Gmail's
            # documented example; the others are custom "from" aliases.
            "dana@example.com": [
                {"sendAsEmail": "dana@example.com", "isPrimary": True, "isDefault": True},
                {"sendAsEmail": "support@example.com", "verificationStatus": "accepted"},
                {"sendAsEmail": "pending@example.com", "verificationStatus": "pending"},
                {"sendAsEmail": "unspec@example.com", "verificationStatus": "verificationStatusUnspecified", "treatAsAlias": True},
                {"sendAsEmail": "blank@example.com", "treatAsAlias": True},
            ],
            # bob's list lacks the primary entry altogether.
            "bob@example.com": [{"sendAsEmail": "team@example.com", "verificationStatus": "accepted"}],
        }
        self.delegates: dict[str, list[dict[str, str]]] = {
            "boss@example.com": [
                {"delegateEmail": "dana@example.com", "verificationStatus": "accepted"},
                {"delegateEmail": "bob@example.com", "verificationStatus": "pending"},
                {"delegateEmail": "nostatus@example.com", "verificationStatus": "verificationStatusUnspecified"},
            ],
        }
        self.group_members = {"eng@example.com": ["dana@example.com"]}  # group -> members; missing group -> 404
        self.no_is_member = False  # hasMember answers {} without isMember

    def token_url(self, srv: itest.Server) -> str:
        return srv.url + "/token"

    def token(self, srv: itest.Server) -> itest.Handler:
        """The OAuth token endpoint: it verifies the JWT bearer assertion."""

        def h(w: itest.ResponseWriter, r: itest.Request) -> None:
            form = r.form()

            def fv(k: str) -> str:
                return (form.get(k) or [""])[0]

            with self.mu:

                def fail(code: str) -> None:
                    w.header().set("Content-Type", "application/json")
                    w.write_header(400)
                    w.write('{"error":"' + code + '","error_description":"' + itest.CANARY + 'desc"}')

                if fv("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer":
                    fail("unsupported_grant_type")
                    return
                a = fv("assertion")
                parts = a.split(".")
                if len(parts) != 3:
                    fail("invalid_request")
                    return
                try:
                    hdr = json.loads(_b64url_decode(parts[0]))
                except ValueError:
                    hdr = {}
                if hdr.get("alg") != "RS256" or hdr.get("typ") != "JWT" or hdr.get("kid") != self.kid:
                    self.errors.append(f"assertion header {hdr}")
                    fail("invalid_request")
                    return
                try:
                    verify(self.key.public_key(), RS256, (parts[0] + "." + parts[1]).encode(), _b64url_decode(parts[2]))
                except ValueError as e:
                    self.errors.append(f"assertion signature: {e}")
                    fail("invalid_grant")
                    return
                cl = decode_jwt_claims(a)
                iss = self.keyless_iss or SA_EMAIL
                now = int(time.time())
                scope = cl.get("scope", "")
                if (
                    cl.get("iss") != iss
                    or cl.get("aud") != self.token_url(srv)
                    or not cl.get("sub")
                    or scope == ""
                    or " " in scope
                    or "," in scope
                    or cl.get("iat", 0) > now + 5
                    or cl.get("exp") != cl.get("iat", 0) + 3600
                ):
                    self.errors.append(f"assertion claims {cl}")
                    fail("invalid_grant")
                    return
                if self.bad_grant.get(cl["sub"]):
                    fail("invalid_grant")
                    return
                k = (cl["sub"], scope)
                self.minted[k] = self.minted.get(k, 0) + 1
                tok = f"{itest.CANARY}{k[0]}|{k[1]}|{self.minted[k]}"
                self.tokens[tok] = k
                write(w, {"access_token": tok, "expires_in": 3599, "token_type": "Bearer"})

        return h

    def api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        """The Google APIs. Every handler checks that the token was minted
        for the expected sub and scope."""
        with self.mu:
            self._api(w, r)

    def _api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        if self.expire401 > 0:
            self.expire401 -= 1
            api_err(w, 401, "authError")
            return
        k = self.tokens.get(r.header.get("Authorization").removeprefix("Bearer "))
        if k is None:
            api_err(w, 401, "authError")
            return

        def need(sub: str, scope: str) -> bool:
            if k != (sub, scope):
                self.errors.append(f"{r.method} {r.path} used token for {k}, want ({sub}, {scope})")
                api_err(w, 403, "insufficientPermissions")
                return False
            return True

        p = r.path
        q = r.q
        if p == "/admin/directory/v1/users":
            if not need(ADMIN_EMAIL, SCOPE_DIRECTORY_USER):
                return
            if q("customer") != "my_customer" or q("maxResults") != "1":
                api_err(w, 400, "invalid")
                return
            write(w, {"users": [{"primaryEmail": "dana@example.com", "id": "100"}]})
        elif p.startswith("/admin/directory/v1/users/"):
            if not need(ADMIN_EMAIL, SCOPE_DIRECTORY_USER):
                return
            if q("projection") != "basic" or q("viewType") != "admin_view":
                self.errors.append(f"user lookup query {r.query}")
            email = p.removeprefix("/admin/directory/v1/users/")
            email = self.aliases.get(email, email)
            u = self.users.get(email)
            if u is None:
                api_err(w, 404, "notFound")
                return
            body: dict[str, Any] = {"id": u.id, "primaryEmail": u.primary_email, "name": {"fullName": "Someone"}}
            if u.suspended is not None:
                body["suspended"] = u.suspended
            if u.archived is not None:
                body["archived"] = u.archived
            write(w, body)
        elif p.startswith("/admin/directory/v1/groups/"):
            if not need(ADMIN_EMAIL, SCOPE_DIRECTORY_GROUP):
                return
            rest = p.removeprefix("/admin/directory/v1/groups/")
            group, sep, member = rest.partition("/hasMember/")
            if not sep:
                api_err(w, 404, "notFound")
                return
            if group == "external@other.com":
                api_err(w, 400, "invalid")
                return
            members = self.group_members.get(group)
            if members is None:
                api_err(w, 404, "notFound")
                return
            if self.no_is_member:
                write(w, {})
                return
            write(w, {"isMember": member in members})
        elif p.startswith("/drive/v3/files/"):
            id = p.removeprefix("/drive/v3/files/")
            if not need(k[0], SCOPE_DRIVE):
                return
            if q("supportsAllDrives") != "true" or not q("fields").startswith("capabilities("):
                self.errors.append(f"drive query {r.query}")
            if k[0] not in self.visible.get(id, []):
                api_err(w, 404, "notFound")
                return
            write(w, self.files.get(id))
        elif p.startswith("/calendar/v3/users/me/calendarList/"):
            if not need(k[0], SCOPE_CALENDAR):
                return
            id = p.removeprefix("/calendar/v3/users/me/calendarList/")
            role = self.calendars.get(k[0], {}).get(id)
            if role is None:
                api_err(w, 404, "notFound")
                return
            write(w, {"id": id, "accessRole": role})
        elif p == "/gmail/v1/users/me/settings/sendAs":
            if not need(k[0], SCOPE_GMAIL_SETTINGS):
                return
            write(w, {"sendAs": self.send_as.get(k[0])})
        elif p == "/gmail/v1/users/me/settings/delegates":
            if not need(k[0], SCOPE_GMAIL_SETTINGS):
                return
            write(w, {"delegates": self.delegates.get(k[0])})
        else:
            self.errors.append(f"fake google: no route for {r.method} {r.target}")
            api_err(w, 404, "notFound")

    def keyless(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        """The metadata server and the IAM Credentials signJwt call."""
        with self.mu:
            if r.path == "/computeMetadata/v1/instance/service-accounts/default/token":
                if r.header.get("Metadata-Flavor") != "Google":
                    w.write_header(403)
                    return
                self.meta_calls += 1
                write(w, {"access_token": itest.CANARY + "meta", "expires_in": 3599, "token_type": "Bearer"})
            elif r.path == "/v1/projects/-/serviceAccounts/" + SA_EMAIL + ":signJwt":
                if r.header.get("Authorization") != "Bearer " + itest.CANARY + "meta":
                    api_err(w, 401, "authError")
                    return
                try:
                    payload = json.loads(r.body).get("payload", "")
                    cl = json.loads(payload)
                except (ValueError, AttributeError) as e:
                    self.errors.append(f"signJwt payload {r.body!r}: {e}")
                    api_err(w, 400, "invalid")
                    return
                if cl.get("iss") != SA_EMAIL:
                    self.errors.append(f"signJwt payload {payload!r}")
                    api_err(w, 400, "invalid")
                    return
                self.sign_calls += 1
                jwt = sign_jwt(self.key, Header(alg=RS256, kid=self.kid), payload.encode())
                write(w, {"keyId": self.kid, "signedJwt": jwt})
            else:
                self.errors.append(f"fake keyless: no route for {r.path}")
                w.write_header(404)

    def key_json(self, srv: itest.Server) -> Secret:
        from cryptography.hazmat.primitives import serialization

        pem_key = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        b = json.dumps(
            {
                "type": "service_account",
                "project_id": "proj",
                "private_key_id": self.kid,
                "private_key": pem_key,
                "client_email": SA_EMAIL,
                "client_id": "123",
                "token_uri": self.token_url(srv),
            }
        )
        return secret_literal(b)


class Env:
    """Servers and fakes made by one test, checked when it ends."""

    def __init__(self) -> None:
        self.servers: list[itest.Server] = []
        self.fakes: list[FakeGoogle] = []

    def server(self) -> itest.Server:
        srv = itest.Server()
        srv.use_spec(specs(), SPEC_OPTIONS)
        self.servers.append(srv)
        return srv

    def setup(self, values: dict[str, str] | None = None) -> tuple[itest.Server, FakeGoogle, Connection]:
        srv = self.server()
        f = FakeGoogle()
        self.fakes.append(f)
        srv.handle("POST", "/token", f.token(srv))
        srv.handle("", "/admin/*", f.api)
        srv.handle("", "/drive/*", f.api)
        srv.handle("", "/calendar/*", f.api)
        srv.handle("", "/gmail/*", f.api)
        srv.handle("", "/computeMetadata/*", f.keyless)
        srv.handle("POST", "/v1/projects/*", f.keyless)
        deps, _ = itest.deps(srv)
        v = {"admin_email": ADMIN_EMAIL, "token_url": f.token_url(srv), "api_url": srv.url, "metadata_url": srv.url, "iamcredentials_url": srv.url}
        v.update(values or {})
        secrets: dict[str, Secret] = {}
        if v.get("auth_mode") != MODE_KEYLESS:
            secrets["credential"] = f.key_json(srv)
        s = itest.settings("gws", "googleworkspace", v, secrets)
        c = GoogleWorkspace().new(background(), s, deps)
        return srv, f, c

    def setup_with(self, f: FakeGoogle, values: dict[str, str] | None = None) -> Connection:
        """A second connection against an existing fake."""
        srv = self.server()
        srv.handle("POST", "/token", f.token(srv))
        srv.handle("", "/admin/*", f.api)
        srv.handle("", "/drive/*", f.api)
        srv.handle("", "/calendar/*", f.api)
        srv.handle("", "/gmail/*", f.api)
        deps, _ = itest.deps(srv)
        v = {"admin_email": ADMIN_EMAIL, "token_url": f.token_url(srv), "api_url": srv.url}
        v.update(values or {})
        s = itest.settings("gws2", "googleworkspace", v, {"credential": f.key_json(srv)})
        return GoogleWorkspace().new(background(), s, deps)

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
sus = User(email="sus@example.com")
arch = User(email="arch@example.com")
nod = User(email="nodelegation@example.com")
nostatus = User(email="nostatus@example.com")
noarch = User(email="noarch@example.com")


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, GoogleWorkspace(), u, action, resource)


def resolve(c: Connection, u: User) -> tuple[Identity | None, BaseException | None]:
    try:
        return c.resolve_identity(background(), u), None
    except Exception as e:  # noqa: BLE001 - the error is the result
        return None, e


def resolve_decision(c: Connection, u: User) -> Decision:
    _, err = resolve(c, u)
    assert err is not None, f"{u.email} resolved"
    return to_decision(err)


# -- authentication ---------------------------------------------------------


def test_token_per_sub_and_scope_cached(env: Env) -> None:
    _, f, c = env.setup()
    itest.expect_code(check(c, dana, "drive.file.read", "file:" + FILE_A), Code.ALLOWED)
    itest.expect_code(check(c, dana, "drive.file.edit", "file:" + FILE_A), Code.ALLOWED)
    itest.expect_code(check(c, dana, "calendar.read", "calendar:ro@example.com"), Code.ALLOWED)
    itest.expect_code(check(c, bob, "drive.file.read", "file:" + FILE_B), Code.ALLOWED)
    with f.mu:
        want = {
            (ADMIN_EMAIL, SCOPE_DIRECTORY_USER): 1,
            ("dana@example.com", SCOPE_DRIVE): 1,
            ("dana@example.com", SCOPE_CALENDAR): 1,
            ("bob@example.com", SCOPE_DRIVE): 1,
        }
        assert len(f.minted) == len(want), f"minted {f.minted}"
        for k, n in want.items():
            assert f.minted.get(k, 0) == n, f"minted {k} {f.minted.get(k, 0)} times, want {n}"


def test_source_cache_bounded(env: Env) -> None:
    _, _, c = env.setup()
    assert isinstance(c, GoogleWorkspaceConnection)
    for i in range(MAX_SOURCES + 50):
        c.source(f"u{i}@example.com", SCOPE_DRIVE)
    assert len(c.sources) == MAX_SOURCES and len(c.order) == MAX_SOURCES, f"cache holds {len(c.sources)} sources"
    assert ("u0@example.com", SCOPE_DRIVE) not in c.sources, "oldest entry not evicted"


def test_retry_once_after401(env: Env) -> None:
    _, f, c = env.setup()
    itest.expect_code(check(c, dana, "drive.file.read", "file:" + FILE_A), Code.ALLOWED)
    with f.mu:
        f.expire401 = 1
    itest.expect_code(check(c, dana, "drive.file.read", "file:" + FILE_A), Code.ALLOWED)
    with f.mu:
        n = f.minted.get((ADMIN_EMAIL, SCOPE_DIRECTORY_USER), 0)
        f.expire401 = 10
    assert n == 2, f"admin token minted {n} times, want 2 (refreshed after 401)"
    itest.expect_code(check(c, dana, "drive.file.read", "file:" + FILE_A), Code.CREDENTIAL_REJECTED)


def test_invalid_grant(env: Env) -> None:
    _, f, c = env.setup()
    # A user hallpass may not impersonate: unknown, not deny.
    d = check(c, nod, "drive.file.read", "file:" + FILE_A)
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "could not act as the user" in d.text, d.text
    itest.assert_no_canary(d.text)
    # The admin: credential_rejected.
    with f.mu:
        f.bad_grant[ADMIN_EMAIL] = True
    c2 = env.setup_with(f)
    d = check(c2, dana, "drive.file.read", "file:" + FILE_A)
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)
    assert "domain-wide delegation" in d.text, d.text


def test_keyless(env: Env) -> None:
    _, f, c = env.setup({"auth_mode": MODE_KEYLESS, "service_account_email": SA_EMAIL})
    with f.mu:
        f.keyless_iss = SA_EMAIL
    itest.expect_code(check(c, dana, "drive.file.read", "file:" + FILE_A), Code.ALLOWED)
    itest.expect_code(check(c, dana, "drive.file.edit", "file:" + FILE_A), Code.ALLOWED)
    with f.mu:
        assert f.meta_calls == 1, f"metadata token fetched {f.meta_calls} times, want 1 (cached)"
        assert f.sign_calls == 2, f"signJwt called {f.sign_calls} times, want 2 (admin + user, then cached)"


def test_bad_key(env: Env) -> None:
    srv = env.server()
    deps, _ = itest.deps(srv)
    for cred in ("not json", '{"client_email":"x@y.z"}', '{"client_email":"x@y.z","private_key":"nope"}'):
        s = itest.settings(
            "gws", "googleworkspace", {"admin_email": ADMIN_EMAIL, "token_url": srv.url + "/token", "api_url": srv.url}, {"credential": secret_literal(itest.CANARY + cred)}
        )
        c = GoogleWorkspace().new(background(), s, deps)
        d = check(c, dana, "drive.file.read", "file:" + FILE_A)
        itest.expect_code(d, Code.CREDENTIAL_REJECTED)
        itest.assert_no_canary(d.text)


def test_new_validation(env: Env) -> None:
    srv = env.server()
    deps, _ = itest.deps(srv)
    cred = {"credential": itest.literal("{}")}
    bad: list[tuple[dict[str, str], dict[str, Secret] | None]] = [
        ({}, cred),
        ({"admin_email": "nope"}, cred),
        ({"admin_email": ADMIN_EMAIL}, None),
        ({"admin_email": ADMIN_EMAIL, "auth_mode": "keyless"}, None),
        ({"admin_email": ADMIN_EMAIL, "auth_mode": "magic"}, cred),
        ({"admin_email": ADMIN_EMAIL, "customer_id": "bad id"}, cred),
    ]
    for v, sec in bad:
        s = itest.settings("gws", "googleworkspace", v, sec)
        with pytest.raises(Exception):  # noqa: B017 - Go only checks err != nil
            GoogleWorkspace().new(background(), s, deps)
    s = itest.settings("gws", "googleworkspace", {"admin_email": ADMIN_EMAIL}, cred)
    c = GoogleWorkspace().new(background(), s, deps)
    assert isinstance(c, GoogleWorkspaceConnection)
    assert c.api.base == DEFAULT_API and c.customer == "my_customer" and c.mode == MODE_KEY and c.token_url_from == "key", f"defaults: {vars(c)}"
    validate_fields(GoogleWorkspace().fields())
    validate_http_url("http://metadata.google.internal")
    with pytest.raises(ValueError):
        validate_http_url("ftp://x")


# -- identity ---------------------------------------------------------------


def test_resolve_identity(env: Env) -> None:
    srv, _, c = env.setup()
    id, err = resolve(c, User(email="Dana@Example.com"))
    assert err is None and id is not None and id.id == "dana@example.com" and id.attr("suspended") == "false" and id.attr("id") == "100", f"{id} {err}"
    last = srv.last_call()
    assert last.path == "/admin/directory/v1/users/dana@example.com" and last.q("viewType") == "admin_view" and last.q("projection") == "basic", (
        f"{last.path} {last.query}"
    )
    id, err = resolve(c, User(email="d.alias@example.com"))
    assert err is None and id is not None and id.id == "dana@example.com", f"alias: {id} {err}"
    itest.expect_code(resolve_decision(c, User(email="nobody@example.com")), Code.USER_NOT_FOUND)
    itest.expect_code(resolve_decision(c, User(email="not an email")), Code.INVALID_REQUEST)
    id, err = resolve(c, sus)
    assert err is None and id is not None and id.attr("suspended") == "true", f"suspended: {id} {err}"
    id, err = resolve(c, arch)
    assert err is None and id is not None and id.attr("archived") == "true", f"archived: {id} {err}"
    id, err = resolve(c, nostatus)
    assert err is None and id is not None and id.attr("suspended") == "unknown" and id.attr("archived") == "unknown", f"no status fields: {id} {err}"
    srv.json("GET", "/admin/directory/v1/users/dana@example.com", 403, '{"error":{"code":403,"message":"' + itest.CANARY + '","errors":[{"reason":"forbidden"}]}}')
    itest.expect_code(resolve_decision(c, dana), Code.CREDENTIAL_REJECTED)


def test_suspended_and_archived_deny(env: Env) -> None:
    _, _, c = env.setup()
    d = check(c, sus, "drive.file.read", "file:" + FILE_A)
    itest.expect_code(d, Code.DENIED)
    assert "suspended" in d.text, d.text
    d = check(c, arch, "group.member", "group:eng@example.com")
    itest.expect_code(d, Code.DENIED)
    assert "archived" in d.text, d.text


def test_status_fields_absent_unknown(env: Env) -> None:
    """A user record without suspended or archived is not taken to be active."""
    srv, _, c = env.setup()
    for u in (nostatus, noarch):
        for action, resource in (("user.active", "user:" + u.email), ("drive.file.read", "file:" + FILE_A), ("group.member", "group:eng@example.com")):
            srv.reset()
            d = check(c, u, action, resource)
            itest.expect_code(d, Code.UNSUPPORTED)
            assert "did not report" in d.text, f"{u.email} {action}: {d.text}"
            for call in srv.calls():
                assert call.path.startswith("/admin/directory/v1/users/") or call.path == "/token", f"{u.email} {action}: unexpected call {call.path}"


# -- actions ----------------------------------------------------------------


def test_action_user_active_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "user.active", "user:dana@example.com"), Code.ALLOWED)
    itest.expect_code(check(c, User(email="d.alias@example.com"), "user.active", "user:d.alias@example.com"), Code.ALLOWED)


def test_action_user_active_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, sus, "user.active", "user:sus@example.com"), Code.DENIED)
    itest.expect_code(check(c, arch, "user.active", "user:arch@example.com"), Code.DENIED)
    itest.expect_code(check(c, dana, "user.active", "user:bob@example.com"), Code.UNSUPPORTED)
    itest.expect_code(check(c, nostatus, "user.active", "user:nostatus@example.com"), Code.UNSUPPORTED)


def drive_allow(env: Env, action: str) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, action, "file:" + FILE_A), Code.ALLOWED)
    assert srv.last_call().path == "/drive/v3/files/" + FILE_A, srv.last_call().path


def drive_deny(env: Env, action: str) -> None:
    _, _, c = env.setup()
    # Capability false.
    itest.expect_code(check(c, bob, action, "file:" + FILE_B), Code.DENIED)
    # Not visible: 404 notFound is a deny.
    d = check(c, bob, action, "file:" + FILE_A)
    itest.expect_code(d, Code.DENIED)
    assert "does not distinguish" in d.text, d.text
    # Capability missing: unknown.
    if action != "drive.file.read":
        itest.expect_code(check(c, dana, action, "file:" + FILE_NO_CAPS), Code.UNSUPPORTED)


def test_action_drive_file_read_allow(env: Env) -> None:
    drive_allow(env, "drive.file.read")


def test_action_drive_file_read_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, bob, "drive.file.read", "file:" + FILE_A), Code.DENIED)
    # Visible with no capabilities is still readable.
    itest.expect_code(check(c, dana, "drive.file.read", "file:" + FILE_NO_CAPS), Code.ALLOWED)


def test_action_drive_file_download_allow(env: Env) -> None:
    drive_allow(env, "drive.file.download")


def test_action_drive_file_download_deny(env: Env) -> None:
    drive_deny(env, "drive.file.download")


def test_action_drive_file_edit_allow(env: Env) -> None:
    drive_allow(env, "drive.file.edit")


def test_action_drive_file_edit_deny(env: Env) -> None:
    drive_deny(env, "drive.file.edit")


def test_action_drive_file_comment_allow(env: Env) -> None:
    drive_allow(env, "drive.file.comment")


def test_action_drive_file_comment_deny(env: Env) -> None:
    drive_deny(env, "drive.file.comment")


def test_action_drive_file_share_allow(env: Env) -> None:
    drive_allow(env, "drive.file.share")


def test_action_drive_file_share_deny(env: Env) -> None:
    drive_deny(env, "drive.file.share")


def test_action_drive_file_trash_allow(env: Env) -> None:
    drive_allow(env, "drive.file.trash")


def test_action_drive_file_trash_deny(env: Env) -> None:
    drive_deny(env, "drive.file.trash")


def test_action_drive_file_delete_allow(env: Env) -> None:
    drive_allow(env, "drive.file.delete")


def test_action_drive_file_delete_deny(env: Env) -> None:
    drive_deny(env, "drive.file.delete")


def test_action_drive_file_rename_allow(env: Env) -> None:
    drive_allow(env, "drive.file.rename")


def test_action_drive_file_rename_deny(env: Env) -> None:
    drive_deny(env, "drive.file.rename")


def test_action_drive_file_copy_allow(env: Env) -> None:
    drive_allow(env, "drive.file.copy")


def test_action_drive_file_copy_deny(env: Env) -> None:
    drive_deny(env, "drive.file.copy")


def test_action_drive_folder_add_child_allow(env: Env) -> None:
    drive_allow(env, "drive.folder.add_child")


def test_action_drive_folder_add_child_deny(env: Env) -> None:
    drive_deny(env, "drive.folder.add_child")


def test_action_drive_folder_list_allow(env: Env) -> None:
    drive_allow(env, "drive.folder.list")


def test_action_drive_folder_list_deny(env: Env) -> None:
    drive_deny(env, "drive.folder.list")


def test_drive_not_found_other_reason(env: Env) -> None:
    """Only a 404 whose reason is notFound is a deny; any other 404 is
    resource_not_visible."""
    srv, _, c = env.setup()
    for body in (
        '{"error":{"code":404,"message":"' + itest.CANARY + 'msg","errors":[{"domain":"global","reason":"fileNotFound"}]}}',
        '{"error":{"code":404,"message":"' + itest.CANARY + 'msg"}}',
        "not json",
    ):
        srv.json("GET", "/drive/v3/files/" + FILE_A, 404, body)
        for action in ("drive.file.read", "drive.file.edit"):
            d = check(c, dana, action, "file:" + FILE_A)
            itest.expect_code(d, Code.RESOURCE_NOT_VISIBLE)
            itest.assert_no_canary(d.text)
    srv.json("GET", "/drive/v3/files/" + FILE_A, 404, '{"error":{"code":404,"message":"' + itest.CANARY + 'msg","errors":[{"domain":"global","reason":"notFound"}]}}')
    itest.expect_code(check(c, dana, "drive.file.read", "file:" + FILE_A), Code.DENIED)


def test_drive_trashed_mentioned(env: Env) -> None:
    _, _, c = env.setup()
    d = check(c, dana, "drive.file.read", "file:" + FILE_B)
    itest.expect_code(d, Code.ALLOWED)
    assert "trash" in d.text, d.text


def test_action_calendar_read_allow(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "calendar.read", "calendar:ro@example.com"), Code.ALLOWED)
    assert srv.last_call().path == "/calendar/v3/users/me/calendarList/ro@example.com", srv.last_call().path
    itest.expect_code(check(c, dana, "calendar.read", "calendar:team@group.calendar.google.com"), Code.ALLOWED)
    # primary and the user's own email need no call.
    srv.reset()
    itest.expect_code(check(c, dana, "calendar.read", "calendar:primary"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "calendar.share", "calendar:Dana@example.com"), Code.ALLOWED)
    for call in srv.calls():
        assert not call.path.startswith("/calendar/"), f"unexpected calendar call {call.path}"


def test_action_calendar_read_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "calendar.read", "calendar:fb@example.com"), Code.DENIED)
    # Not in the list: unknown, ACLs may still grant access.
    d = check(c, dana, "calendar.read", "calendar:unknown@example.com")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "ACL" in d.text, d.text
    itest.expect_code(check(c, dana, "calendar.read", "calendar:odd@example.com"), Code.UNSUPPORTED)


def test_action_calendar_event_write_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "calendar.event.write", "calendar:wwpa@example.com"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "calendar.event.write", "calendar:team@group.calendar.google.com"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "calendar.event.write", "calendar:mine@example.com"), Code.ALLOWED)


def test_action_calendar_event_write_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "calendar.event.write", "calendar:ro@example.com"), Code.DENIED)
    itest.expect_code(check(c, dana, "calendar.event.write", "calendar:fb@example.com"), Code.DENIED)


def test_action_calendar_share_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "calendar.share", "calendar:mine@example.com"), Code.ALLOWED)
    itest.expect_code(check(c, dana, "calendar.share", "calendar:primary"), Code.ALLOWED)


def test_action_calendar_share_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "calendar.share", "calendar:team@group.calendar.google.com"), Code.DENIED)


def gmail_token(srv: itest.Server, f: FakeGoogle) -> tuple[str, str] | None:
    """The (sub, scope) the last Gmail call was made with."""
    last = srv.last_call()
    assert last.path.startswith("/gmail/v1/users/me/settings/"), f"last call {last.path} is not a Gmail settings call"
    with f.mu:
        return f.tokens.get(last.header.get("Authorization").removeprefix("Bearer "))


def test_action_mail_send_as_allow(env: Env) -> None:
    srv, f, c = env.setup({"enable_gmail_settings": "true"})
    # The own mailbox is answered by the isPrimary entry of sendAs.list, read
    # as the user, never without a Gmail call.
    srv.reset()
    d = check(c, dana, "mail.send_as", "mailbox:Dana@example.com")
    itest.expect_code(d, Code.ALLOWED)
    assert "primary" in d.text, d.text
    k = gmail_token(srv, f)
    assert k == ("dana@example.com", SCOPE_GMAIL_SETTINGS), f"sendAs read as {k}, want the user"
    assert srv.last_call().path == "/gmail/v1/users/me/settings/sendAs", srv.last_call().path
    itest.expect_code(check(c, dana, "mail.send_as", "mailbox:support@example.com"), Code.ALLOWED)


def test_action_mail_send_as_deny(env: Env) -> None:
    _, _, c = env.setup({"enable_gmail_settings": "true"})
    itest.expect_code(check(c, dana, "mail.send_as", "mailbox:other@example.com"), Code.DENIED)
    d = check(c, dana, "mail.send_as", "mailbox:pending@example.com")
    itest.expect_code(d, Code.DENIED)
    assert "awaiting verification" in d.text, d.text
    itest.expect_code(check(c, sus, "mail.send_as", "mailbox:sus@example.com"), Code.DENIED)
    # Feature off: unknown, for another address and for the own mailbox.
    srv2, _, c2 = env.setup()
    for mailbox in ("mailbox:support@example.com", "mailbox:dana@example.com"):
        d = check(c2, dana, "mail.send_as", mailbox)
        itest.expect_code(d, Code.UNSUPPORTED)
        assert "enable_gmail_settings" in d.text, d.text
    for call in srv2.calls():
        assert not call.path.startswith("/gmail/"), f"gmail called with the feature off: {call.path}"


def test_send_as_verification_status(env: Env) -> None:
    """Only accepted (or the primary entry) allows; pending denies; an absent
    or unspecified status is unknown even when the alias is treatAsAlias in
    the same domain."""
    srv, _, c = env.setup({"enable_gmail_settings": "true"})
    for mailbox in ("mailbox:unspec@example.com", "mailbox:blank@example.com"):
        d = check(c, dana, "mail.send_as", mailbox)
        itest.expect_code(d, Code.UNSUPPORTED)
        assert "without a verification status" in d.text, d.text
    # The own primary address missing from the list: unknown, not allow.
    d = check(c, bob, "mail.send_as", "mailbox:bob@example.com")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "primary" in d.text, d.text
    # Gmail refusals as the user: no mailbox or a user-level policy is
    # unknown; hallpass's own scope or API enablement is credential_rejected.
    for status, reason, code in (
        (404, "notFound", Code.UNSUPPORTED),
        (400, "failedPrecondition", Code.UNSUPPORTED),
        (403, "domainPolicy", Code.UNSUPPORTED),
        (403, "forbidden", Code.UNSUPPORTED),
        (403, "insufficientPermissions", Code.CREDENTIAL_REJECTED),
        (403, "accessNotConfigured", Code.CREDENTIAL_REJECTED),
        (403, "userRateLimitExceeded", Code.UPSTREAM_RATE_LIMIT),
    ):
        srv.handle("GET", "/gmail/v1/users/me/settings/sendAs", lambda w, r, status=status, reason=reason: api_err(w, status, reason))
        for mailbox in ("mailbox:dana@example.com", "mailbox:support@example.com"):
            d = check(c, dana, "mail.send_as", mailbox)
            itest.expect_code(d, code)
            itest.assert_no_canary(d.text)


def test_action_mail_delegate_access_allow(env: Env) -> None:
    srv, f, c = env.setup({"enable_gmail_settings": "true"})
    itest.expect_code(check(c, dana, "mail.delegate_access", "mailbox:boss@example.com"), Code.ALLOWED)
    last = srv.last_call()
    assert last.path == "/gmail/v1/users/me/settings/delegates", last.path
    with f.mu:
        k = f.tokens.get(last.header.get("Authorization").removeprefix("Bearer "))
    assert k == ("boss@example.com", SCOPE_GMAIL_SETTINGS), f"delegates read as {k}, want the mailbox owner"
    # The own mailbox is allowed only after Gmail answered as the user.
    srv.reset()
    itest.expect_code(check(c, dana, "mail.delegate_access", "mailbox:dana@example.com"), Code.ALLOWED)
    k = gmail_token(srv, f)
    assert k == ("dana@example.com", SCOPE_GMAIL_SETTINGS), f"own mailbox read as {k}, want the user"


def test_action_mail_delegate_access_deny(env: Env) -> None:
    srv, _, c = env.setup({"enable_gmail_settings": "true"})
    itest.expect_code(check(c, bob, "mail.delegate_access", "mailbox:boss@example.com"), Code.DENIED)
    itest.expect_code(check(c, dana, "mail.delegate_access", "mailbox:bob@example.com"), Code.DENIED)
    # An unspecified verification status is not a deny.
    itest.expect_code(check(c, nostatus, "mail.delegate_access", "mailbox:boss@example.com"), Code.UNSUPPORTED)
    # Mailbox hallpass cannot impersonate: unknown.
    itest.expect_code(check(c, dana, "mail.delegate_access", "mailbox:nodelegation@example.com"), Code.UNSUPPORTED)
    # Gmail refuses the call as the user: unknown, including the own mailbox.
    for status, reason, code in (
        (404, "notFound", Code.UNSUPPORTED),
        (403, "domainPolicy", Code.UNSUPPORTED),
        (403, "insufficientPermissions", Code.CREDENTIAL_REJECTED),
    ):
        srv.handle("GET", "/gmail/v1/users/me/settings/delegates", lambda w, r, status=status, reason=reason: api_err(w, status, reason))
        for mailbox in ("mailbox:dana@example.com", "mailbox:boss@example.com"):
            d = check(c, dana, "mail.delegate_access", mailbox)
            itest.expect_code(d, code)
            itest.assert_no_canary(d.text)
    # Feature off: unknown, for another mailbox and for the own one.
    srv2, _, c2 = env.setup()
    itest.expect_code(check(c2, dana, "mail.delegate_access", "mailbox:boss@example.com"), Code.UNSUPPORTED)
    itest.expect_code(check(c2, dana, "mail.delegate_access", "mailbox:dana@example.com"), Code.UNSUPPORTED)
    for call in srv2.calls():
        assert not call.path.startswith("/gmail/"), f"gmail called with the feature off: {call.path}"


def test_action_group_member_allow(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "group.member", "group:Eng@example.com"), Code.ALLOWED)
    assert srv.last_call().path == "/admin/directory/v1/groups/eng@example.com/hasMember/dana@example.com", srv.last_call().path


def test_action_group_member_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, bob, "group.member", "group:eng@example.com"), Code.DENIED)
    itest.expect_code(check(c, bob, "group.member", "group:missing@example.com"), Code.UNSUPPORTED)
    itest.expect_code(check(c, bob, "group.member", "group:external@other.com"), Code.UNSUPPORTED)


def test_group_member_unreported(env: Env) -> None:
    """A hasMember body without isMember is unknown."""
    _, f, c = env.setup()
    with f.mu:
        f.no_is_member = True
    d = check(c, dana, "group.member", "group:eng@example.com")
    itest.expect_code(d, Code.UNSUPPORTED)
    assert "did not report" in d.text, d.text


# -- resources and errors ---------------------------------------------------


def test_bad_resources(env: Env) -> None:
    _, _, c = env.setup()
    cases = [
        ("drive.file.read", "file:short"),
        ("drive.file.read", "file:has/slash/" + FILE_A),
        ("drive.file.read", "calendar:" + FILE_A),
        ("calendar.read", "calendar:bad calendar"),
        ("calendar.read", "calendar:x?y=1"),
        ("group.member", "group:not-an-email"),
        ("mail.send_as", "user:dana@example.com"),
        ("user.active", "mailbox:dana@example.com"),
    ]
    for action, resource in cases:
        d = check(c, dana, action, resource)
        assert d.code == Code.INVALID_REQUEST, f"{action} {resource} -> {d.code}: {d.text}"


def test_error_classification(env: Env) -> None:
    srv, _, c = env.setup()
    for reason, code in (
        ("userRateLimitExceeded", Code.UPSTREAM_RATE_LIMIT),
        ("rateLimitExceeded", Code.UPSTREAM_RATE_LIMIT),
        ("insufficientPermissions", Code.CREDENTIAL_REJECTED),
        ("accessNotConfigured", Code.CREDENTIAL_REJECTED),
        ("forbidden", Code.CREDENTIAL_REJECTED),
        ("somethingElse", Code.CREDENTIAL_REJECTED),
        # About the user or the file, not hallpass's credential.
        ("insufficientFilePermissions", Code.UNSUPPORTED),
        ("domainPolicy", Code.UNSUPPORTED),
        ("cannotDownloadAbusiveFile", Code.UNSUPPORTED),
    ):
        srv.handle("GET", "/drive/v3/files/" + FILE_A, lambda w, r, reason=reason: api_err(w, 403, reason))
        d = check(c, dana, "drive.file.edit", "file:" + FILE_A)
        itest.expect_code(d, code)
        itest.assert_no_canary(d.text)
        if code == Code.UNSUPPORTED:
            assert reason in d.text, f"{reason}: {d.text}"
    # A 403 with no reason at all is hallpass's problem.
    srv.json("GET", "/drive/v3/files/" + FILE_A, 403, '{"error":{"code":403,"message":"' + itest.CANARY + '"}}')
    itest.expect_code(check(c, dana, "drive.file.edit", "file:" + FILE_A), Code.CREDENTIAL_REJECTED)


def test_failures(env: Env) -> None:
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "drive.file.read", "file:" + FILE_A), Code.ALLOWED)
    itest.failure_cases(srv, lambda: check(c, dana, "drive.file.read", "file:" + FILE_A))


def test_failures_at_token_endpoint(env: Env) -> None:
    srv, _, c = env.setup()
    itest.failure_cases(srv, lambda: check(c, dana, "group.member", "group:eng@example.com"))


# -- probe ------------------------------------------------------------------


def test_probe(env: Env) -> None:
    srv, f, c = env.setup()
    r = c.probe(background())
    assert SA_EMAIL in r.summary and ADMIN_EMAIL in r.summary, r.summary
    joined = "\n".join(r.warnings)
    assert "could not be minted" not in joined and "gmail.settings.basic" not in joined and "domain-wide delegation" in joined, f"warnings: {joined!r}"
    assert any(call.path == "/admin/directory/v1/users" and call.q("customer") == "my_customer" for call in srv.calls()), "probe did not list users"
    with f.mu:
        for sc in (SCOPE_DIRECTORY_GROUP, SCOPE_DRIVE, SCOPE_CALENDAR):
            assert f.minted.get((ADMIN_EMAIL, sc)) == 1, f"probe did not mint {sc} as the admin"

    # Gmail on: warns about the write-capable scope.
    _, _, c2 = env.setup({"enable_gmail_settings": "true"})
    r = c2.probe(background())
    assert "gmail.settings.basic" in "\n".join(r.warnings), f"warnings: {r.warnings}"


def test_probe_scope_missing(env: Env) -> None:
    srv, f, c = env.setup()
    # Drive scope not delegated: the token endpoint refuses that scope.
    orig = f.token(srv)

    def token(w: itest.ResponseWriter, r: itest.Request) -> None:
        a = (r.form().get("assertion") or [""])[0]
        try:
            cl = decode_jwt_claims(a)
        except ValueError:
            cl = {}
        if cl.get("scope") == SCOPE_DRIVE:
            w.write_header(400)
            w.write('{"error":"invalid_grant","error_description":"' + itest.CANARY + 'x"}')
            return
        orig(w, r)

    srv.handle("POST", "/token", token)
    r = c.probe(background())
    joined = "\n".join(r.warnings)
    assert SCOPE_DRIVE in joined and "allowlist" in joined, f"warnings: {joined!r}"
    itest.assert_no_canary(joined)

    # Admin delegation broken: probe fails with credential_rejected.
    with f.mu:
        f.bad_grant[ADMIN_EMAIL] = True
    c2 = env.setup_with(f)
    with pytest.raises(Exception) as ei:  # noqa: B017 - any error; its code is checked
        c2.probe(background())
    itest.expect_code(to_decision(ei.value), Code.CREDENTIAL_REJECTED)


def test_actions_listed() -> None:
    for a in ACTION_LIST:
        assert find_action(GoogleWorkspace(), a.name) is not None, f"{a.name} not found"
    assert len(GoogleWorkspace().actions()) == 18, f"{len(GoogleWorkspace().actions())} actions"
