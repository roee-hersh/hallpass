"""Port of internal/integrations/github/github_test.go."""

from __future__ import annotations

import base64
import json
import queue
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from hallpass.authx import jwt as authx_jwt
from hallpass.core.cache import PanicError
from hallpass.core.context import background, with_cancel, with_timeout
from hallpass.core.decision import Code, Decision, to_decision
from hallpass.core.errors import as_error
from hallpass.core.integration import Connection, User, validate_fields
from hallpass.core.secret import Secret
from hallpass.core.template import Template, validate_email_domains, validate_template
from hallpass.integrations.github import GitHub, GitHubConnection
from hallpass.integrations.github import identity as identity_mod
from hallpass.integrations.github.actions import valid_branch
from hallpass.integrations.github.github import validate_app_id, validate_installation_id, validate_login
from hallpass.integrations.github.identity import read_user_map
from tests import harness as itest
from tests.harness.spec import SpecOptions, spec_from_env

TEST_APP_ID = "Iv1.0123456789abcdef"
TEST_INST = "42"

_KEY_LOCK = threading.Lock()
_KEY: list[Any] = []


def rsa_key() -> Any:
    """Generated once per process; 2048-bit keys are slow."""
    with _KEY_LOCK:
        if not _KEY:
            _KEY.append(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        return _KEY[0]


def key_secret() -> Secret:
    """The App private key as a test secret. The canary goes in a comment
    line before the PEM block, which parse_rsa_private_key skips."""
    pem = rsa_key().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    return itest.literal("github\n" + pem.decode())


class Clock:
    """A settable time source shared by the connection and the fake."""

    def __init__(self, t: float) -> None:
        self._lock = threading.Lock()
        self.t = t

    def now(self) -> float:
        with self._lock:
            return self.t

    def advance(self, d: float) -> None:
        with self._lock:
            self.t += d


@dataclass
class Membership:
    state: str
    role: str


@dataclass
class PermRecord:
    role: str = ""
    perms: dict[str, bool] | None = None  # None: only the lossy string is reported
    str: str = ""


def _perms(pull: bool = False, triage: bool = False, push: bool = False, maintain: bool = False, admin: bool = False) -> dict[str, bool]:
    return {"pull": pull, "triage": triage, "push": push, "maintain": maintain, "admin": admin}


def _b64url_decode(s: str) -> bytes:
    if "=" in s:
        raise ValueError("padding")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def write_json(w: itest.ResponseWriter, status: int, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write(json.dumps(v) + "\n")


class Fake:
    """A GitHub REST + GraphQL API for one organization "acme". Tests change
    its fields through with_(), which takes the lock the handler holds."""

    def __init__(self) -> None:
        all_ = _perms(True, True, True, True, True)
        write = _perms(True, True, True)
        read = _perms(True)
        tok = itest.CANARY + "ghs_1"
        self.lock = threading.RLock()
        self.errors: list[str] = []
        self.now: Callable[[], float] = time.time
        self.minted = tok  # the token access_tokens hands out
        self.accepted = tok  # the token the API accepts
        self.mints = 0  # access_tokens calls
        self.minted_for = ""  # installation id of the last mint
        self.bad_jwts = 0
        self.inst_perms: dict[str, str] = {"metadata": "read", "members": "read"}
        self.users = {"dana": "User", "bob": "User", "carol": "User", "frank": "User", "mallory": "User", "acme": "Organization"}
        self.perms: dict[str, dict[str, PermRecord]] = {
            "dana": {
                "api": PermRecord("admin", all_, "admin"),
                "webapp": PermRecord("write", write, "write"),
                "legacy": PermRecord(str="write"),
            },
            "bob": {
                "api": PermRecord("read", read, "read"),
                "webapp": PermRecord("read", read, "read"),
                "custom": PermRecord("security-champion", read, "read"),
                "legacy": PermRecord(str="security-champion"),
            },
            "carol": {
                "api": PermRecord("none", _perms(), "none"),
                "webapp": PermRecord("none", _perms(), "none"),
            },
        }
        self.perm_status = 0  # override for the permission endpoint (0: normal)
        self.perm_header: dict[str, list[str]] = {}
        self.repos: dict[str, dict[str, Any]] = {
            "api": {"name": "api", "has_issues": True, "allow_forking": True, "visibility": "public"},
            "webapp": {"name": "webapp", "has_issues": False, "allow_forking": False, "visibility": "private"},
            "custom": {"name": "custom", "has_issues": True, "allow_forking": True, "visibility": "private"},
            "legacy": {"name": "legacy"},
        }
        self.repo_status = 0  # override for GET /repos/acme/{repo} (0: normal)
        self.members: dict[str, Membership] = {
            "dana": Membership("active", "admin"),
            "bob": Membership("active", "member"),
            "eve": Membership("pending", "member"),
            "frank": Membership("", "member"),
        }
        self.org: dict[str, Any] = {
            "login": "acme",
            "members_can_create_repositories": True,
            "members_can_create_public_repositories": False,
            "members_can_create_private_repositories": True,
        }
        self.teams: dict[str, dict[str, Membership]] = {
            "platform": {
                "dana": Membership("active", "maintainer"),
                "bob": Membership("active", "member"),
                "eve": Membership("pending", "member"),
                "frank": Membership("", "member"),
            },
            "release": {"bob": Membership("active", "member")},
        }
        self.rules: dict[str, list[dict[str, Any]]] = {
            "api@main": [{"type": "pull_request"}, {"type": "required_status_checks"}, {"type": "pull_request"}],
            "api@release": [{"type": "required_signatures"}],
            "webapp@dev": [{"type": "update"}],
            "webapp@queue": [{"type": "merge_queue"}, {"type": "required_status_checks"}],
            "webapp@lifecycle": [{"type": "creation"}, {"type": "deletion"}],
        }
        self.rules_status = 0
        # The classic branch protection, "repo@branch" -> body; a branch
        # without an entry answers 404 as GitHub does.
        self.protection: dict[str, dict[str, Any]] = {}
        self.protection_status = 0
        self.team_member_status = 0  # override for the team membership endpoint (0: normal)
        self.saml = True
        self.identities: list[dict[str, Any]] = [
            {"user": {"login": "dana"}, "samlIdentity": {"nameId": "dana@example.com", "username": "dana@example.com"}, "scimIdentity": None},
            {"user": {"login": "bob"}, "samlIdentity": {"nameId": "bob@example.com", "username": None}, "scimIdentity": {"username": "bob@example.com"}},
            {"user": None, "samlIdentity": {"nameId": "ghost@example.com", "username": "ghost@example.com"}, "scimIdentity": None},
            {"user": {"login": "zed"}, "samlIdentity": {"nameId": "Zed@Example.com", "username": "zed"}, "scimIdentity": None},
            {"user": None, "samlIdentity": {"nameId": "phantom@example.com", "username": "phantom"}, "scimIdentity": None},
            {"user": {"login": "carol"}, "samlIdentity": {"nameId": "carol@example.com", "username": "carol@example.com"}, "scimIdentity": None},
            {"user": {"login": "eve"}, "samlIdentity": {"nameId": "eve@example.com", "username": "eve@example.com"}, "scimIdentity": None},
        ]
        # When set, what the userName filter returns whatever the email:
        # GitHub's filter is not trusted to match exactly.
        self.filter_nodes: list[dict[str, Any]] | None = None
        self.page_size = 2
        self.page_queries = 0
        self.gql_errors: list[dict[str, Any]] | None = None

    def with_(self, fn: Callable[[], None]) -> None:
        """Run fn under the fake's lock."""
        with self.lock:
            fn()

    def mint_count(self) -> int:
        with self.lock:
            return self.mints

    def page_count(self) -> int:
        with self.lock:
            return self.page_queries

    def check_jwt(self, w: itest.ResponseWriter, r: itest.Request) -> bool:
        """Verify the App JWT: RS256, signed by the test key, iss is the app
        id, lifetime at most 10 minutes."""
        tok = r.header.get("Authorization").removeprefix("Bearer ")
        parts = tok.split(".")

        def fail(msg: str) -> bool:
            with self.lock:
                self.bad_jwts += 1
                self.errors.append(f"bad App JWT: {msg}")
            write_json(w, 401, {"message": "Bad credentials"})
            return False

        if len(parts) != 3:
            return fail("not a compact JWS")
        try:
            hb = _b64url_decode(parts[0])
        except ValueError:
            return fail("header")
        try:
            hdr = json.loads(hb)
        except ValueError:
            hdr = None
        if not isinstance(hdr, dict) or hdr.get("alg") != "RS256" or hdr.get("typ") != "JWT":
            return fail("header " + hb.decode("utf-8", "replace"))
        try:
            sig = _b64url_decode(parts[2])
        except ValueError:
            return fail("signature encoding")
        try:
            authx_jwt.verify(rsa_key().public_key(), authx_jwt.RS256, (parts[0] + "." + parts[1]).encode(), sig)
        except ValueError as e:
            return fail(f"signature: {e}")
        try:
            claims = authx_jwt.decode_jwt_claims(tok)
            iss, iat, exp = claims.get("iss", ""), int(claims.get("iat", 0)), int(claims.get("exp", 0))
        except (ValueError, TypeError, AttributeError) as e:
            return fail(f"claims: {e}")
        if iss != TEST_APP_ID:
            return fail("iss " + str(iss))
        if exp - iat > 600 or exp <= iat:
            return fail("lifetime")
        now = int(self.now())
        if iat > now or exp < now:
            return fail("clock")
        return True

    def check_token(self, w: itest.ResponseWriter, r: itest.Request) -> bool:
        with self.lock:
            want = "Bearer " + self.accepted
        if r.header.get("Authorization") != want:
            write_json(w, 401, {"message": "Bad credentials", "note": itest.CANARY + "body"})
            return False
        if r.header.get("Accept") != "application/vnd.github+json" or r.header.get("X-GitHub-Api-Version") != "2022-11-28":
            with self.lock:
                self.errors.append(f"missing GitHub headers on {r.method} {r.path}: {r.header!r}")
            write_json(w, 400, {"message": "headers"})
            return False
        return True

    def handle(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        p = r.raw_path.removeprefix("/api")
        if p == "/graphql" and r.method == "POST":
            if self.check_token(w, r):
                self.graphql(w, r)
            return
        p = p.removeprefix("/v3")
        seg = p.removeprefix("/").split("/")
        if p == "/app" and r.method == "GET":
            if self.check_jwt(w, r):
                write_json(w, 200, {"slug": "hallpass-reader", "name": "hallpass reader", "note": itest.CANARY + "app"})
        elif len(seg) == 3 and seg[0] == "orgs" and seg[2] == "installation" and r.method == "GET":
            if not self.check_jwt(w, r):
                return
            if seg[1] != "acme":
                write_json(w, 404, {"message": "Not Found"})
                return
            with self.lock:
                write_json(w, 200, {"id": 42, "permissions": self.inst_perms, "account": {"login": "acme"}})
        elif len(seg) == 4 and seg[0] == "app" and seg[1] == "installations" and seg[3] == "access_tokens" and r.method == "POST":
            if self.check_jwt(w, r):
                with self.lock:
                    self.mints += 1
                    self.minted_for = seg[2]
                    exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.now() + 3600))
                    write_json(w, 201, {"token": self.minted, "expires_at": exp})
        elif self.check_token(w, r):
            with self.lock:
                self.rest(w, r, seg)

    def rest(self, w: itest.ResponseWriter, r: itest.Request, seg: list[str]) -> None:
        """Serve the installation-token endpoints. Called with the lock held."""

        def not_found() -> None:
            write_json(w, 404, {"message": "Not Found", "note": itest.CANARY + "404"})

        if r.method != "GET":
            write_json(w, 405, {"message": "method"})
            return
        n = len(seg)
        if n == 2 and seg[0] == "users":
            typ = self.users.get(seg[1])
            if typ is None:
                not_found()
                return
            write_json(w, 200, {"login": seg[1], "type": typ})
        elif n == 3 and seg[0] == "repos" and seg[1] == "acme":
            if self.repo_status != 0:
                write_json(w, self.repo_status, {"message": "override", "note": itest.CANARY + "repo"})
                return
            body = self.repos.get(seg[2])
            if body is None:
                not_found()
                return
            write_json(w, 200, body)
        elif n == 6 and seg[0] == "repos" and seg[1] == "acme" and seg[3] == "collaborators" and seg[5] == "permission":
            if self.perm_status != 0:
                for k, vs in self.perm_header.items():
                    for v in vs:
                        w.header().add(k, v)
                write_json(w, self.perm_status, {"message": "override"})
                return
            rec = self.perms.get(seg[4], {}).get(seg[2])
            if rec is None or seg[2] not in self.repos:
                not_found()
                return
            user: dict[str, Any] = {"login": seg[4]}
            if rec.perms is not None:
                user["permissions"] = rec.perms
            write_json(w, 200, {"permission": rec.str, "role_name": rec.role, "user": user})
        elif n == 6 and seg[0] == "repos" and seg[1] == "acme" and seg[3] == "rules" and seg[4] == "branches":
            if self.rules_status != 0:
                write_json(w, self.rules_status, {"message": "override"})
                return
            if seg[2] not in self.repos:
                not_found()
                return
            branch = urllib.parse.unquote(seg[5])
            write_json(w, 200, self.rules.get(seg[2] + "@" + branch) or [])
        elif n == 6 and seg[0] == "repos" and seg[1] == "acme" and seg[3] == "branches" and seg[5] == "protection":
            if self.protection_status != 0:
                write_json(w, self.protection_status, {"message": "override", "note": itest.CANARY + "prot"})
                return
            if seg[2] not in self.repos:
                not_found()
                return
            branch = urllib.parse.unquote(seg[4])
            prot = self.protection.get(seg[2] + "@" + branch)
            if prot is None:
                write_json(w, 404, {"message": "Branch not protected", "note": itest.CANARY + "404"})
                return
            write_json(w, 200, prot)
        elif n == 2 and seg[0] == "orgs" and seg[1] == "acme":
            write_json(w, 200, self.org)
        elif n == 4 and seg[0] == "orgs" and seg[1] == "acme" and seg[2] == "memberships":
            m = self.members.get(seg[3])
            if m is None:
                not_found()
                return
            write_json(w, 200, {"state": m.state, "role": m.role})
        elif n == 4 and seg[0] == "orgs" and seg[1] == "acme" and seg[2] == "teams":
            if seg[3] not in self.teams:
                not_found()
                return
            write_json(w, 200, {"slug": seg[3]})
        elif n == 6 and seg[0] == "orgs" and seg[1] == "acme" and seg[2] == "teams" and seg[4] == "memberships":
            if self.team_member_status != 0:
                write_json(w, self.team_member_status, {"message": "override", "note": itest.CANARY + "team"})
                return
            m = self.teams.get(seg[3], {}).get(seg[5])
            if m is None:
                not_found()
                return
            write_json(w, 200, {"state": m.state, "role": m.role})
        else:
            not_found()

    def graphql(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        try:
            req = json.loads(r.body)
            query, variables = str(req.get("query", "")), req.get("variables") or {}
        except (ValueError, AttributeError):
            write_json(w, 400, {"message": "bad json"})
            return
        with self.lock:
            if variables.get("org") != "acme":
                write_json(w, 200, {"data": {"organization": None}})
                return
            if self.gql_errors is not None:
                write_json(w, 200, {"data": None, "errors": self.gql_errors})
                return
            if not self.saml:
                write_json(w, 200, {"data": {"organization": {"samlIdentityProvider": None}}})
                return
            if "userName:$email" in query:
                email = variables.get("email", "")
                email = email if isinstance(email, str) else ""
                nodes = [
                    i
                    for i in self.identities
                    if _identity_username(i, "samlIdentity").lower() == email.lower() or _identity_username(i, "scimIdentity").lower() == email.lower()
                ]
                if self.filter_nodes is not None:
                    nodes = self.filter_nodes
                ext: dict[str, Any] = {"nodes": nodes}
            else:
                self.page_queries += 1
                start = 0
                c = variables.get("cursor")
                if isinstance(c, str):
                    try:
                        start = int(c)
                    except ValueError:
                        start = 0
                end = min(start + self.page_size, len(self.identities))
                ext = {"pageInfo": {"hasNextPage": end < len(self.identities), "endCursor": str(end)}, "nodes": self.identities[start:end]}
            write_json(w, 200, {"data": {"organization": {"samlIdentityProvider": {"externalIdentities": ext}}}})


def _identity_username(ident: dict[str, Any], key: str) -> str:
    sub = ident.get(key)
    if not isinstance(sub, dict):
        return ""
    s = sub.get("username")
    return s if isinstance(s, str) else ""


GITHUB_SPEC_OPTS = SpecOptions(strip_prefix=[r"/api/v3"], ignore_paths=[r"^/graphql$", r"^/api/graphql$"])


@dataclass
class Env:
    srv: itest.Server
    api: Fake
    conn: Connection
    clock: Clock
    logs: itest.Logs

    def check(self, u: User, action: str, resource: str) -> Decision:
        return itest.check(self.conn, GitHub(), u, action, resource)

    def calls(self, path: str) -> int:
        return sum(1 for c in self.srv.calls() if path in c.path)


class Harness:
    """Builds fake servers and connections for one test and checks them
    when it ends (Go: t.Cleanup plus t.Errorf in the fake)."""

    def __init__(self) -> None:
        self.servers: list[itest.Server] = []
        self.fakes: list[Fake] = []

    def server(self, spec: bool = True) -> itest.Server:
        srv = itest.Server()
        self.servers.append(srv)
        if spec:
            srv.use_spec(spec_from_env("github"), GITHUB_SPEC_OPTS)
        return srv

    def setup(self, values: dict[str, str] | None = None) -> Env:
        srv = self.server()
        api = Fake()
        self.fakes.append(api)
        srv.handle("", "/api/*", api.handle)
        ck = Clock(time.time())
        deps, logs = itest.deps(srv, now=ck.now)
        api.now = ck.now
        v = {"url": srv.url, "organization": "acme", "app_id": TEST_APP_ID, "identity_mode": "saml", "login_template": "{local}"}
        v.update(values or {})
        s = itest.settings("gh", "github", v, {"credential": key_secret()})
        c = GitHub().new(background(), s, deps)
        return Env(srv=srv, api=api, conn=c, clock=ck, logs=logs)

    def close(self) -> None:
        errors: list[str] = []
        for srv in self.servers:
            srv.close()
            errors.extend(srv.spec_errors)
        for f in self.fakes:
            errors.extend(f.errors)
        assert not errors, "\n".join(errors)


@pytest.fixture
def gh() -> Iterator[Harness]:
    h = Harness()
    yield h
    h.close()


DANA = User(email="dana@example.com")
BOB = User(email="bob@example.com")
CAROL = User(email="carol@example.com")
EVE = User(email="eve@example.com")


def expect_text(d: Decision, code: Code, substr: str) -> None:
    itest.expect_code(d, code)
    assert substr in d.text, f"decision text {d.text!r} does not contain {substr!r}"


def resolve(e: Env, email: str) -> Any:
    """resolve_identity as (identity, error)."""
    try:
        return e.conn.resolve_identity(background(), User(email=email)), None
    except Exception as err:
        return None, err


def err_decision(err: BaseException | None) -> Decision:
    assert err is not None, "expected an error"
    return to_decision(err)


# -- auth ----------------------------------------------------------------------


def test_auth_flow_and_token_cache(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), Code.ALLOWED)
    itest.expect_code(e.check(DANA, "repo.push", "repo:acme/api"), Code.ALLOWED)

    paths = [c.method + " " + c.path for c in e.srv.calls()]
    want = [
        "GET /api/v3/orgs/acme/installation",
        "POST /api/v3/app/installations/42/access_tokens",
        "POST /api/graphql",
        "GET /api/v3/repos/acme/api/collaborators/dana/permission",
        "POST /api/graphql",
        "GET /api/v3/repos/acme/api/collaborators/dana/permission",
    ]
    assert paths == want, "calls:\n" + "\n".join(paths) + "\nwant:\n" + "\n".join(want)
    assert e.api.mint_count() == 1, f"installation token minted {e.api.mint_count()} times, want 1"
    # Decode the JWT the connection presented and check the claims directly.
    inst = next(c for c in reversed(e.srv.calls()) if c.path == "/api/v3/orgs/acme/installation")
    jwt = inst.header.get("Authorization").removeprefix("Bearer ")
    claims = authx_jwt.decode_jwt_claims(jwt)
    assert claims["iss"] == TEST_APP_ID and 0 < claims["exp"] - claims["iat"] <= 600, f"claims {claims}"
    parts = jwt.split(".")
    authx_jwt.verify(rsa_key().public_key(), authx_jwt.RS256, (parts[0] + "." + parts[1]).encode(), _b64url_decode(parts[2]))
    last = e.srv.last_call()
    assert (
        last.header.get("Authorization") == "Bearer " + itest.CANARY + "ghs_1"
        and last.header.get("X-GitHub-Api-Version") == "2022-11-28"
        and last.header.get("Accept") == "application/vnd.github+json"
    ), f"REST headers: {last.header!r}"


def test_configured_installation_id_skips_discovery(gh: Harness) -> None:
    e = gh.setup({"installation_id": TEST_INST})
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), Code.ALLOWED)
    assert e.calls("/orgs/acme/installation") == 0, "installation discovered although installation_id is set"
    assert e.api.mint_count() == 1, f"mints = {e.api.mint_count()}"


def test_token_invalidated_on401(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), Code.ALLOWED)

    # GitHub revoked the token: the API wants the next one it mints.
    def revoke() -> None:
        e.api.minted = e.api.accepted = itest.CANARY + "ghs_2"

    e.api.with_(revoke)
    e.srv.reset()
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), Code.ALLOWED)
    assert e.api.mint_count() == 2, f"mints = {e.api.mint_count()}, want 2"
    assert e.calls("/api/graphql") == 2, f"graphql called {e.calls('/api/graphql')} times, want 2 (401 then retry)"
    assert e.calls("/permission") == 1, f"permission called {e.calls('/permission')} times, want 1"
    # A token that keeps being rejected is retried once, then reported.
    e.api.with_(lambda: setattr(e.api, "accepted", "never-matches"))
    e.srv.reset()
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), Code.CREDENTIAL_REJECTED)
    assert e.calls("/api/graphql") == 2, f"graphql called {e.calls('/api/graphql')} times, want 2"
    assert e.api.mint_count() == 3, f"mints = {e.api.mint_count()}, want 3"


def test_token_refresh_near_expiry(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), Code.ALLOWED)
    e.clock.advance(56 * 60)  # within 5 min of the 1 h expiry
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), Code.ALLOWED)
    assert e.api.mint_count() == 2, f"mints = {e.api.mint_count()}, want 2 after the token neared expiry"


def test_bad_key_and_missing_installation(gh: Harness) -> None:
    srv = gh.server()
    api = Fake()
    gh.fakes.append(api)
    srv.handle("", "/api/*", api.handle)
    deps, _ = itest.deps(srv)
    v = {"url": srv.url, "organization": "acme", "app_id": TEST_APP_ID, "identity_mode": "template", "email_domains": "example.com"}
    s = itest.settings("gh", "github", v, {"credential": itest.literal("not-a-key")})
    c = GitHub().new(background(), s, deps)
    d = itest.check(c, GitHub(), DANA, "repo.read", "repo:acme/api")
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)
    assert len(srv.calls()) == 0, "an unparsable key reached the API"

    e = gh.setup({"organization": "other", "identity_mode": "template", "email_domains": "example.com"})
    d = e.check(DANA, "repo.read", "repo:other/api")
    expect_text(d, Code.CREDENTIAL_REJECTED, "not installed")


# -- identity ------------------------------------------------------------------


def test_identity_saml(gh: Harness) -> None:
    e = gh.setup()
    ctx = background()
    ident = e.conn.resolve_identity(ctx, DANA)
    assert ident.id == "dana" and ident.attr("identity_mode") == "saml", f"dana: {ident}"
    ident = e.conn.resolve_identity(ctx, BOB)  # matched through scimIdentity.username
    assert ident.id == "bob", f"bob: {ident}"
    assert e.api.page_count() == 0, "direct hits should not list identities"
    # Unlinked identity on a direct hit.
    _, err = resolve(e, "ghost@example.com")
    expect_text(err_decision(err), Code.UNSUPPORTED, "not linked")

    # zed's userName is not the email: found through the paginated listing.
    ident, err = resolve(e, "zed@example.com")
    assert err is None and ident.id == "zed", f"zed: {ident} {err}"
    assert e.api.page_count() == 4, f"page queries = {e.api.page_count()}, want 4"  # 7 identities, 2 per page
    # The listing is cached: another miss does not re-list.
    _, err = resolve(e, "nobody@example.com")
    itest.expect_code(err_decision(err), Code.USER_NOT_FOUND)
    _, err = resolve(e, "phantom@example.com")
    expect_text(err_decision(err), Code.UNSUPPORTED, "not linked")
    assert e.api.page_count() == 4, f"page queries = {e.api.page_count()} after cache, want 4"
    e.clock.advance(11 * 60)
    resolve(e, "nobody@example.com")
    assert e.api.page_count() == 8, f"page queries = {e.api.page_count()} after the cache expired, want 8"
    # The GraphQL variables carry the email, never string-interpolated.
    for c in e.srv.calls():
        if c.path != "/api/graphql":
            continue
        body = c.json()
        variables = body["variables"]
        assert all(isinstance(x, str) for x in variables.values()), f"graphql variables: {variables}"
        assert "@example.com" not in body["query"] and variables.get("org") == "acme", f"graphql body: {body}"
    # A bad email never reaches the network.
    e.srv.reset()
    for bad in ("not an email", "", "a@b@c", "x@", "@x", "dana@exa mple.com"):
        _, err = resolve(e, bad)
        itest.expect_code(err_decision(err), Code.INVALID_REQUEST)
    assert len(e.srv.calls()) == 0, "invalid email hit the API"


def test_identity_saml_conflicts(gh: Harness) -> None:
    """The same address on identities linked to different accounts is
    ambiguous, never whichever came last."""
    e = gh.setup()
    e.api.with_(
        lambda: e.api.identities.extend(
            [
                {"user": {"login": "dupone"}, "samlIdentity": {"nameId": "dup@example.com", "username": "dup-one"}, "scimIdentity": None},
                {"user": {"login": "duptwo"}, "samlIdentity": {"nameId": "Dup@example.com", "username": "dup-two"}, "scimIdentity": None},
                # The same account twice is not a conflict; an unlinked twin does not override.
                {"user": {"login": "twin"}, "samlIdentity": {"nameId": "twin@example.com", "username": "twin-a"}, "scimIdentity": None},
                {"user": {"login": "Twin"}, "samlIdentity": {"nameId": "twin@example.com", "username": "twin-b"}, "scimIdentity": None},
                {"user": None, "samlIdentity": {"nameId": "twin@example.com", "username": "twin-c"}, "scimIdentity": None},
            ]
        )
    )
    _, err = resolve(e, "dup@example.com")
    expect_text(err_decision(err), Code.USER_AMBIGUOUS, "several GitHub accounts")
    ident, err = resolve(e, "twin@example.com")
    assert err is None and ident.id == "twin", f"twin: {ident} {err}"
    # A conflict through the userName filter is ambiguous too.
    e.api.with_(
        lambda: setattr(
            e.api,
            "filter_nodes",
            [
                {"user": {"login": "dupone"}, "samlIdentity": {"nameId": "dup@example.com", "username": "dup@example.com"}, "scimIdentity": None},
                {"user": {"login": "duptwo"}, "samlIdentity": {"nameId": "x", "username": "x"}, "scimIdentity": {"username": "dup@example.com"}},
            ],
        )
    )
    _, err = resolve(e, "dup@example.com")
    itest.expect_code(err_decision(err), Code.USER_AMBIGUOUS)


def test_saml_map_panic_does_not_wedge(gh: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    """A crash inside the identity listing becomes an error for the caller
    and for everyone waiting on the same fetch, the next call fetches
    again, and nothing unwinds through resolve_identity."""
    # Go: panic("boom") — a crash in Python is a bug-type exception
    # (TypeError), which the cache turns into a PanicError as Go does a panic.
    ctx = background()
    e = gh.setup()
    c = e.conn
    assert isinstance(c, GitHubConnection)

    # The leader crashes while waiters are parked on its round.
    started: queue.Queue[None] = queue.Queue(1)
    release = threading.Event()
    first = threading.Lock()
    first_done = [False]

    def hook() -> None:
        # Only the first fetch parks.
        with first:
            park = not first_done[0]
            first_done[0] = True
        if park:
            started.put(None)
            release.wait()
        raise TypeError("boom " + itest.CANARY)

    monkeypatch.setattr(identity_mod, "SAML_FETCH_HOOK", hook)
    waiters = 3
    results: queue.Queue[BaseException | None] = queue.Queue()

    def leader() -> None:
        try:
            c._saml_map(ctx)
            results.put(None)
        except Exception as err:
            results.put(err)

    threading.Thread(target=leader, daemon=True).start()
    started.get(timeout=10)

    def waiter() -> None:
        wctx, cancel = with_timeout(ctx, 10)
        try:
            c._saml_map(wctx)
            results.put(None)
        except Exception as err:
            results.put(err)
        finally:
            cancel()

    for _ in range(waiters):
        threading.Thread(target=waiter, daemon=True).start()
    # Let the waiters park on the round, then let the leader crash.
    time.sleep(0.02)
    release.set()
    for i in range(waiters + 1):
        try:
            err = results.get(timeout=10)
        except queue.Empty:
            pytest.fail("a caller is still waiting: the in-flight marker was not released")
        assert err is not None, f"caller {i} succeeded"
        d = to_decision(err)
        pe = as_error(err, PanicError)
        assert d.code == Code.UPSTREAM_ERROR and pe is not None and str(pe.value) == "boom " + itest.CANARY, f"caller {i}: {err}"
        # The decision text is fixed; the panic value stays in the cause.
        itest.assert_no_canary(d.text)
    itest.assert_no_canary(e.logs.text())

    # Through resolve_identity the crash is an unknown decision, not a crash.
    _, err = resolve(e, "zed@example.com")
    itest.expect_code(err_decision(err), Code.UPSTREAM_ERROR)

    # Once the fault is gone the next call fetches and succeeds.
    monkeypatch.setattr(identity_mod, "SAML_FETCH_HOOK", None)
    ident, err = resolve(e, "zed@example.com")
    assert err is None and ident.id == "zed", f"after the panic: {ident} {err}"


def test_saml_map_cancelled_leader(gh: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    """A waiter is not failed by the leader's own context ending; the fetch
    runs on, detached, and the waiter gets it."""
    e = gh.setup()
    c = e.conn
    assert isinstance(c, GitHubConnection)
    leader_ctx, cancel_leader = with_cancel(background())
    started: queue.Queue[None] = queue.Queue(1)
    lock = threading.Lock()
    fetches = [0]

    def hook() -> None:
        with lock:
            fetches[0] += 1
            n = fetches[0]
        if n == 1:
            started.put(None)
            leader_ctx.wait(threading.Event())  # returns when the leader's context ends

    monkeypatch.setattr(identity_mod, "SAML_FETCH_HOOK", hook)
    leader_err: queue.Queue[BaseException | None] = queue.Queue(1)

    def run_leader() -> None:
        try:
            c._saml_map(leader_ctx)
            leader_err.put(None)
        except Exception as err:
            leader_err.put(err)

    threading.Thread(target=run_leader, daemon=True).start()
    started.get(timeout=10)
    waiter_done: queue.Queue[BaseException | None] = queue.Queue(1)

    def run_waiter() -> None:
        try:
            c._saml_map(background())
            waiter_done.put(None)
        except Exception as err:
            waiter_done.put(err)

    threading.Thread(target=run_waiter, daemon=True).start()
    time.sleep(0.02)
    cancel_leader()
    assert leader_err.get(timeout=10) is not None, "the cancelled leader succeeded"
    try:
        werr = waiter_done.get(timeout=10)
    except queue.Empty:
        pytest.fail("waiter hung")
    assert werr is None, f"waiter after a cancelled leader: {werr}"
    assert fetches[0] == 1, f"fetches = {fetches[0]}, want 1 (the leader's, reused by the waiter)"


def test_identity_saml_truncated(gh: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    """A miss on a partial identity list is unknown, not user_not_found.
    Both the identity cap and the page cap truncate."""
    old = identity_mod.SAML_MAX_IDENTITIES
    monkeypatch.setattr(identity_mod, "SAML_MAX_IDENTITIES", 4)  # 7 identities, 2 per page: the listing stops after page 2
    e = gh.setup()
    ident, err = resolve(e, "zed@example.com")  # 4th identity: still listed
    assert err is None and ident.id == "zed", f"zed: {ident} {err}"
    assert e.api.page_count() == 2, f"page queries = {e.api.page_count()}, want 2"
    _, err = resolve(e, "nobody@example.com")
    expect_text(err_decision(err), Code.UNSUPPORTED, "identity list truncated")
    assert "identity limit" in e.logs.text(), "truncation not logged"
    monkeypatch.setattr(identity_mod, "SAML_MAX_IDENTITIES", old)

    # The page cap (httpx.MAX_PAGES) truncates as well.
    e2 = gh.setup()

    def many() -> None:
        e2.api.page_size = 1
        e2.api.identities = [
            {"user": {"login": f"u{i}"}, "samlIdentity": {"nameId": f"u{i}@example.com", "username": f"u{i}"}, "scimIdentity": None} for i in range(60)
        ]

    e2.api.with_(many)
    ident, err = resolve(e2, "u10@example.com")
    assert err is None and ident.id == "u10", f"u10: {ident} {err}"
    _, err = resolve(e2, "u59@example.com")
    itest.expect_code(err_decision(err), Code.UNSUPPORTED)
    # A complete listing still answers user_not_found for a miss.
    e2.api.with_(lambda: setattr(e2.api, "identities", e2.api.identities[:20]))
    e2.clock.advance(11 * 60)
    _, err = resolve(e2, "u59@example.com")
    itest.expect_code(err_decision(err), Code.USER_NOT_FOUND)


def test_identity_saml_filter_mismatch(gh: Harness) -> None:
    """GitHub's userName filter is not trusted; a returned identity must
    carry the email itself."""
    e = gh.setup()
    e.api.with_(
        lambda: setattr(
            e.api,
            "filter_nodes",
            [{"user": {"login": "mallory"}, "samlIdentity": {"nameId": "mallory@example.com", "username": "mallory@example.com"}, "scimIdentity": None}],
        )
    )
    # The non-matching node is ignored; the fallback listing finds zed.
    ident, err = resolve(e, "zed@example.com")
    assert err is None and ident.id == "zed", f"zed: {ident} {err}"
    assert e.api.page_count() != 0, "fallback listing not used"
    _, err = resolve(e, "nobody@example.com")
    itest.expect_code(err_decision(err), Code.USER_NOT_FOUND)
    # A node matching case-insensitively through nameId is accepted without listing.
    by_name_id = [{"user": {"login": "bob"}, "samlIdentity": {"nameId": "Bob@Example.com", "username": "bob"}, "scimIdentity": None}]
    e3 = gh.setup()
    e3.api.with_(lambda: setattr(e3.api, "filter_nodes", by_name_id))
    ident, err = resolve(e3, BOB.email)
    assert err is None and ident.id == "bob" and e3.api.page_count() == 0, f"bob: {ident} {err} (pages {e3.api.page_count()})"


def test_email_domains_spaced_list(gh: Harness) -> None:
    """`acme.com, acme.io` (with the space) is one list of two domains, and
    an upper-case entry matches the lower-case email."""
    e = gh.setup({"identity_mode": "template", "login_template": "{local}", "email_domains": "acme.com, Example.com"})
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), Code.ALLOWED)
    itest.expect_code(e.check(User(email="dana@acme.com"), "repo.read", "repo:acme/api"), Code.ALLOWED)
    itest.expect_code(e.check(User(email="dana@acme.io"), "repo.read", "repo:acme/api"), Code.UNSUPPORTED)


def test_template_email_domains(gh: Harness) -> None:
    """The template applies only to listed domains, so root@attacker.example
    never becomes the login "root"."""
    e = gh.setup({"identity_mode": "template", "login_template": "{local}", "email_domains": "example.com, corp.example"})
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), Code.ALLOWED)
    itest.expect_code(e.check(User(email="dana@CORP.example"), "repo.read", "repo:acme/api"), Code.ALLOWED)
    e.srv.reset()
    d = e.check(User(email="dana@attacker.example"), "repo.read", "repo:acme/api")
    expect_text(d, Code.UNSUPPORTED, "not in email_domains")
    assert e.calls("/users/") == 0, "an unlisted domain reached the API"
    itest.assert_no_canary(d.text)

    # new requires and validates the field in template mode.
    srv = gh.server(spec=False)
    deps, _ = itest.deps(srv)

    def build(v: dict[str, str] | None) -> Exception | None:
        base = {"organization": "acme", "app_id": TEST_APP_ID, "identity_mode": "template"}
        base.update(v or {})
        try:
            GitHub().new(background(), itest.settings("gh", "github", base, {"credential": key_secret()}), deps)
        except Exception as err:
            return err
        return None

    err = build(None)
    assert err is not None and "email_domains" in str(err), f"template without email_domains: {err}"
    for bad in ("a b.com", ",", "exa_mple.com", "acme.com,", "acme.com, ,acme.io"):
        assert build({"email_domains": bad}) is not None, f"email_domains {bad!r} accepted"
        with pytest.raises(ValueError):
            validate_email_domains(bad)
    for good in ("acme.com,acme.io", "acme.com, acme.io", "Example.com"):
        err = build({"email_domains": good})
        assert err is None, f"email_domains {good!r}: {err}"
    # Other modes do not need it.
    err = build({"identity_mode": "saml"})
    assert err is None, err


def test_identity_saml_no_provider_and_errors(gh: Harness) -> None:
    e = gh.setup()
    e.api.with_(lambda: setattr(e.api, "saml", False))
    d = e.check(DANA, "repo.read", "repo:acme/api")
    expect_text(d, Code.UNSUPPORTED, "no SAML identity provider")

    e.api.with_(lambda: setattr(e.api, "saml", True))
    cases: list[tuple[list[dict[str, Any]], Code]] = [
        ([{"type": "FORBIDDEN", "message": "Resource not accessible by integration"}], Code.CREDENTIAL_REJECTED),
        ([{"type": "INSUFFICIENT_SCOPES", "message": "x"}], Code.CREDENTIAL_REJECTED),
        ([{"message": "Something went wrong", "note": itest.CANARY + "gql"}], Code.UPSTREAM_ERROR),
        ([{"type": "RATE_LIMITED", "message": "slow down"}], Code.UPSTREAM_RATE_LIMIT),
    ]
    for errs, code in cases:
        e.api.with_(lambda errs=errs: setattr(e.api, "gql_errors", errs))  # type: ignore[misc]
        itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), code)


def test_identity_template(gh: Harness) -> None:
    e = gh.setup({"identity_mode": "template", "login_template": "{local}", "email_domains": "example.com"})
    d = e.check(DANA, "repo.read", "repo:acme/api")
    itest.expect_code(d, Code.ALLOWED)
    assert e.calls("/api/graphql") == 0 and e.calls("/users/dana") == 1, "template mode must GET /users/{login} and not use GraphQL"
    d = e.check(User(email="nobody@example.com"), "repo.read", "repo:acme/api")
    itest.expect_code(d, Code.USER_NOT_FOUND)
    # A login that renders to an organization is not a user.
    d = e.check(User(email="acme@example.com"), "repo.read", "repo:acme/api")
    expect_text(d, Code.USER_NOT_FOUND, "organization")
    # A template producing an invalid login never hits the API.
    e2 = gh.setup({"identity_mode": "template", "login_template": "{local}.{domain}", "email_domains": "example.com"})
    d = e2.check(DANA, "repo.read", "repo:acme/api")
    itest.expect_code(d, Code.USER_NOT_FOUND)
    assert e2.calls("/users/") == 0, "invalid login reached the API"


def test_identity_map_file(gh: Harness, tmp_path: Any) -> None:
    path = str(tmp_path / "users.txt")

    def write(s: str) -> None:
        with open(path, "w") as f:
            f.write(s)

    write("# hallpass users\n\ndana@example.com dana   # comment\nBob@Example.com=bob\n")
    e = gh.setup({"identity_mode": "map_file", "user_map_file": path})
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), Code.ALLOWED)
    itest.expect_code(e.check(User(email="BOB@example.com"), "repo.read", "repo:acme/api"), Code.ALLOWED)
    itest.expect_code(e.check(CAROL, "repo.read", "repo:acme/api"), Code.USER_NOT_FOUND)
    assert e.calls("/api/graphql") == 0 and e.calls("/users/") == 0, "map_file mode must not look users up upstream"
    # The file is re-read at most every 60 s.
    write("dana@example.com dana\ncarol@example.com carol\n")
    itest.expect_code(e.check(CAROL, "repo.read", "repo:acme/api"), Code.USER_NOT_FOUND)
    e.clock.advance(61)
    itest.expect_code(e.check(CAROL, "repo.read", "repo:acme/api"), Code.DENIED)
    # A broken rewrite keeps the previous map.
    write("dana@example.com not a login\n")
    e.clock.advance(61)
    itest.expect_code(e.check(CAROL, "repo.read", "repo:acme/api"), Code.DENIED)

    # new validates the file exists.
    srv = gh.server()
    deps, _ = itest.deps(srv)
    base = {"url": srv.url, "organization": "acme", "app_id": TEST_APP_ID, "identity_mode": "map_file"}
    secrets = {"credential": key_secret()}
    v = {"user_map_file": str(tmp_path / "missing"), **base}
    with pytest.raises(ValueError):
        GitHub().new(background(), itest.settings("gh", "github", v, secrets), deps)
    with pytest.raises(ValueError):
        GitHub().new(background(), itest.settings("gh", "github", base, secrets), deps)
    for bad in ("x\n", "dana@example.com dana bob\n", "nope dana\n", "dana@example.com bad--login\n"):
        write(bad)
        with pytest.raises(ValueError):
            read_user_map(path)


# -- fields and resources ------------------------------------------------------


def test_fields(gh: Harness) -> None:
    validate_fields(GitHub().fields())
    with pytest.raises(ValueError):
        validate_login("bad--login")  # double hyphen
    with pytest.raises(ValueError):
        validate_login("-bad")  # leading hyphen
    with pytest.raises(ValueError):
        validate_login("a" * 40)  # 40-character login
    with pytest.raises(ValueError):
        validate_app_id("has space")
    with pytest.raises(ValueError):
        validate_installation_id("x1")
    with pytest.raises(ValueError):
        validate_template("static")  # template without placeholder
    with pytest.raises(ValueError):
        validate_template("{user}")  # unknown placeholder
    assert Template("{local}-{domain}").render("dana@example.com") == "dana-example.com", "template"
    srv = gh.server()
    deps, _ = itest.deps(srv)
    s = itest.settings(
        "gh", "github", {"organization": "acme", "app_id": TEST_APP_ID, "identity_mode": "template", "login_template": "static"}, {"credential": key_secret()}
    )
    with pytest.raises(ValueError):
        GitHub().new(background(), s, deps)  # a template without placeholders
    s = itest.settings("gh", "github", {"organization": "acme", "app_id": TEST_APP_ID}, None)
    with pytest.raises(ValueError):
        GitHub().new(background(), s, deps)  # a missing credential
    # github.com layout when url is omitted; defaults apply when keys are absent.
    s = itest.settings("gh", "github", {"organization": "acme", "app_id": TEST_APP_ID}, {"credential": key_secret()})
    gc = GitHub().new(background(), s, deps)
    assert isinstance(gc, GitHubConnection)
    assert gc.rest.base == "https://api.github.com" and gc.graphql_url == "https://api.github.com/graphql" and gc.mode == "saml", (
        f"public bases: {gc.rest.base} {gc.graphql_url} {gc.mode}"
    )
    assert len(srv.calls()) == 0, "new touched the network"


BAD_RESOURCES = [
    ("repo.read", "repo:other/api"),
    ("repo.read", "repo:acme"),
    ("repo.read", "repo:acme/"),
    ("repo.read", "repo:acme/api/extra"),
    ("repo.read", "repo:acme/api@"),
    ("repo.read", "repo:acme/api@-x"),
    ("repo.read", "repo:acme/api@a..b"),
    ("repo.read", "repo:acme/api@a b"),
    ("repo.read", "repo:acme/api?x=1"),
    ("repo.read", "repo:ac me/api"),
    ("repo.read", "repo:acme/.."),
    ("repo.read", "org:acme"),
    ("org.member", "repo:acme/api"),
    ("org.member", "org:other"),
    ("org.member", "org:Acme Inc"),
    ("team.member", "team:acme"),
    ("team.member", "team:other/platform"),
    ("team.member", "team:acme/Platform"),
    ("team.member", "team:acme/plat_form"),
    ("team.member", "org:acme"),
]


def test_bad_resources(gh: Harness) -> None:
    e = gh.setup()
    for action, resource in BAD_RESOURCES:
        d = e.check(DANA, action, resource)
        assert d.code == Code.INVALID_REQUEST, f"{action} {resource} -> {d.code}: {d.text}"
    # Owner comparison is case-insensitive, as GitHub's is.
    itest.expect_code(e.check(DANA, "repo.read", "repo:Acme/api"), Code.ALLOWED)
    itest.expect_code(e.check(DANA, "org.member", "org:ACME"), Code.ALLOWED)
    for ok in ("main", "release/1.2", "feat_x", "v1.0-rc.1"):
        assert valid_branch(ok), f"branch {ok!r} rejected"


# -- repository checks ---------------------------------------------------------


def test_permission_endpoint_statuses(gh: Harness) -> None:
    e = gh.setup()
    d = e.check(DANA, "repo.read", "repo:acme/secret")
    expect_text(d, Code.RESOURCE_NOT_VISIBLE, "not visible")

    def rate_limited() -> None:
        e.api.perm_status = 403
        e.api.perm_header = {"X-Ratelimit-Remaining": ["0"], "X-Ratelimit-Reset": ["1"]}

    e.api.with_(rate_limited)
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), Code.UPSTREAM_RATE_LIMIT)
    e.api.with_(lambda: setattr(e.api, "perm_header", {"X-Ratelimit-Remaining": ["4999"]}))
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), Code.CREDENTIAL_REJECTED)
    e.api.with_(lambda: setattr(e.api, "perm_status", 0))

    # A response with only the lossy permission string is still usable.
    itest.expect_code(e.check(DANA, "repo.push", "repo:acme/legacy"), Code.ALLOWED)
    itest.expect_code(e.check(DANA, "repo.admin", "repo:acme/legacy"), Code.DENIED)
    # has_issues absent -> unknown.
    itest.expect_code(e.check(DANA, "issue.create", "repo:acme/legacy"), Code.UNSUPPORTED)


def test_branch_rules(gh: Harness) -> None:
    e = gh.setup()
    d = e.check(DANA, "repo.push", "repo:acme/api@main")
    expect_text(d, Code.UNSUPPORTED, "requires pull requests")

    d = e.check(DANA, "pr.merge", "repo:acme/api@main")
    expect_text(d, Code.ALLOWED, "branch main has 3 rules (types pull_request, required_status_checks)")

    d = e.check(DANA, "repo.push", "repo:acme/api@release")
    expect_text(d, Code.ALLOWED, "branch release has 1 rules (types required_signatures)")

    e.srv.reset()
    d = e.check(DANA, "repo.push", "repo:acme/api@feature/x")
    expect_text(d, Code.ALLOWED, "no rules")
    assert e.calls("/api/rules/branches/feature/x") == 1 and e.calls("/api/branches/feature/x/protection") == 1, (
        f"branch paths: {e.calls('/api/rules/branches/feature/x')} rules, {e.calls('/api/branches/feature/x/protection')} protection calls"
    )

    # A deny needs no rules lookup.
    e.srv.reset()
    itest.expect_code(e.check(BOB, "repo.push", "repo:acme/api@main"), Code.DENIED)
    assert e.calls("/rules/") == 0, "rules fetched for a deny"
    # Rules endpoint not readable: the App lacks Administration: read, so
    # the branch cannot be evaluated. Never an allow.
    e.api.with_(lambda: setattr(e.api, "rules_status", 403))
    d = e.check(DANA, "repo.push", "repo:acme/api@main")
    expect_text(d, Code.UNSUPPORTED, "Repository Administration: read")
    d = e.check(DANA, "pr.merge", "repo:acme/api@main")
    itest.expect_code(d, Code.UNSUPPORTED)
    # The endpoint answers 200 [] for a branch without rules, so 404 means
    # the repository or branch is not visible.
    e.api.with_(lambda: setattr(e.api, "rules_status", 404))
    d = e.check(DANA, "repo.push", "repo:acme/api@main")
    expect_text(d, Code.RESOURCE_NOT_VISIBLE, "not visible")
    e.api.with_(lambda: setattr(e.api, "rules_status", 500))
    itest.expect_code(e.check(DANA, "repo.push", "repo:acme/api@main"), Code.UPSTREAM_ERROR)
    # Other repo actions ignore @branch.
    e.api.with_(lambda: setattr(e.api, "rules_status", 0))
    e.srv.reset()
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api@main"), Code.ALLOWED)
    assert e.calls("/rules/") == 0, "rules fetched for repo.read"


def test_branch_rule_types(gh: Harness) -> None:
    """update and merge_queue rules route changes through bypass actors or
    the queue like pull_request does; creation and deletion do not affect a
    push to an existing branch."""
    e = gh.setup()
    d = e.check(DANA, "repo.push", "repo:acme/webapp@dev")
    expect_text(d, Code.UNSUPPORTED, "update rule")
    d = e.check(DANA, "repo.push", "repo:acme/webapp@queue")
    expect_text(d, Code.UNSUPPORTED, "merge_queue rule")
    d = e.check(DANA, "repo.push", "repo:acme/webapp@lifecycle")
    expect_text(d, Code.ALLOWED, "types creation, deletion")
    # Merges are not direct pushes.
    itest.expect_code(e.check(DANA, "pr.merge", "repo:acme/webapp@dev"), Code.ALLOWED)
    itest.expect_code(e.check(DANA, "pr.merge", "repo:acme/webapp@queue"), Code.ALLOWED)


def test_branch_protection(gh: Harness) -> None:
    """Classic branch protection: push restrictions by user and team,
    required reviews, admin enforcement and endpoint errors."""
    e = gh.setup()

    def set_prot(key: str, prot: dict[str, Any]) -> None:
        e.api.with_(lambda: e.api.protection.__setitem__(key, prot))

    def restrict(users: list[str] | None, teams: list[str] | None) -> dict[str, Any]:
        return {"users": [{"login": x} for x in users or []], "teams": [{"slug": x} for x in teams or []], "apps": []}

    def set_team(team: str, login: str, m: Membership | None) -> None:
        def f() -> None:
            if m is None:
                e.api.teams[team].pop(login, None)
            else:
                e.api.teams[team][login] = m

        e.api.with_(f)

    # dana has write (not admin) on webapp: no admin bypass to consider.
    set_prot("webapp@main", {"restrictions": restrict(["Dana"], None), "enforce_admins": {"enabled": False}})
    d = e.check(DANA, "repo.push", "repo:acme/webapp@main")
    expect_text(d, Code.ALLOWED, "among those allowed to push")

    # Not listed, not in the listed team (release has bob only): a positive no.
    set_prot("webapp@main", {"restrictions": restrict(["carol"], ["release"])})
    e.srv.reset()
    d = e.check(DANA, "repo.push", "repo:acme/webapp@main")
    expect_text(d, Code.DENIED, "restricts pushes")
    assert e.calls("/teams/release/memberships/dana") == 1, "team membership not consulted"
    # UNVERIFIED in the code: whether the restriction blocks merges; unknown.
    d = e.check(DANA, "pr.merge", "repo:acme/webapp@main")
    expect_text(d, Code.UNSUPPORTED, "merging may be rejected")

    # Member of a listed team.
    set_prot("webapp@main", {"restrictions": restrict(None, ["release", "platform"])})
    d = e.check(DANA, "repo.push", "repo:acme/webapp@main")
    expect_text(d, Code.ALLOWED, "among those allowed to push")
    # A pending team membership does not count; an empty state is unknown.
    set_team("release", "dana", Membership("pending", "member"))
    set_prot("webapp@main", {"restrictions": restrict(None, ["release"])})
    itest.expect_code(e.check(DANA, "repo.push", "repo:acme/webapp@main"), Code.DENIED)
    set_team("release", "dana", Membership("", "member"))
    itest.expect_code(e.check(DANA, "repo.push", "repo:acme/webapp@main"), Code.UNSUPPORTED)
    set_team("release", "dana", None)

    # Teams that cannot be checked: unknown, never a deny.
    e.api.with_(lambda: setattr(e.api, "team_member_status", 403))
    d = e.check(DANA, "repo.push", "repo:acme/webapp@main")
    expect_text(d, Code.UNSUPPORTED, "may not read")
    e.api.with_(lambda: setattr(e.api, "team_member_status", 500))
    itest.expect_code(e.check(DANA, "repo.push", "repo:acme/webapp@main"), Code.UPSTREAM_ERROR)
    e.api.with_(lambda: setattr(e.api, "team_member_status", 0))
    set_prot("webapp@main", {"restrictions": restrict(None, ["Not A Slug"])})
    e.srv.reset()
    itest.expect_code(e.check(DANA, "repo.push", "repo:acme/webapp@main"), Code.UNSUPPORTED)
    assert e.calls("/teams/") == 0, "an invalid team slug reached the API"

    # Required reviews: a direct push is unknown, a merge is not affected.
    set_prot("webapp@main", {"required_pull_request_reviews": {"required_approving_review_count": 1}})
    d = e.check(DANA, "repo.push", "repo:acme/webapp@main")
    expect_text(d, Code.UNSUPPORTED, "requires pull request reviews")
    d = e.check(DANA, "pr.merge", "repo:acme/webapp@main")
    expect_text(d, Code.ALLOWED, "classic protection")

    # Admins: exempt unless enforce_admins is enabled; unknown when GitHub
    # does not say. dana is admin on api.
    prot: dict[str, Any] = {
        "restrictions": restrict(["carol"], None),
        "required_pull_request_reviews": {"required_approving_review_count": 2},
        "enforce_admins": {"enabled": False},
    }
    set_prot("api@release", dict(prot))
    d = e.check(DANA, "repo.push", "repo:acme/api@release")
    expect_text(d, Code.ALLOWED, "does not enforce its protection for admins")
    prot["enforce_admins"] = {"enabled": True}
    set_prot("api@release", dict(prot))
    expect_text(e.check(DANA, "repo.push", "repo:acme/api@release"), Code.DENIED, "restricts pushes")
    del prot["enforce_admins"]
    set_prot("api@release", dict(prot))
    expect_text(e.check(DANA, "repo.push", "repo:acme/api@release"), Code.UNSUPPORTED, "admins are exempt")

    # The protection endpoint itself.
    e.api.with_(lambda: setattr(e.api, "protection_status", 403))
    d = e.check(DANA, "repo.push", "repo:acme/webapp@main")
    expect_text(d, Code.UNSUPPORTED, "Repository Administration: read")
    e.api.with_(lambda: setattr(e.api, "protection_status", 500))
    itest.expect_code(e.check(DANA, "repo.push", "repo:acme/webapp@main"), Code.UPSTREAM_ERROR)
    e.api.with_(lambda: setattr(e.api, "protection_status", 0))
    # 404 is "not protected": the allow stands.
    d = e.check(DANA, "repo.push", "repo:acme/webapp@other")
    expect_text(d, Code.ALLOWED, "no classic protection")
    # Denied by permissions: neither endpoint is read.
    e.srv.reset()
    itest.expect_code(e.check(BOB, "repo.push", "repo:acme/webapp@main"), Code.DENIED)
    assert e.calls("/protection") == 0 and e.calls("/rules/") == 0, "branch endpoints read for a deny"
    for d in (e.check(DANA, "repo.push", "repo:acme/webapp@main"), e.check(DANA, "pr.merge", "repo:acme/webapp@main")):
        itest.assert_no_canary(d.text)


def test_pr_create_forking(gh: Harness) -> None:
    """Without push a pull request needs a fork, so allow_forking decides;
    absent it is unknown."""
    e = gh.setup()
    d = e.check(BOB, "pr.create", "repo:acme/webapp")
    expect_text(d, Code.DENIED, "forking disabled")
    assert "pull request needs push access" in d.text, f"text {d.text!r}"
    e.api.with_(lambda: e.api.repos["api"].pop("allow_forking"))
    d = e.check(BOB, "pr.create", "repo:acme/api")
    expect_text(d, Code.UNSUPPORTED, "may be forked")
    e.api.with_(lambda: e.api.repos["api"].__setitem__("allow_forking", True))
    d = e.check(BOB, "pr.create", "repo:acme/api")
    expect_text(d, Code.ALLOWED, "via fork")
    # With push the repository record is not needed.
    e.srv.reset()
    itest.expect_code(e.check(DANA, "pr.create", "repo:acme/webapp"), Code.ALLOWED)
    assert e.calls("/repos/acme/webapp") == 1, f"repository read for a pusher: {e.calls('/repos/acme/webapp')} calls"  # the permission call only
    # Repository record not readable: unknown, never a deny or an allow.
    e.api.with_(lambda: setattr(e.api, "repo_status", 404))
    itest.expect_code(e.check(BOB, "pr.create", "repo:acme/api"), Code.RESOURCE_NOT_VISIBLE)
    e.api.with_(lambda: setattr(e.api, "repo_status", 403))
    itest.expect_code(e.check(BOB, "pr.create", "repo:acme/api"), Code.CREDENTIAL_REJECTED)
    e.api.with_(lambda: setattr(e.api, "repo_status", 0))


def test_custom_repository_role(gh: Harness) -> None:
    """A custom role may grant abilities the five booleans do not show, so a
    missing level is unknown, not a deny."""
    e = gh.setup()
    d = e.check(BOB, "repo.push", "repo:acme/custom")
    expect_text(d, Code.UNSUPPORTED, "custom repository role")
    assert "extra abilities not modeled" in d.text, f"text {d.text!r}"
    # When the booleans grant the level, allow as for any role.
    expect_text(e.check(BOB, "repo.read", "repo:acme/custom"), Code.ALLOWED, "security-champion")
    # A lossy record whose permission string is not a base role is unknown.
    itest.expect_code(e.check(BOB, "repo.read", "repo:acme/legacy"), Code.UNSUPPORTED)
    # The base roles still deny.
    itest.expect_code(e.check(BOB, "repo.push", "repo:acme/api"), Code.DENIED)
    itest.expect_code(e.check(CAROL, "repo.read", "repo:acme/api"), Code.DENIED)


def test_empty_membership_state(gh: Harness) -> None:
    """A membership record without a state is unknown."""
    e = gh.setup({"identity_mode": "template", "email_domains": "example.com"})
    frank = User(email="frank@example.com")
    expect_text(e.check(frank, "org.member", "org:acme"), Code.UNSUPPORTED, "no membership state")
    itest.expect_code(e.check(frank, "org.admin", "org:acme"), Code.UNSUPPORTED)
    expect_text(e.check(frank, "team.member", "team:acme/platform"), Code.UNSUPPORTED, "no membership state")
    itest.expect_code(e.check(frank, "team.maintainer", "team:acme/platform"), Code.UNSUPPORTED)


# -- organization and team checks ----------------------------------------------


def test_org_repo_create_variants(gh: Harness) -> None:
    e = gh.setup()
    d = e.check(BOB, "org.repo.create", "org:acme")
    expect_text(d, Code.ALLOWED, "(private)")
    itest.expect_code(e.check(DANA, "org.repo.create", "org:acme"), Code.ALLOWED)
    e.api.with_(lambda: e.api.org.__setitem__("members_can_create_repositories", False))
    itest.expect_code(e.check(BOB, "org.repo.create", "org:acme"), Code.DENIED)
    itest.expect_code(e.check(DANA, "org.repo.create", "org:acme"), Code.ALLOWED)
    e.api.with_(lambda: e.api.org.pop("members_can_create_repositories"))
    itest.expect_code(e.check(BOB, "org.repo.create", "org:acme"), Code.UNSUPPORTED)
    itest.expect_code(e.check(CAROL, "org.repo.create", "org:acme"), Code.DENIED)
    itest.expect_code(e.check(EVE, "org.repo.create", "org:acme"), Code.DENIED)


def test_team_not_found(gh: Harness) -> None:
    e = gh.setup()
    d = e.check(DANA, "team.member", "team:acme/nope")
    itest.expect_code(d, Code.RESOURCE_NOT_VISIBLE)
    itest.expect_code(e.check(EVE, "team.member", "team:acme/platform"), Code.DENIED)
    itest.expect_code(e.check(EVE, "team.maintainer", "team:acme/platform"), Code.DENIED)


# -- failures, probe, canary ---------------------------------------------------


def test_failures(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(DANA, "repo.read", "repo:acme/api"), Code.ALLOWED)
    itest.failure_cases(e.srv, lambda: e.check(DANA, "repo.read", "repo:acme/api"))
    # Also before any token exists: the failure hits the token exchange.
    e2 = gh.setup({"identity_mode": "template", "email_domains": "example.com"})
    itest.failure_cases(e2.srv, lambda: e2.check(DANA, "repo.read", "repo:acme/api"))


def test_probe(gh: Harness) -> None:
    e = gh.setup()
    r = e.conn.probe(background())
    assert r.summary == "app hallpass-reader installed in acme" and len(r.warnings) == 0, r

    def over() -> None:
        e.api.inst_perms = {"metadata": "read", "contents": "write", "administration": "admin"}
        e.api.saml = False

    e.api.with_(over)
    r = e.conn.probe(background())
    joined = "\n".join(r.warnings)
    for want in ("members: read", "contents: write", "administration: admin", "no SAML identity provider"):
        assert want in joined, f"warnings lack {want!r}:\n{joined}"
    assert len(r.warnings) == 4, f"warnings: {r.warnings}"

    def members_only() -> None:
        e.api.inst_perms = {"members": "read"}
        e.api.saml = True

    e.api.with_(members_only)
    r = e.conn.probe(background())
    assert len(r.warnings) == 1 and "metadata" in r.warnings[0], f"warnings: {r.warnings}"
    e3 = gh.setup({"installation_id": "7"})
    r = e3.conn.probe(background())
    assert len(r.warnings) == 1 and "installation_id" in r.warnings[0], f"warnings: {r.warnings}"
    e.srv.fail(itest.Failure.UNAUTHORIZED)
    try:
        with pytest.raises(Exception):  # noqa: B017 - Go: any error
            e.conn.probe(background())
    finally:
        e.srv.fail(itest.Failure.NONE)


def test_no_secret_in_decisions_or_logs(gh: Harness) -> None:
    e = gh.setup()
    decisions = [
        e.check(DANA, "repo.read", "repo:acme/api"),
        e.check(DANA, "repo.read", "repo:acme/secret"),
        e.check(CAROL, "repo.read", "repo:acme/api"),
    ]
    e.srv.fail(itest.Failure.UNAUTHORIZED)
    decisions.append(e.check(DANA, "repo.read", "repo:acme/api"))
    e.srv.fail(itest.Failure.NONE)
    for d in decisions:
        itest.assert_no_canary(d.text)
    itest.assert_no_canary(e.logs.text())
    assert e.logs.text() != "", "expected debug log lines from httpx"


# -- per-action allow/deny (coverage gate) -------------------------------------


def test_action_repo_read_allow(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(BOB, "repo.read", "repo:acme/api"), Code.ALLOWED)


def test_action_repo_read_deny(gh: Harness) -> None:
    e = gh.setup()
    expect_text(e.check(CAROL, "repo.read", "repo:acme/api"), Code.DENIED, "does not include pull")


def test_action_repo_triage_allow(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(DANA, "repo.triage", "repo:acme/webapp"), Code.ALLOWED)


def test_action_repo_triage_deny(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(BOB, "repo.triage", "repo:acme/api"), Code.DENIED)


def test_action_repo_push_allow(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(DANA, "repo.push", "repo:acme/webapp"), Code.ALLOWED)


def test_action_repo_push_deny(gh: Harness) -> None:
    e = gh.setup()
    expect_text(e.check(BOB, "repo.push", "repo:acme/api"), Code.DENIED, "bob has read on acme/api")


def test_action_repo_maintain_allow(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(DANA, "repo.maintain", "repo:acme/api"), Code.ALLOWED)


def test_action_repo_maintain_deny(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(DANA, "repo.maintain", "repo:acme/webapp"), Code.DENIED)


def test_action_repo_admin_allow(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(DANA, "repo.admin", "repo:acme/api"), Code.ALLOWED)


def test_action_repo_admin_deny(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(DANA, "repo.admin", "repo:acme/webapp"), Code.DENIED)


def test_action_issue_create_allow(gh: Harness) -> None:
    e = gh.setup()
    expect_text(e.check(BOB, "issue.create", "repo:acme/api"), Code.ALLOWED, "issues are enabled")


def test_action_issue_create_deny(gh: Harness) -> None:
    e = gh.setup()
    expect_text(e.check(DANA, "issue.create", "repo:acme/webapp"), Code.DENIED, "issues are disabled")
    itest.expect_code(e.check(CAROL, "issue.create", "repo:acme/api"), Code.DENIED)


def test_action_pr_create_allow(gh: Harness) -> None:
    e = gh.setup()
    expect_text(e.check(BOB, "pr.create", "repo:acme/api"), Code.ALLOWED, "via fork; pushing a branch to the repository itself needs push")
    d = e.check(DANA, "pr.create", "repo:acme/api")
    itest.expect_code(d, Code.ALLOWED)
    assert "via fork" not in d.text, f"admin should not be told to fork: {d.text}"


def test_action_pr_create_deny(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(CAROL, "pr.create", "repo:acme/api"), Code.DENIED)


def test_action_pr_merge_allow(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(DANA, "pr.merge", "repo:acme/webapp"), Code.ALLOWED)


def test_action_pr_merge_deny(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(BOB, "pr.merge", "repo:acme/api"), Code.DENIED)


def test_action_org_member_allow(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(BOB, "org.member", "org:acme"), Code.ALLOWED)


def test_action_org_member_deny(gh: Harness) -> None:
    e = gh.setup()
    expect_text(e.check(CAROL, "org.member", "org:acme"), Code.DENIED, "not a member")
    expect_text(e.check(EVE, "org.member", "org:acme"), Code.DENIED, "pending")


def test_action_org_admin_allow(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(DANA, "org.admin", "org:acme"), Code.ALLOWED)


def test_action_org_admin_deny(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(BOB, "org.admin", "org:acme"), Code.DENIED)
    itest.expect_code(e.check(CAROL, "org.admin", "org:acme"), Code.DENIED)


def test_action_org_repo_create_allow(gh: Harness) -> None:
    e = gh.setup()
    expect_text(e.check(BOB, "org.repo.create", "org:acme"), Code.ALLOWED, "members may create repositories")


def test_action_org_repo_create_deny(gh: Harness) -> None:
    e = gh.setup()
    e.api.with_(lambda: e.api.org.__setitem__("members_can_create_repositories", False))
    expect_text(e.check(BOB, "org.repo.create", "org:acme"), Code.DENIED, "may not create repositories")


def test_action_team_member_allow(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(BOB, "team.member", "team:acme/platform"), Code.ALLOWED)


def test_action_team_member_deny(gh: Harness) -> None:
    e = gh.setup()
    expect_text(e.check(CAROL, "team.member", "team:acme/platform"), Code.DENIED, "not a member of team acme/platform")


def test_action_team_maintainer_allow(gh: Harness) -> None:
    e = gh.setup()
    itest.expect_code(e.check(DANA, "team.maintainer", "team:acme/platform"), Code.ALLOWED)


def test_action_team_maintainer_deny(gh: Harness) -> None:
    e = gh.setup()
    expect_text(e.check(BOB, "team.maintainer", "team:acme/platform"), Code.DENIED, "not a maintainer")
