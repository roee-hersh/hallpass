"""Port of internal/integrations/slack/slack_test.go."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from hallpass.core.catalog import Resource, parse_resource
from hallpass.core.context import background
from hallpass.core.decision import Code, Decision, to_decision
from hallpass.core.integration import CheckRequest, Connection, Identity, User, find_action, validate_fields
from hallpass.core.secret import Secret
from hallpass.core.secret import literal as secret_literal
from hallpass.integrations.slack import INTEGRATION
from hallpass.integrations.slack.slack import (
    ATTR_ADMIN,
    ATTR_DELETED,
    ATTR_ENTERPRISE_ADMIN,
    ATTR_ENTERPRISE_ID,
    ATTR_OWNER,
    ATTR_TEAM_ID,
    SlackUser,
    parse_posters,
    posters_allows,
    validate_team_id,
)
from tests import harness as itest
from tests.harness.spec import SpecOptions, spec_from_env

# The fake workspace's bot token: a real-looking prefix carrying the canary.
TOKEN = "xoxb-" + itest.CANARY + "x"

# Fixture user ids.
U_FULL = "U0000FULL1"
U_ADMIN = "U0000ADMIN"
U_OWNER = "U0000OWNER"
U_GUEST = "U0000GUEST"
U_ULTRA = "U0000ULTRA"
U_DEAD = "U0000DEAD1"
U_BOT = "U0000BOT01"
U_INVITED = "U0000INVIT"
U_STRANGER = "U0000STRNG"
U_GRID_ADM = "U0000GRIDA"
U_GRID_USER = "U0000GRIDU"

# Fixture channel ids.
C_PUBLIC = "C0000PUBLC"
C_GENERAL = "C0000GENRL"
C_RESTRICT = "C0000RSTRC"
C_ARCHIVED = "C0000ARCHV"
C_NO_PROPS = "C0000NOPRP"  # conversations.info returns no properties object
G_PRIVATE = "G0000PRIVT"
G_HIDDEN = "G0000HIDDN"
S_GROUP = "S0000GROUP"


@dataclass
class FakeChannel:
    obj: dict[str, Any]
    members: list[str]
    visible: bool  # False: conversations.info answers channel_not_found


def user(id: str, email: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    u: dict[str, Any] = {
        "id": id,
        "team_id": "T0000TEAM1",
        "name": id.lower(),
        "real_name": "Person " + id,
        "deleted": False,
        "is_admin": False,
        "is_owner": False,
        "is_primary_owner": False,
        "is_restricted": False,
        "is_ultra_restricted": False,
        "is_bot": False,
        "is_invited_user": False,
        "profile": {"email": email, "real_name": "Person " + id, "title": itest.CANARY + "title"},
    }
    u.update(extra or {})
    return u


def chan_obj(id: str, name: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """A channel object. By default it carries a properties object with an
    empty posting rule (everyone may post); pass "properties": None to leave
    the object out, as Slack may for a channel without properties."""
    c: dict[str, Any] = {
        "id": id,
        "name": name,
        "is_channel": True,
        "is_archived": False,
        "is_private": False,
        "is_general": False,
        "is_member": True,
        "is_ext_shared": False,
        "is_shared": False,
        "purpose": {"value": itest.CANARY + "purpose"},
        "properties": {"posting_restricted_to": {"type": [], "user": []}},
    }
    for k, v in (extra or {}).items():
        if v is None:
            c.pop(k, None)
            continue
        c[k] = v
    return c


def _atoi(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return 0


@dataclass
class FakeSlack:
    """The fake Web API."""

    users: dict[str, dict[str, Any]] = field(default_factory=dict)  # email -> user object
    channels: dict[str, FakeChannel] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)  # channel ids in listing order
    groups: list[dict[str, Any]] = field(default_factory=list)
    prefs: dict[str, Any] = field(default_factory=dict)  # team.preferences.list fields
    pref_scope: bool = True  # team.preferences:read granted
    ug_scope: bool = True  # usergroups:read granted
    page_size: int = 0  # users.conversations page size, 0 = one page
    member_ps: int = 0  # conversations.members page size, 0 = one page
    list_ps: int = 0  # conversations.list page size, 0 = one page
    fail: dict[str, str] = field(default_factory=dict)  # method -> ok:false error code
    needed: str = ""  # scope named on missing_scope
    scopes_hdr: str = ""  # X-OAuth-Scopes on auth.test
    errors: list[str] = field(default_factory=list)  # Go: t.Errorf from the handler

    def user_by_id(self, id: str) -> dict[str, Any] | None:
        for u in self.users.values():
            if u.get("id") == id:
                return u
        return None

    def handler(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        def write(body: dict[str, Any]) -> None:
            w.header().set("Content-Type", "application/json")
            w.write_header(200)
            w.write(json.dumps(body) + "\n")

        def fail(code: str) -> None:
            body: dict[str, Any] = {"ok": False, "error": code}
            if code == "missing_scope":
                body["needed"] = self.needed
                body["provided"] = "users:read"
            write(body)

        def page(n: int, size: int) -> tuple[int, int, str]:
            lo = 0
            c = r.q("cursor")
            if c != "":
                lo = _atoi(c)
            hi = n
            nxt = ""
            if size > 0 and lo + size < n:
                hi = lo + size
                nxt = str(hi)
            return lo, hi, nxt

        method = r.path.removeprefix("/api/")
        if r.method != "GET":
            self.errors.append(f"{method} called with {r.method}, want GET")
        if r.header.get("Authorization") != "Bearer " + TOKEN:
            fail("invalid_auth")
            return
        code = self.fail.get(method, "")
        if code != "":
            fail(code)
            return
        q = r
        if method == "auth.test":
            if self.scopes_hdr != "":
                w.header().set("X-OAuth-Scopes", self.scopes_hdr)
            write(
                {
                    "ok": True,
                    "url": "https://" + itest.CANARY + ".slack.com/",
                    "team": "Acme",
                    "user": "hallpass",
                    "team_id": "T0000TEAM1",
                    "user_id": "U0000HALLP",
                    "bot_id": "B0000HALLP",
                    "is_enterprise_install": False,
                }
            )
        elif method == "users.lookupByEmail":
            u = self.users.get(q.q("email"))
            if u is None:
                fail("users_not_found")
                return
            write({"ok": True, "user": u})
        elif method == "conversations.info":
            ch = self.channels.get(q.q("channel"))
            if ch is None or not ch.visible:
                fail("channel_not_found")
                return
            write({"ok": True, "channel": ch.obj})
        elif method == "users.conversations":
            uid = q.q("user")
            if self.user_by_id(uid) is None:
                fail("user_not_found")
                return
            if q.q("types") != "public_channel,private_channel" or q.q("limit") == "":
                self.errors.append(f"users.conversations query {r.query}")
            mine = []
            for id in self.order:
                ch = self.channels[id]
                if not ch.visible:
                    continue
                for m in ch.members:
                    if m == uid:
                        mine.append({"id": id, "name": ch.obj.get("name")})
            lo, hi, nxt = page(len(mine), self.page_size)
            # Go slices a nil slice when the user is in no channel: null.
            write({"ok": True, "channels": mine[lo:hi] if mine else None, "response_metadata": {"next_cursor": nxt}})
        elif method == "conversations.list":
            if q.q("types") != "public_channel" or q.q("exclude_archived") != "true" or q.q("limit") == "":
                self.errors.append(f"conversations.list query {r.query}")
            lst = []
            for id in self.order:
                ch = self.channels[id]
                if not ch.visible or ch.obj.get("is_private") is True or ch.obj.get("is_archived") is True:
                    continue
                lst.append(ch.obj)
            lo, hi, nxt = page(len(lst), self.list_ps)
            write({"ok": True, "channels": lst[lo:hi] if lst else None, "response_metadata": {"next_cursor": nxt}})
        elif method == "conversations.members":
            ch = self.channels.get(q.q("channel"))
            if ch is None or not ch.visible:
                fail("channel_not_found")
                return
            lo, hi, nxt = page(len(ch.members), self.member_ps)
            write({"ok": True, "members": ch.members[lo:hi], "response_metadata": {"next_cursor": nxt}})
        elif method == "team.preferences.list":
            if not self.pref_scope:
                self.needed = "team.preferences:read"
                fail("missing_scope")
                return
            body: dict[str, Any] = {"ok": True}
            body.update(self.prefs)
            write(body)
        elif method == "usergroups.list":
            if not self.ug_scope:
                self.needed = "usergroups:read"
                fail("missing_scope")
                return
            write({"ok": True, "usergroups": self.groups})
        else:
            self.errors.append(f"unexpected method {method}")
            fail("unknown_method")


def new_fake() -> FakeSlack:
    return FakeSlack(
        users={
            "dana@example.com": user(U_FULL, "dana@example.com"),
            "admin@example.com": user(U_ADMIN, "admin@example.com", {"is_admin": True}),
            "owner@example.com": user(U_OWNER, "owner@example.com", {"is_admin": True, "is_owner": True}),
            "guest@example.com": user(U_GUEST, "guest@example.com", {"is_restricted": True}),
            "ultra@example.com": user(U_ULTRA, "ultra@example.com", {"is_restricted": True, "is_ultra_restricted": True}),
            "dead@example.com": user(U_DEAD, "dead@example.com", {"deleted": True}),
            "bot@example.com": user(U_BOT, "bot@example.com", {"is_bot": True}),
            "invited@example.com": user(U_INVITED, "invited@example.com", {"is_invited_user": True}),
            "stranger@example.com": user(U_STRANGER, "stranger@example.com", {"is_stranger": True}),
            "gridadmin@example.com": user(
                U_GRID_ADM,
                "gridadmin@example.com",
                {"enterprise_user": {"id": U_GRID_ADM, "enterprise_id": "E0000ENTRP", "is_admin": True, "is_owner": False}},
            ),
            "griduser@example.com": user(
                U_GRID_USER,
                "griduser@example.com",
                {"enterprise_user": {"id": U_GRID_USER, "enterprise_id": "E0000ENTRP", "is_admin": False, "is_owner": False}},
            ),
        },
        channels={
            C_PUBLIC: FakeChannel(chan_obj(C_PUBLIC, "public"), [U_FULL, U_ADMIN, U_OWNER, U_ULTRA], True),
            C_GENERAL: FakeChannel(chan_obj(C_GENERAL, "general", {"is_general": True}), [U_FULL, U_ADMIN, U_OWNER, U_GUEST], True),
            C_RESTRICT: FakeChannel(
                chan_obj(C_RESTRICT, "announcements", {"properties": {"posting_restricted_to": {"type": ["admin"], "user": [U_ULTRA]}}}),
                [U_FULL, U_ADMIN, U_GUEST, U_ULTRA],
                True,
            ),
            C_ARCHIVED: FakeChannel(chan_obj(C_ARCHIVED, "old", {"is_archived": True}), [U_FULL, U_ADMIN], True),
            C_NO_PROPS: FakeChannel(chan_obj(C_NO_PROPS, "plain", {"properties": None}), [U_FULL, U_ADMIN, U_GUEST], True),
            G_PRIVATE: FakeChannel(chan_obj(G_PRIVATE, "secret", {"is_private": True, "is_channel": False, "is_group": True}), [U_FULL, U_GUEST], True),
            G_HIDDEN: FakeChannel(chan_obj(G_HIDDEN, "hidden", {"is_private": True}), [U_FULL], False),
        },
        order=[C_PUBLIC, C_GENERAL, C_RESTRICT, C_ARCHIVED, C_NO_PROPS, G_PRIVATE, G_HIDDEN],
        groups=[{"id": S_GROUP, "handle": "oncall", "users": [U_FULL, U_ADMIN]}],
        prefs={"who_can_post_general": {"type": ["admin"], "user": []}, "msg_edit_window_mins": -1},
        pref_scope=True,
        ug_scope=True,
        fail={},
        scopes_hdr="users:read,users:read.email,channels:read,groups:read,team.preferences:read,usergroups:read",
    )


class Env:
    """The servers and fakes of one test (Go: itest.NewServer's t.Cleanup)."""

    def __init__(self) -> None:
        self.servers: list[itest.Server] = []
        self.fakes: list[FakeSlack] = []

    def setup(self, values: dict[str, str] | None = None) -> tuple[itest.Server, FakeSlack, Connection]:
        return self.setup_token(values, secret_literal(TOKEN))

    def setup_token(self, values: dict[str, str] | None, cred: Secret) -> tuple[itest.Server, FakeSlack, Connection]:
        srv = itest.Server()
        self.servers.append(srv)
        # Slack's published description is the legacy one: the token is a
        # query parameter there, team_id (org installs) and
        # team.preferences.list are newer than it.
        srv.use_spec(
            spec_from_env("slack"),
            SpecOptions(
                strip_prefix=[r"/api"],
                optional_params=["token"],
                allow_query=["team_id"],
                ignore_paths=[r"^(/api)?/team\.preferences\.list$"],
            ),
        )
        f = new_fake()
        self.fakes.append(f)
        srv.handle("", "/api/*", f.handler)
        deps, _ = itest.deps(srv)
        v = {"url": srv.url + "/api", "assume_default_prefs": "false"}
        v.update(values or {})
        s = itest.settings("slack", "slack", v, {"credential": cred})
        c = INTEGRATION.new(background(), s, deps)
        return srv, f, c

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


dana = User(email="dana@example.com")
admin = User(email="admin@example.com")
owner = User(email="owner@example.com")
guest = User(email="guest@example.com")
ultra = User(email="ultra@example.com")
dead = User(email="dead@example.com")
bot = User(email="bot@example.com")
invited = User(email="invited@example.com")
stranger = User(email="stranger@example.com")
grid_adm = User(email="gridadmin@example.com")
grid_user = User(email="griduser@example.com")
nobody = User(email="nobody@example.com")


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, INTEGRATION, u, action, resource)


def expect_text(d: Decision, sub: str) -> None:
    assert sub in d.text, f"decision text {d.text!r} does not mention {sub!r}"


def methods(srv: itest.Server) -> list[str]:
    return [c.path.removeprefix("/api/") for c in srv.calls()]


def count(ms: list[str], m: str) -> int:
    return sum(1 for x in ms if x == m)


def is_code(err: BaseException | None, code: Code) -> bool:
    if err is None:
        return code is Code.ALLOWED  # Go: ToDecision(nil) is allowed
    return to_decision(err).code == code


def probe_err(c: Connection) -> BaseException | None:
    try:
        c.probe(background())
    except Exception as e:
        return e
    return None


# Identity.


def test_identity(env: Env) -> None:
    srv, _, c = env.setup()
    ident = c.resolve_identity(background(), dana)
    assert (
        ident.id == U_FULL
        and ident.display == "Person " + U_FULL
        and ident.attr(ATTR_ADMIN) == "false"
        and ident.attr(ATTR_DELETED) == "false"
        and ident.attr(ATTR_TEAM_ID) == "T0000TEAM1"
    ), f"identity {ident}"
    assert ident.attr(ATTR_ENTERPRISE_ADMIN) == "", "non-Grid user should have no enterprise attrs"
    assert isinstance(ident.native, SlackUser), f"native is {type(ident.native)}"
    last = srv.last_call()
    assert last.method == "GET" and last.path == "/api/users.lookupByEmail" and last.q("email") == dana.email, (
        f"lookup call {last.method} {last.path} {last.query}"
    )
    assert "team_id" not in last.query, "team_id sent without configuration"

    ident = c.resolve_identity(background(), admin)
    assert ident.attr(ATTR_ADMIN) == "true", "admin attr"
    ident = c.resolve_identity(background(), grid_adm)
    assert ident.attr(ATTR_ENTERPRISE_ADMIN) == "true" and ident.attr(ATTR_ENTERPRISE_ID) == "E0000ENTRP", f"grid attrs {ident.attrs}"

    with pytest.raises(Exception) as ei:
        c.resolve_identity(background(), nobody)
    assert is_code(ei.value, Code.USER_NOT_FOUND), f"nobody: {ei.value}"
    itest.expect_code(check(c, nobody, "user.active", "workspace"), Code.USER_NOT_FOUND)


def test_inactive_accounts(env: Env) -> None:
    _, _, c = env.setup()
    d = check(c, dead, "user.active", "workspace")
    itest.expect_code(d, Code.DENIED)
    expect_text(d, "deactivated")
    d = check(c, bot, "user.active", "workspace")
    itest.expect_code(d, Code.DENIED)
    expect_text(d, "bot")
    d = check(c, invited, "user.active", "workspace")
    itest.expect_code(d, Code.DENIED)
    expect_text(d, "invited")
    # Inactive accounts are denied everything, without a channel lookup.
    srv, _, c = env.setup()
    itest.expect_code(check(c, dead, "channel.read", "channel:" + C_PUBLIC), Code.DENIED)
    assert count(methods(srv), "conversations.info") == 0, "channel looked up for a deactivated account"


def test_slackbot_is_bot(env: Env) -> None:
    _, f, c = env.setup()
    f.users["slackbot@example.com"] = user("USLACKBOT", "slackbot@example.com")
    d = check(c, User(email="slackbot@example.com"), "user.active", "workspace")
    itest.expect_code(d, Code.DENIED)
    expect_text(d, "bot")


def test_token_prefix(env: Env) -> None:
    srv, _, c = env.setup_token(None, itest.literal("not-a-bot-token"))
    d = check(c, dana, "user.active", "workspace")
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)
    expect_text(d, "xoxb-")
    assert len(srv.calls()) == 0, "a request was sent with a non-bot token"
    assert "not-a-bot-token" not in d.text, "decision text carries the credential"
    err = probe_err(c)
    assert is_code(err, Code.CREDENTIAL_REJECTED), f"probe: {err}"


def test_error_mapping(env: Env) -> None:
    _, f, c = env.setup()
    cases = [
        ("invalid_auth", Code.CREDENTIAL_REJECTED),
        ("not_authed", Code.CREDENTIAL_REJECTED),
        ("account_inactive", Code.CREDENTIAL_REJECTED),
        ("token_revoked", Code.CREDENTIAL_REJECTED),
        ("token_expired", Code.CREDENTIAL_REJECTED),
        ("missing_scope", Code.CREDENTIAL_REJECTED),
        ("ratelimited", Code.UPSTREAM_RATE_LIMIT),
        ("users_not_found", Code.USER_NOT_FOUND),
        ("internal_error", Code.UPSTREAM_ERROR),
        ("fatal_error", Code.UPSTREAM_ERROR),
    ]
    errors = []
    for code, want in cases:
        f.fail["users.lookupByEmail"] = code
        f.needed = "users:read.email"
        d = check(c, dana, "user.active", "workspace")
        if d.code != want:
            errors.append(f"{code} -> {d.code} ({d.text}), want {want}")
        if code == "missing_scope" and "users:read.email" not in d.text:
            errors.append(f"decision text {d.text!r} does not mention 'users:read.email'")
    assert not errors, "\n".join(errors)
    del f.fail["users.lookupByEmail"]

    # Errors on later calls map the same way.
    f.fail["conversations.info"] = "channel_not_found"
    itest.expect_code(check(c, dana, "channel.read", "channel:" + C_PUBLIC), Code.RESOURCE_NOT_VISIBLE)
    f.fail["conversations.info"] = "not_in_channel"
    d = check(c, dana, "channel.read", "channel:" + C_PUBLIC)
    itest.expect_code(d, Code.RESOURCE_NOT_VISIBLE)
    expect_text(d, "invite the bot")
    f.fail["conversations.info"] = "internal_error"
    itest.expect_code(check(c, dana, "channel.read", "channel:" + C_PUBLIC), Code.UPSTREAM_ERROR)
    del f.fail["conversations.info"]
    f.fail["users.conversations"] = "not_in_channel"
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_PUBLIC), Code.RESOURCE_NOT_VISIBLE)
    f.fail["users.conversations"] = "token_revoked"
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_PUBLIC), Code.CREDENTIAL_REJECTED)
    del f.fail["users.conversations"]
    f.fail["usergroups.list"] = "missing_scope"
    f.needed = "usergroups:read"
    d = check(c, dana, "usergroup.member", "usergroup:" + S_GROUP)
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)
    expect_text(d, "usergroups:read")


def test_not_visible_channel(env: Env) -> None:
    _, _, c = env.setup()
    for res in ("channel:" + G_HIDDEN, "channel:C0000NOSUCH", "channel:G0000NOSUCH"):
        d = check(c, dana, "channel.read", res)
        itest.expect_code(d, Code.RESOURCE_NOT_VISIBLE)
        expect_text(d, "invite the bot")


def test_stranger(env: Env) -> None:
    srv, _, c = env.setup()
    for a in ("channel.read", "channel.join", "message.post", "channel.invite"):
        itest.expect_code(check(c, stranger, a, "channel:" + C_PUBLIC), Code.UNSUPPORTED)
    assert count(methods(srv), "conversations.info") == 0, "channel looked up for an external user"
    # Workspace facts are still answered.
    itest.expect_code(check(c, stranger, "user.active", "workspace"), Code.ALLOWED)


def test_team_id(env: Env) -> None:
    srv, _, c = env.setup({"team_id": "T0000TEAM1"})
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_PUBLIC), Code.ALLOWED)
    itest.expect_code(check(c, dana, "usergroup.member", "usergroup:" + S_GROUP), Code.ALLOWED)
    c.probe(background())
    calls = srv.calls()
    assert len(calls) >= 6, f"only {len(calls)} calls"
    for cl in calls:
        assert cl.q("team_id") == "T0000TEAM1", f"{cl.path} sent without team_id: {cl.query}"
    for bad in ("acme", "t0123", "T0123?x=1"):
        with pytest.raises(ValueError):
            validate_team_id(bad)
    validate_team_id("E0000ENTRP")


def test_membership_pagination(env: Env) -> None:
    srv, f, c = env.setup()
    f.page_size = 1  # dana is in 6 visible channels; secret is the fifth: public, general, announcements, old, secret, plain
    f.order = [C_PUBLIC, C_GENERAL, C_RESTRICT, C_ARCHIVED, G_PRIVATE, C_NO_PROPS, G_HIDDEN]
    d = check(c, dana, "message.post", "channel:" + G_PRIVATE)
    itest.expect_code(d, Code.ALLOWED)
    ms = methods(srv)
    n = count(ms, "users.conversations")
    assert n == 5, f"users.conversations called {n} times, want 5 ({ms})"
    assert count(ms, "conversations.members") == 0, "fell back to conversations.members although the channel was on page 5"
    cursors = [cl.q("cursor") for cl in srv.calls() if cl.path.endswith("users.conversations")]
    assert ",".join(cursors) == ",1,2,3,4", f"cursors {cursors}"


def test_membership_fallback(env: Env) -> None:
    srv, f, c = env.setup()
    f.page_size = 1
    # Put dana in enough channels that the target is beyond page 5.
    for i in range(6):
        id = "C0000EXTRA" + str(i)
        f.channels[id] = FakeChannel(chan_obj(id, "extra" + str(i)), [U_FULL], True)
        f.order = [id, *f.order]
    f.member_ps = 2
    d = check(c, dana, "message.post", "channel:" + G_PRIVATE)
    itest.expect_code(d, Code.ALLOWED)
    ms = methods(srv)
    n = count(ms, "users.conversations")
    assert n == 5, f"users.conversations called {n} times, want 5"
    n = count(ms, "conversations.members")
    assert n == 1, f"conversations.members called {n} times, want 1 ({ms})"
    # Members pagination: a user on the second page.
    srv.reset()
    f.channels[G_PRIVATE].members = [U_ADMIN, U_OWNER, U_FULL]
    d = check(c, dana, "message.post", "channel:" + G_PRIVATE)
    itest.expect_code(d, Code.ALLOWED)
    n = count(methods(srv), "conversations.members")
    assert n == 2, f"conversations.members called {n} times, want 2"
    # Not a member after the whole fallback: deny.
    f.channels[G_PRIVATE].members = [U_ADMIN]
    d = check(c, dana, "message.post", "channel:" + G_PRIVATE)
    itest.expect_code(d, Code.DENIED)


def test_general_posting(env: Env) -> None:
    _, f, c = env.setup()
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_GENERAL), Code.DENIED)
    itest.expect_code(check(c, admin, "message.post", "channel:" + C_GENERAL), Code.ALLOWED)
    itest.expect_code(check(c, owner, "message.post", "channel:" + C_GENERAL), Code.ALLOWED)

    f.prefs["who_can_post_general"] = {"type": ["owner"], "user": [U_FULL]}
    itest.expect_code(check(c, admin, "message.post", "channel:" + C_GENERAL), Code.DENIED)
    itest.expect_code(check(c, owner, "message.post", "channel:" + C_GENERAL), Code.ALLOWED)
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_GENERAL), Code.ALLOWED)

    f.prefs["who_can_post_general"] = "admin"
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_GENERAL), Code.DENIED)
    f.prefs["who_can_post_general"] = "everyone"
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_GENERAL), Code.ALLOWED)
    f.prefs["who_can_post_general"] = "something_new"
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_GENERAL), Code.UNSUPPORTED)

    del f.prefs["who_can_post_general"]
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_GENERAL), Code.UNSUPPORTED)
    f.pref_scope = False
    d = check(c, dana, "message.post", "channel:" + C_GENERAL)
    itest.expect_code(d, Code.CREDENTIAL_REJECTED)
    expect_text(d, "team.preferences:read")

    # Non-general channels never read the preferences.
    srv, _, c = env.setup()
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_PUBLIC), Code.ALLOWED)
    assert count(methods(srv), "team.preferences.list") == 0, "team.preferences.list read for a non-general channel"


def test_assume_default_prefs(env: Env) -> None:
    _, f, c = env.setup({"assume_default_prefs": "true"})
    f.pref_scope = False
    d = check(c, dana, "message.post", "channel:" + C_GENERAL)
    itest.expect_code(d, Code.ALLOWED)
    f.pref_scope = True
    del f.prefs["who_can_post_general"]
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_GENERAL), Code.ALLOWED)
    f.prefs["who_can_post_general"] = {"type": ["admin"]}
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_GENERAL), Code.DENIED)

    d = check(c, dana, "channel.create", "workspace")
    itest.expect_code(d, Code.ALLOWED)
    expect_text(d, "default")
    itest.expect_code(check(c, guest, "channel.create", "workspace"), Code.DENIED)


def test_posting_restriction(env: Env) -> None:
    _, _, c = env.setup()
    d = check(c, dana, "message.post", "channel:" + C_RESTRICT)
    itest.expect_code(d, Code.DENIED)
    expect_text(d, "admins and owners")
    itest.expect_code(check(c, admin, "message.post", "channel:" + C_RESTRICT), Code.ALLOWED)
    # A named user may post even as a guest.
    itest.expect_code(check(c, ultra, "message.post", "channel:" + C_RESTRICT), Code.ALLOWED)
    itest.expect_code(check(c, guest, "message.post", "channel:" + C_RESTRICT), Code.DENIED)
    # Thread replies are not blocked by the restriction.
    d = check(c, dana, "message.post_thread", "channel:" + C_RESTRICT)
    itest.expect_code(d, Code.ALLOWED)
    expect_text(d, "thread replies")
    # An empty rule means everyone.
    d = check(c, dana, "message.post", "channel:" + C_PUBLIC)
    itest.expect_code(d, Code.ALLOWED)
    expect_text(d, "is a member of")


def test_posting_property_absent(env: Env) -> None:
    """An absent posting_restricted_to is not "unrestricted": whether a bot
    token sees the property is unverified, so the answer is unknown unless
    the connection opts in with assume_default_prefs."""
    _, f, c = env.setup()
    for a in ("message.post", "message.post_thread", "file.upload"):
        d = check(c, dana, a, "channel:" + C_NO_PROPS)
        itest.expect_code(d, Code.UNSUPPORTED)
        expect_text(d, "not visible to the bot")
        itest.expect_code(check(c, admin, a, "channel:" + C_NO_PROPS), Code.UNSUPPORTED)
    # A properties object without the posting_restricted_to key is absent too.
    f.channels[C_NO_PROPS].obj["properties"] = {"canvas": {"is_empty": True}}
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_NO_PROPS), Code.UNSUPPORTED)
    # Membership and archival are still decided first.
    itest.expect_code(check(c, ultra, "message.post", "channel:" + C_NO_PROPS), Code.DENIED)
    f.channels[C_NO_PROPS].obj["is_archived"] = True
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_NO_PROPS), Code.DENIED)

    _, _, c = env.setup({"assume_default_prefs": "true"})
    d = check(c, dana, "message.post", "channel:" + C_NO_PROPS)
    itest.expect_code(d, Code.ALLOWED)
    expect_text(d, "no posting restriction is visible to the bot")
    expect_text(d, "assume_default_prefs")
    itest.expect_code(check(c, guest, "message.post", "channel:" + C_NO_PROPS), Code.ALLOWED)
    # #general's own rule still applies before the channel property.
    _, f, c = env.setup({"assume_default_prefs": "true"})
    f.channels[C_GENERAL].obj["properties"] = None
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_GENERAL), Code.DENIED)
    itest.expect_code(check(c, admin, "message.post", "channel:" + C_GENERAL), Code.ALLOWED)


def test_unrecognised_poster_type(env: Env) -> None:
    """A posting rule naming a poster type hallpass does not model cannot be
    evaluated: unknown, not deny."""
    _, f, c = env.setup()
    f.prefs["who_can_post_general"] = {"type": ["something_new"], "user": []}
    d = check(c, dana, "message.post", "channel:" + C_GENERAL)
    itest.expect_code(d, Code.UNSUPPORTED)
    expect_text(d, "something_new")
    itest.expect_code(check(c, admin, "message.post", "channel:" + C_GENERAL), Code.UNSUPPORTED)
    # A recognised match still wins.
    f.prefs["who_can_post_general"] = {"type": ["admin", "something_new"], "user": [U_GUEST]}
    itest.expect_code(check(c, admin, "message.post", "channel:" + C_GENERAL), Code.ALLOWED)
    itest.expect_code(check(c, guest, "message.post", "channel:" + C_GENERAL), Code.ALLOWED)
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_GENERAL), Code.UNSUPPORTED)

    f.channels[C_RESTRICT].obj["properties"] = {"posting_restricted_to": {"type": ["something_new"], "user": [U_ULTRA]}}
    d = check(c, dana, "message.post", "channel:" + C_RESTRICT)
    itest.expect_code(d, Code.UNSUPPORTED)
    expect_text(d, "something_new")
    itest.expect_code(check(c, dana, "file.upload", "channel:" + C_RESTRICT), Code.UNSUPPORTED)
    # Admins bypass the channel restriction, named users match, threads are
    # not limited by it.
    itest.expect_code(check(c, admin, "message.post", "channel:" + C_RESTRICT), Code.ALLOWED)
    itest.expect_code(check(c, ultra, "message.post", "channel:" + C_RESTRICT), Code.ALLOWED)
    itest.expect_code(check(c, dana, "message.post_thread", "channel:" + C_RESTRICT), Code.ALLOWED)
    # A recognised type that positively excludes the user is still a deny.
    f.channels[C_RESTRICT].obj["properties"] = {"posting_restricted_to": {"type": ["owner"], "user": []}}
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_RESTRICT), Code.DENIED)


def test_channel_actions_need_membership(env: Env) -> None:
    """Invite, rename and archive act from inside the channel: membership first."""
    srv, f, c = env.setup()
    for a in ("channel.invite", "channel.rename", "channel.archive"):
        # Admins and owners who are not members of a private channel.
        for u in (admin, owner):
            d = check(c, u, a, "channel:" + G_PRIVATE)
            itest.expect_code(d, Code.DENIED)
            expect_text(d, "not a member")
        # A full member of the private channel: the preference gate as usual.
        d = check(c, dana, a, "channel:" + G_PRIVATE)
        itest.expect_code(d, Code.UNSUPPORTED)
        expect_text(d, "not readable by a bot token")
        # A guest member of the private channel is refused by the gate.
        itest.expect_code(check(c, guest, a, "channel:" + G_PRIVATE), Code.DENIED)
    assert count(methods(srv), "users.conversations") != 0, "membership never read"
    # An admin member of a private channel is allowed.
    f.channels[G_PRIVATE].members.append(U_ADMIN)
    for a in ("channel.invite", "channel.rename", "channel.archive"):
        itest.expect_code(check(c, admin, a, "channel:" + G_PRIVATE), Code.ALLOWED)
    # Public channel, not a member: joining first is possible, so unknown
    # for admins and full members, deny for guests.
    f.channels[C_PUBLIC].members = [U_OWNER]
    for a in ("channel.invite", "channel.rename", "channel.archive"):
        for u in (admin, dana):
            d = check(c, u, a, "channel:" + C_PUBLIC)
            itest.expect_code(d, Code.UNSUPPORTED)
            expect_text(d, "not a member")
            expect_text(d, "joining first is possible")
        for u in (guest, ultra):
            d = check(c, u, a, "channel:" + C_PUBLIC)
            itest.expect_code(d, Code.DENIED)
            expect_text(d, "not a member")
        itest.expect_code(check(c, owner, a, "channel:" + C_PUBLIC), Code.ALLOWED)
    # assume_default_prefs does not turn a non-member into an allow.
    _, f, c = env.setup({"assume_default_prefs": "true"})
    f.channels[C_PUBLIC].members = [U_OWNER]
    itest.expect_code(check(c, dana, "channel.invite", "channel:" + C_PUBLIC), Code.UNSUPPORTED)
    itest.expect_code(check(c, admin, "channel.archive", "channel:" + G_PRIVATE), Code.DENIED)
    itest.expect_code(check(c, dana, "channel.rename", "channel:" + G_PRIVATE), Code.ALLOWED)
    # Archived and #general answers come before the membership read.
    srv, _, c = env.setup()
    itest.expect_code(check(c, admin, "channel.archive", "channel:" + C_GENERAL), Code.DENIED)
    itest.expect_code(check(c, admin, "channel.invite", "channel:" + C_ARCHIVED), Code.DENIED)
    assert count(methods(srv), "users.conversations") == 0, "membership read for an answer that does not depend on it"


def test_grid_team_mismatch(env: Env) -> None:
    """On an Enterprise Grid org-level install the user object may belong to
    another workspace of the organization; "any full member of this
    workspace" is then not established."""
    _, f, c = env.setup({"team_id": "T0000OTHR1"})
    for a in ("channel.read", "channel.join"):
        d = check(c, dana, a, "channel:" + C_PUBLIC)
        itest.expect_code(d, Code.UNSUPPORTED)
        expect_text(d, "another workspace of the organization")
        itest.expect_code(check(c, admin, a, "channel:" + C_PUBLIC), Code.UNSUPPORTED)
    # Positive facts still decide: membership of a private channel, guests.
    itest.expect_code(check(c, dana, "channel.read", "channel:" + G_PRIVATE), Code.ALLOWED)
    itest.expect_code(check(c, admin, "channel.read", "channel:" + G_PRIVATE), Code.DENIED)
    itest.expect_code(check(c, ultra, "channel.read", "channel:" + C_PUBLIC), Code.ALLOWED)
    itest.expect_code(check(c, guest, "channel.join", "channel:" + C_PUBLIC), Code.DENIED)
    itest.expect_code(check(c, dana, "channel.join", "channel:" + C_ARCHIVED), Code.DENIED)
    # A user object without team_id cannot be compared.
    del f.users["dana@example.com"]["team_id"]
    itest.expect_code(check(c, dana, "channel.read", "channel:" + C_PUBLIC), Code.ALLOWED)

    # The same workspace, or no team_id on the connection: allowed as before.
    _, _, c = env.setup({"team_id": "T0000TEAM1"})
    itest.expect_code(check(c, dana, "channel.read", "channel:" + C_PUBLIC), Code.ALLOWED)
    itest.expect_code(check(c, dana, "channel.join", "channel:" + C_PUBLIC), Code.ALLOWED)
    _, f, c = env.setup()
    f.users["dana@example.com"]["team_id"] = "T0000OTHR1"
    itest.expect_code(check(c, dana, "channel.read", "channel:" + C_PUBLIC), Code.ALLOWED)


def test_read_and_join_rules(env: Env) -> None:
    srv, _, c = env.setup()
    # Public channel, full member: no membership call.
    itest.expect_code(check(c, dana, "channel.read", "channel:" + C_PUBLIC), Code.ALLOWED)
    itest.expect_code(check(c, dana, "channel.join", "channel:" + C_PUBLIC), Code.ALLOWED)
    assert count(methods(srv), "users.conversations") == 0, "membership read for a full member on a public channel"
    # Guests need membership.
    itest.expect_code(check(c, ultra, "channel.read", "channel:" + C_PUBLIC), Code.ALLOWED)
    itest.expect_code(check(c, guest, "channel.read", "channel:" + C_PUBLIC), Code.DENIED)
    itest.expect_code(check(c, ultra, "channel.join", "channel:" + C_PUBLIC), Code.ALLOWED)
    itest.expect_code(check(c, guest, "channel.join", "channel:" + C_PUBLIC), Code.DENIED)
    # Private: membership decides.
    itest.expect_code(check(c, dana, "channel.read", "channel:" + G_PRIVATE), Code.ALLOWED)
    itest.expect_code(check(c, admin, "channel.read", "channel:" + G_PRIVATE), Code.DENIED)
    d = check(c, dana, "channel.join", "channel:" + G_PRIVATE)
    itest.expect_code(d, Code.ALLOWED)
    expect_text(d, "already a member")
    itest.expect_code(check(c, admin, "channel.join", "channel:" + G_PRIVATE), Code.DENIED)
    # Archived: readable, not joinable, not postable.
    d = check(c, dana, "channel.read", "channel:" + C_ARCHIVED)
    itest.expect_code(d, Code.ALLOWED)
    expect_text(d, "archived")
    itest.expect_code(check(c, dana, "channel.join", "channel:" + C_ARCHIVED), Code.DENIED)
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_ARCHIVED), Code.DENIED)
    itest.expect_code(check(c, dana, "file.upload", "channel:" + C_ARCHIVED), Code.DENIED)
    itest.expect_code(check(c, admin, "channel.rename", "channel:" + C_ARCHIVED), Code.DENIED)
    itest.expect_code(check(c, admin, "channel.invite", "channel:" + C_ARCHIVED), Code.DENIED)
    itest.expect_code(check(c, admin, "channel.archive", "channel:" + C_ARCHIVED), Code.DENIED)
    itest.expect_code(check(c, admin, "channel.archive", "channel:" + C_GENERAL), Code.DENIED)
    # Not a member of a public channel: post denied, join possible.
    d = check(c, guest, "message.post", "channel:" + C_PUBLIC)
    itest.expect_code(d, Code.DENIED)
    _, f2, c2 = env.setup()
    f2.channels[C_PUBLIC].members = [U_ADMIN]
    d = check(c2, dana, "message.post", "channel:" + C_PUBLIC)
    itest.expect_code(d, Code.DENIED)
    expect_text(d, "joining is possible")


def test_pref_gate(env: Env) -> None:
    _, _, c = env.setup()
    for action, resource in (
        ("channel.invite", "channel:" + C_PUBLIC),
        ("channel.create", "workspace"),
        ("channel.archive", "channel:" + C_PUBLIC),
        ("channel.rename", "channel:" + C_PUBLIC),
    ):
        d = check(c, dana, action, resource)
        itest.expect_code(d, Code.UNSUPPORTED)
        expect_text(d, "not readable by a bot token")
        itest.expect_code(check(c, guest, action, resource), Code.DENIED)
        itest.expect_code(check(c, ultra, action, resource), Code.DENIED)
        itest.expect_code(check(c, admin, action, resource), Code.ALLOWED)
        itest.expect_code(check(c, owner, action, resource), Code.ALLOWED)
    # Channel-scoped ones still need a visible channel.
    itest.expect_code(check(c, admin, "channel.rename", "channel:" + G_HIDDEN), Code.RESOURCE_NOT_VISIBLE)


def test_usergroups(env: Env) -> None:
    srv, _, c = env.setup()
    d = check(c, dana, "usergroup.member", "usergroup:" + S_GROUP)
    itest.expect_code(d, Code.ALLOWED)
    expect_text(d, "@oncall")
    last = srv.last_call()
    assert last.path == "/api/usergroups.list" and last.q("include_users") == "true", f"usergroups.list call {last.path} {last.query}"
    itest.expect_code(check(c, guest, "usergroup.member", "usergroup:" + S_GROUP), Code.DENIED)
    itest.expect_code(check(c, dana, "usergroup.member", "usergroup:S0000NOSUCH"), Code.RESOURCE_NOT_VISIBLE)


def test_org_admin(env: Env) -> None:
    _, _, c = env.setup()
    d = check(c, dana, "org.admin", "workspace")
    itest.expect_code(d, Code.UNSUPPORTED)
    expect_text(d, "Enterprise Grid")
    itest.expect_code(check(c, grid_adm, "org.admin", "workspace"), Code.ALLOWED)
    itest.expect_code(check(c, grid_user, "org.admin", "workspace"), Code.DENIED)
    itest.expect_code(check(c, admin, "org.admin", "workspace"), Code.UNSUPPORTED)


def test_bad_resources(env: Env) -> None:
    _, _, c = env.setup()
    cases = [
        ("channel.read", "workspace"),
        ("channel.read", "channel:general"),
        ("channel.read", "channel:C0000PUBLC?x=1"),
        ("channel.read", "channel:c0000publc"),
        ("channel.read", "channel:D0000DMDM1"),
        ("channel.read", "channel:"),
        ("user.active", "workspace:acme"),
        ("user.active", "channel:" + C_PUBLIC),
        ("usergroup.member", "usergroup:oncall"),
        ("usergroup.member", "usergroup:" + C_PUBLIC),
        ("channel.create", "channel:" + C_PUBLIC),
    ]
    errors = []
    for action, resource in cases:
        d = check(c, dana, action, resource)
        if d.code != Code.INVALID_REQUEST:
            errors.append(f"{action} {resource} -> {d.code}: {d.text}")
    assert not errors, "\n".join(errors)
    assert find_action(INTEGRATION, "raw:x") is None, "pattern action accepted"
    validate_fields(INTEGRATION.fields())


def must_res(s: str) -> Resource:
    return parse_resource(s)


def test_failures(env: Env) -> None:
    srv, _, c = env.setup()
    itest.failure_cases(srv, lambda: check(c, dana, "message.post", "channel:" + C_PUBLIC))
    # A failure after identity resolution maps the same way.
    ident = c.resolve_identity(background(), dana)

    def direct() -> Decision:
        act = find_action(INTEGRATION, "channel.read")
        assert act is not None
        try:
            return c.check(
                background(),
                CheckRequest(user=dana, identity=ident, action=act, action_name="channel.read", resource=must_res("channel:" + G_PRIVATE)),
            )
        except Exception as e:  # Go: ToDecision(err)
            return to_decision(e)

    itest.failure_cases(srv, direct)


def test_probe(env: Env) -> None:
    _, f, c = env.setup()
    r = c.probe(background())
    assert "U0000HALLP" in r.summary and "Acme" in r.summary and "B0000HALLP" in r.summary and "channel properties visible" in r.summary, (
        f"summary {r.summary!r}"
    )
    assert len(r.warnings) == 0, f"warnings {r.warnings}"

    f.scopes_hdr = "users:read,users:read.email,channels:read,groups:read,chat:write,channels:manage,admin.users:read"
    r = c.probe(background())
    assert len(r.warnings) == 1 and "chat:write" in r.warnings[0] and "channels:manage" in r.warnings[0] and "admin.users:read" in r.warnings[0], (
        f"write scope warnings {r.warnings}"
    )
    f.scopes_hdr = "users:read,channels:read"
    r = c.probe(background())
    assert len(r.warnings) == 1 and "users:read.email" in r.warnings[0] and "groups:read" in r.warnings[0], f"missing scope warnings {r.warnings}"
    f.scopes_hdr = ""

    f.pref_scope, f.ug_scope = False, False
    r = c.probe(background())
    assert len(r.warnings) == 2 and "team.preferences:read" in r.warnings[0] and "usergroups:read" in r.warnings[1], f"optional scope warnings {r.warnings}"
    f.pref_scope, f.ug_scope = True, True

    f.fail["users.lookupByEmail"] = "missing_scope"
    f.needed = "users:read.email"
    r = c.probe(background())
    assert len(r.warnings) == 1 and "users:read.email" in r.warnings[0], f"lookup scope: {r.warnings}"
    del f.fail["users.lookupByEmail"]

    f.fail["auth.test"] = "invalid_auth"
    err = probe_err(c)
    assert err is not None and is_code(err, Code.CREDENTIAL_REJECTED), f"auth.test invalid_auth: {err}"
    del f.fail["auth.test"]
    f.fail["usergroups.list"] = "internal_error"
    err = probe_err(c)
    assert err is not None and is_code(err, Code.UPSTREAM_ERROR), f"usergroups internal_error: {err}"


def test_probe_channel_properties(env: Env) -> None:
    """The probe reads #general to report whether channel properties are visible."""
    srv, f, c = env.setup()
    f.list_ps = 1  # #general is the second public channel listed
    r = c.probe(background())
    assert "channel properties visible" in r.summary and len(r.warnings) == 0, f"summary {r.summary!r} warnings {r.warnings}"
    ms = methods(srv)
    n = count(ms, "conversations.list")
    assert n == 2, f"conversations.list called {n} times, want 2 ({ms})"
    infos = []
    for cl in srv.calls():
        if cl.path.endswith("conversations.list"):
            assert cl.q("types") == "public_channel" and cl.q("exclude_archived") == "true" and cl.q("limit") == "200", f"conversations.list query {cl.query}"
        if cl.path.endswith("conversations.info"):
            infos.append(cl.q("channel"))
    assert ",".join(infos) == C_GENERAL, f"conversations.info called for {infos}, want only #general"

    # No properties object on #general: warn.
    f.channels[C_GENERAL].obj["properties"] = None
    r = c.probe(background())
    assert "channel properties visible" not in r.summary, f"summary {r.summary!r}"
    assert len(r.warnings) == 1 and "no properties object" in r.warnings[0] and "assume_default_prefs" in r.warnings[0], f"warnings {r.warnings}"
    # #general not listed: warn, without a conversations.info call.
    f.channels[C_GENERAL].obj["is_general"] = False
    srv.reset()
    r = c.probe(background())
    assert len(r.warnings) == 1 and "#general was not found" in r.warnings[0], f"warnings {r.warnings}"
    assert count(methods(srv), "conversations.info") == 0, "conversations.info called without #general"
    # Failures of the listing are the probe's failures.
    f.fail["conversations.list"] = "missing_scope"
    f.needed = "channels:read"
    err = probe_err(c)
    assert err is not None and is_code(err, Code.CREDENTIAL_REJECTED), f"conversations.list missing_scope: {err}"


@dataclass
class PostersCase:
    raw: str
    full: bool = False
    adm: bool = False
    own: bool = False
    nil_p: bool = False
    err: bool = False
    unknown: str = ""  # reported for whoever is not allowed


POSTERS_CASES = [
    PostersCase(raw="", nil_p=True),
    PostersCase(raw="null", nil_p=True),
    PostersCase(raw="{}", full=True, adm=True, own=True),
    PostersCase(raw='{"type":[],"user":[]}', full=True, adm=True, own=True),
    PostersCase(raw='{"type":["admin"],"user":[]}', adm=True, own=True),
    PostersCase(raw='{"type":["owner"],"user":["' + U_FULL + '"]}', full=True, own=True),
    PostersCase(raw='{"type":["weird"],"user":[]}', unknown="weird"),
    PostersCase(raw='{"type":["admin","weird"],"user":["' + U_FULL + '"]}', full=True, adm=True, own=True),
    PostersCase(raw='{"type":["weird","owner"],"user":[]}', own=True, unknown="weird"),
    PostersCase(raw='"everyone"', full=True, adm=True, own=True),
    PostersCase(raw='"admin"', adm=True, own=True),
    PostersCase(raw='"owner"', own=True),
    PostersCase(raw='"weird"', err=True),
    PostersCase(raw="42", err=True),
]


@pytest.mark.parametrize("cs", POSTERS_CASES, ids=[c.raw or "empty" for c in POSTERS_CASES])
def test_posters_parsing(cs: PostersCase) -> None:
    full = Identity(id=U_FULL)
    adm = Identity(id=U_ADMIN, attrs={ATTR_ADMIN: "true"})
    own = Identity(id=U_OWNER, attrs={ATTR_ADMIN: "true", ATTR_OWNER: "true"})
    if cs.err:
        with pytest.raises(ValueError):
            parse_posters(cs.raw)
        return
    p = parse_posters(cs.raw)
    if cs.nil_p:
        assert p is None, f"{cs.raw}: expected None"
        return
    assert p is not None
    for ident, want in ((full, cs.full), (adm, cs.adm), (own, cs.own)):
        ok, unknown = posters_allows(p, ident)
        assert ok == want, f"{cs.raw}: {ident.id} allowed={ok}, want {want}"
        want_unknown = "" if ok else cs.unknown
        assert unknown == want_unknown, f"{cs.raw}: {ident.id} unknown={unknown!r}, want {want_unknown!r}"


# Allow/deny tests per action (coverage gate).


def test_action_user_active_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "user.active", "workspace"), Code.ALLOWED)
    itest.expect_code(check(c, guest, "user.active", "workspace"), Code.ALLOWED)


def test_action_user_active_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dead, "user.active", "workspace"), Code.DENIED)


def test_action_workspace_admin_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, admin, "workspace.admin", "workspace"), Code.ALLOWED)
    itest.expect_code(check(c, owner, "workspace.admin", "workspace"), Code.ALLOWED)


def test_action_workspace_admin_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "workspace.admin", "workspace"), Code.DENIED)
    itest.expect_code(check(c, dead, "workspace.admin", "workspace"), Code.DENIED)


def test_action_org_admin_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, grid_adm, "org.admin", "workspace"), Code.ALLOWED)


def test_action_org_admin_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, grid_user, "org.admin", "workspace"), Code.DENIED)


def test_action_channel_read_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "channel.read", "channel:" + C_PUBLIC), Code.ALLOWED)
    itest.expect_code(check(c, dana, "channel.read", "channel:" + G_PRIVATE), Code.ALLOWED)


def test_action_channel_read_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, admin, "channel.read", "channel:" + G_PRIVATE), Code.DENIED)
    itest.expect_code(check(c, guest, "channel.read", "channel:" + C_PUBLIC), Code.DENIED)


def test_action_channel_join_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "channel.join", "channel:" + C_PUBLIC), Code.ALLOWED)


def test_action_channel_join_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, guest, "channel.join", "channel:" + C_PUBLIC), Code.DENIED)
    itest.expect_code(check(c, admin, "channel.join", "channel:" + G_PRIVATE), Code.DENIED)
    itest.expect_code(check(c, dana, "channel.join", "channel:" + C_ARCHIVED), Code.DENIED)


def test_action_message_post_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_PUBLIC), Code.ALLOWED)
    itest.expect_code(check(c, admin, "message.post", "channel:" + C_GENERAL), Code.ALLOWED)


def test_action_message_post_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, guest, "message.post", "channel:" + C_PUBLIC), Code.DENIED)
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_GENERAL), Code.DENIED)
    itest.expect_code(check(c, dana, "message.post", "channel:" + C_RESTRICT), Code.DENIED)


def test_action_message_post_thread_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "message.post_thread", "channel:" + C_PUBLIC), Code.ALLOWED)
    itest.expect_code(check(c, dana, "message.post_thread", "channel:" + C_RESTRICT), Code.ALLOWED)


def test_action_message_post_thread_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, guest, "message.post_thread", "channel:" + C_PUBLIC), Code.DENIED)
    itest.expect_code(check(c, dana, "message.post_thread", "channel:" + C_ARCHIVED), Code.DENIED)
    itest.expect_code(check(c, dana, "message.post_thread", "channel:" + C_GENERAL), Code.DENIED)


def test_action_file_upload_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "file.upload", "channel:" + C_PUBLIC), Code.ALLOWED)


def test_action_file_upload_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, guest, "file.upload", "channel:" + C_PUBLIC), Code.DENIED)
    itest.expect_code(check(c, dana, "file.upload", "channel:" + C_RESTRICT), Code.DENIED)


def test_action_usergroup_member_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, dana, "usergroup.member", "usergroup:" + S_GROUP), Code.ALLOWED)


def test_action_usergroup_member_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, guest, "usergroup.member", "usergroup:" + S_GROUP), Code.DENIED)


def test_action_channel_invite_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, admin, "channel.invite", "channel:" + C_PUBLIC), Code.ALLOWED)


def test_action_channel_invite_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, guest, "channel.invite", "channel:" + C_PUBLIC), Code.DENIED)
    itest.expect_code(check(c, admin, "channel.invite", "channel:" + G_PRIVATE), Code.DENIED)


def test_action_channel_create_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, admin, "channel.create", "workspace"), Code.ALLOWED)


def test_action_channel_create_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, guest, "channel.create", "workspace"), Code.DENIED)


def test_action_channel_archive_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, admin, "channel.archive", "channel:" + C_PUBLIC), Code.ALLOWED)


def test_action_channel_archive_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, guest, "channel.archive", "channel:" + C_PUBLIC), Code.DENIED)
    itest.expect_code(check(c, admin, "channel.archive", "channel:" + G_PRIVATE), Code.DENIED)


def test_action_channel_rename_allow(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, admin, "channel.rename", "channel:" + C_PUBLIC), Code.ALLOWED)


def test_action_channel_rename_deny(env: Env) -> None:
    _, _, c = env.setup()
    itest.expect_code(check(c, guest, "channel.rename", "channel:" + C_PUBLIC), Code.DENIED)
    itest.expect_code(check(c, admin, "channel.rename", "channel:" + G_PRIVATE), Code.DENIED)
