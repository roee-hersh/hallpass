"""Port of internal/integrations/zendesk/zendesk_test.go."""

from __future__ import annotations

import base64
import binascii
import json
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from hallpass.core.context import background
from hallpass.core.decision import Code, Decision, HallpassError
from hallpass.core.errors import as_error
from hallpass.core.integration import Connection, User
from hallpass.core.secret import Secret, literal
from hallpass.integrations.zendesk import Zendesk, ZendeskConnection
from hallpass.integrations.zendesk.zendesk import AUTH_OAUTH, AUTH_TOKEN, ROLE_ADMIN, ROLE_AGENT, ROLE_END_USER
from hallpass.net import httpx
from tests import harness as itest
from tests.harness.spec import SpecOptions, spec_from_env

# Users. Ids are Zendesk-style integers.
BOT_ID = 1
ADMIN_ID = 10
DANA_ID = 11  # custom role "Tier 1": within-groups, edits, public comments, no delete
BOB_ID = 12  # custom role "Reader": assigned-only, read only, private comments
LITE_ID = 13  # light agent, no custom role
SARA_ID = 14  # plain agent, ticket_restriction groups (non-Enterprise style)
ORG_AGENT = 15  # custom role "Org": within-organization, edit-within-org profiles
END_ID = 20  # end user
END2_ID = 21  # end user in org 500
GONE_ID = 22  # deleted
SUSP_ID = 23  # suspended

ROLE_TIER1 = 100
ROLE_READER = 101
ROLE_ORG = 102

GROUP_A = 300
GROUP_B = 301
GROUP_PU = 302  # public
ORG500 = 500

admin = User(email="admin@example.com")
dana = User(email="dana@example.com")
bob = User(email="bob@example.com")
lite = User(email="lite@example.com")
sara = User(email="sara@example.com")
org_ag = User(email="orgagent@example.com")
end_usr = User(email="end@example.com")
end2 = User(email="end2@example.com")


@dataclass
class FakeUser:
    id: int
    email: str
    role: str
    role_type: int | None = None
    custom_role: int | None = None
    active: bool = False
    suspended: bool = False
    ticket_restriction: str | None = None
    only_private_comments: bool | None = None
    org_id: int | None = None
    groups: list[int] = field(default_factory=list)
    identities: list[str] = field(default_factory=list)  # secondary email identities


@dataclass
class FakeTicket:
    status: str
    group: int | None = None
    assignee: int | None = None
    requester: int | None = None
    org_id: int | None = None
    collaborators: list[int] | None = None


def _cfg(kv: dict[str, Any]) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ticket_access": "all",
        "ticket_editing": True,
        "ticket_deletion": False,
        "ticket_merge": False,
        "ticket_comment_access": "public",
        "modify_closed_tickets": False,
        "macro_access": "readonly",
        "view_access": "readonly",
        "organization_editing": False,
        "end_user_profile_access": "readonly",
        "manage_business_rules": False,
        "light_agent": False,
        "chat_access": False,
        "voice_access": False,
        "explore_access": "none",
        "report_access": "none",
        "forum_access": "readonly",
        "group_access": False,
    }
    base.update(kv)
    return base


def _parse_int(s: str) -> int | None:
    """Go's strconv.ParseInt(s, 10, 64)."""
    t = s[1:] if s[:1] in "+-" else s
    if not t or not all("0" <= c <= "9" for c in t):
        return None
    n = int(s)
    return n if -(1 << 63) <= n < (1 << 63) else None


class Fake:
    def __init__(self) -> None:
        self.mu = threading.Lock()
        self.errors: list[str] = []
        self.token = itest.CANARY + "tok"
        self.per_page = 100
        self.status = 0
        self.roles_got = 0
        self.users = [
            FakeUser(BOT_ID, "bot@example.com", ROLE_ADMIN, active=True),
            FakeUser(ADMIN_ID, "admin@example.com", ROLE_ADMIN, active=True, groups=[GROUP_A]),
            FakeUser(DANA_ID, "dana@example.com", ROLE_AGENT, role_type=0, custom_role=ROLE_TIER1, active=True, groups=[GROUP_A], org_id=ORG500),
            FakeUser(BOB_ID, "bob@example.com", ROLE_AGENT, role_type=0, custom_role=ROLE_READER, active=True, groups=[GROUP_B]),
            FakeUser(LITE_ID, "lite@example.com", ROLE_AGENT, role_type=1, active=True, only_private_comments=True, groups=[GROUP_A]),
            FakeUser(SARA_ID, "sara@example.com", ROLE_AGENT, active=True, ticket_restriction="groups", only_private_comments=False, groups=[GROUP_B]),
            FakeUser(ORG_AGENT, "orgagent@example.com", ROLE_AGENT, role_type=0, custom_role=ROLE_ORG, active=True, org_id=ORG500),
            FakeUser(END_ID, "end@example.com", ROLE_END_USER, active=True, ticket_restriction="requested"),
            FakeUser(END2_ID, "end2@example.com", ROLE_END_USER, active=True, ticket_restriction="requested", org_id=ORG500),
            FakeUser(GONE_ID, "gone@example.com", ROLE_AGENT, active=False),
            FakeUser(SUSP_ID, "susp@example.com", ROLE_AGENT, active=True, suspended=True),
            # Matches an email: search loosely; must not count.
            FakeUser(99, "dana@example.com.au", ROLE_ADMIN, active=True),
            # Found through a secondary identity.
            FakeUser(30, "alice@corp.example", ROLE_ADMIN, active=True, identities=["alice@example.com"]),
        ]
        self.roles: dict[int, dict[str, Any]] = {
            ROLE_TIER1: _cfg(
                {
                    "ticket_access": "within-groups",
                    "ticket_merge": True,
                    "macro_access": "manage-personal",
                    "view_access": "full",
                    "end_user_profile_access": "full",
                }
            ),
            ROLE_READER: _cfg({"ticket_access": "assigned-only", "ticket_editing": False, "ticket_comment_access": "none"}),
            ROLE_ORG: _cfg(
                {
                    "ticket_access": "within-organization",
                    "organization_editing": True,
                    "end_user_profile_access": "edit-within-org",
                    "manage_business_rules": True,
                }
            ),
        }
        self.tickets: dict[int, FakeTicket] = {
            1: FakeTicket("open", group=GROUP_A, assignee=ADMIN_ID, requester=END_ID),
            2: FakeTicket("open", group=GROUP_B, assignee=BOB_ID, requester=END2_ID, org_id=ORG500),
            3: FakeTicket("closed", group=GROUP_A, requester=END_ID),
            4: FakeTicket("open", group=GROUP_PU, requester=END2_ID, org_id=ORG500, collaborators=[END_ID]),
            5: FakeTicket("open", requester=LITE_ID),
            6: FakeTicket("open", group=GROUP_B, requester=END_ID),
        }
        self.orgs = {ORG500: True}
        # id -> is_public
        self.groups = {GROUP_A: False, GROUP_B: False, GROUP_PU: True}

    def user_json(self, u: FakeUser) -> dict[str, Any]:
        m: dict[str, Any] = {
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "active": u.active,
            "suspended": u.suspended,
            "name": itest.CANARY + " name",
            "notes": itest.CANARY,
            "url": f"https://example.zendesk.com/api/v2/users/{u.id}.json",
        }
        m["role_type"] = u.role_type
        if u.custom_role is not None:
            m["custom_role_id"] = u.custom_role
        m["ticket_restriction"] = u.ticket_restriction
        if u.only_private_comments is not None:
            m["only_private_comments"] = u.only_private_comments
        if u.org_id is not None:
            m["organization_id"] = u.org_id
        return m

    def authed(self, r: itest.Request) -> bool:
        h = r.header.get("Authorization")
        if h.startswith("Bearer "):
            return h.removeprefix("Bearer ") == self.token
        try:
            raw = base64.b64decode(h.removeprefix("Basic "), validate=True)
        except (binascii.Error, ValueError):
            return False
        return raw == ("bot@example.com/token:" + self.token).encode()

    def api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        with self.mu:
            self._api(w, r)

    def _api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        if not self.authed(r):
            w.write_header(401)
            w.write('{"error":"Couldn\'t authenticate you"}')
            return
        if self.status != 0:
            zd_err(w, self.status)
            return
        p = r.path

        def seg(prefix: str) -> int | None:
            rest = p.removeprefix(prefix)
            return _parse_int(rest.split("/", 1)[0])

        if p == "/api/v2/users/me":
            write(w, {"user": self.user_json(self.users[0])})
        elif p == "/api/v2/users/search":
            query = r.q("query")
            if not query.startswith("email:"):
                self.errors.append(f"search without an email clause: {query!r}")
            needle = query.removeprefix("email:")
            users = []
            for u in self.users:
                if needle in u.email:
                    users.append(self.user_json(u))
                    continue
                for alt in u.identities:
                    if alt == needle:
                        users.append(self.user_json(u))
            if needle == "dup@example.com":
                users += [
                    self.user_json(FakeUser(501, "dup@example.com", ROLE_AGENT, active=True)),
                    self.user_json(FakeUser(502, "DUP@example.com", ROLE_AGENT, active=True)),
                ]
            write(w, {"users": users, "count": len(users), "next_page": None, "previous_page": None})
        elif p.startswith("/api/v2/users/") and p.endswith("/identities"):
            uid = seg("/api/v2/users/") or 0
            ids: list[dict[str, Any]] = []
            for u in self.users:
                if u.id != uid:
                    continue
                ids.append({"id": uid * 100, "user_id": uid, "type": "email", "value": u.email, "primary": True, "verified": True})
                for i, alt in enumerate(u.identities):
                    ids.append({"id": uid * 100 + i + 1, "user_id": uid, "type": "email", "value": alt, "primary": False, "verified": True})
                ids.append({"id": uid * 100 + 50, "user_id": uid, "type": "phone_number", "value": itest.CANARY, "primary": False})
            write(w, {"identities": ids, "next_page": None, "previous_page": None, "count": len(ids)})
        elif p.startswith("/api/v2/users/") and p.endswith("/group_memberships"):
            uid = seg("/api/v2/users/") or 0
            all_: list[dict[str, Any]] = []
            for u in self.users:
                if u.id != uid:
                    continue
                for i, g in enumerate(u.groups):
                    all_.append({"id": uid * 10 + i, "user_id": uid, "group_id": g, "default": i == 0, "url": itest.CANARY})
            page = _parse_int(r.q("page")) or 0
            if page < 1:
                page = 1
            start = min((page - 1) * self.per_page, len(all_))
            end = min(start + self.per_page, len(all_))
            nxt = None
            if end < len(all_):
                nxt = f"https://{r.host}/api/v2/users/{uid}/group_memberships?page={page + 1}"
            write(w, {"group_memberships": all_[start:end], "next_page": nxt, "previous_page": None, "count": len(all_)})
        elif p.startswith("/api/v2/users/"):
            uid2 = seg("/api/v2/users/")
            for u in self.users:
                if uid2 is not None and u.id == uid2:
                    write(w, {"user": self.user_json(u)})
                    return
            zd_err(w, 404)
        elif p == "/api/v2/custom_roles":
            self.roles_got += 1
            roles = [
                {"id": rid, "name": f"role-{rid}", "description": itest.CANARY, "role_type": 0, "team_member_count": 1, "configuration": cfg}
                for rid, cfg in self.roles.items()
            ]
            write(w, {"custom_roles": roles or None})
        elif p.startswith("/api/v2/tickets/"):
            tid = seg("/api/v2/tickets/")
            tk = self.tickets.get(tid) if tid is not None else None
            if tk is None:
                zd_err(w, 404)
                return
            if tid == 7:
                zd_err(w, 403)
                return
            m = {
                "id": tid,
                "status": tk.status,
                "subject": itest.CANARY,
                "description": itest.CANARY,
                "group_id": tk.group,
                "assignee_id": tk.assignee,
                "requester_id": tk.requester,
                "organization_id": tk.org_id,
                "collaborator_ids": tk.collaborators,
            }
            write(w, {"ticket": m})
        elif p.startswith("/api/v2/organizations/"):
            oid = seg("/api/v2/organizations/")
            if oid is None or not self.orgs.get(oid):
                zd_err(w, 404)
                return
            write(w, {"organization": {"id": oid, "name": itest.CANARY, "notes": itest.CANARY}})
        elif p.startswith("/api/v2/groups/"):
            gid = seg("/api/v2/groups/")
            if gid is None or gid not in self.groups:
                zd_err(w, 404)
                return
            write(w, {"group": {"id": gid, "name": itest.CANARY, "is_public": self.groups[gid]}})
        else:
            self.errors.append(f"fake: no route for {r.method} {p}")
            zd_err(w, 404)


def zd_err(w: itest.ResponseWriter, status: int) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    if status == 404:
        w.write(f'{{"error":"RecordNotFound","description":"{itest.CANARY}"}}')
    elif status == 403:
        w.write(f'{{"error":{{"title":"Forbidden","message":"{itest.CANARY}"}}}}')
    else:
        w.write(f'{{"error":"Unavailable","description":"{itest.CANARY}"}}')


def write(w: itest.ResponseWriter, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write(json.dumps(v) + "\n")


Env = tuple[itest.Server, Fake, Connection]


@pytest.fixture
def setup_mode() -> Iterator[Callable[[str], Env]]:
    made: list[tuple[itest.Server, Fake]] = []

    def make(mode: str) -> Env:
        srv = itest.Server()
        srv.use_spec(spec_from_env("zendesk"), SpecOptions())
        f = Fake()
        srv.handle("GET", "/api/*", f.api)
        made.append((srv, f))
        deps, _ = itest.deps(srv)
        values = {"url": srv.url, "auth_mode": mode}
        if mode == AUTH_TOKEN:
            values["username"] = "bot@example.com"
        s = itest.settings("zd", "zendesk", values, {"credential": literal(f.token)})
        c = Zendesk().new(background(), s, deps)
        return srv, f, c

    yield make
    for srv, f in made:
        srv.close()
        assert not f.errors, "\n".join(f.errors)
        assert not srv.spec_errors, "requests did not match the API description:\n" + "\n".join(srv.spec_errors)


@pytest.fixture
def setup(setup_mode: Callable[[str], Env]) -> Callable[[], Env]:
    return lambda: setup_mode(AUTH_TOKEN)


Setup = Callable[[], Env]


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, Zendesk(), u, action, resource)


def expect(d: Decision, code: Code, text: str) -> None:
    itest.expect_code(d, code)
    if text:
        assert text in d.text, f"text {d.text!r} does not contain {text!r}"
    itest.assert_no_canary(d.text)


# --- the action table -------------------------------------------------------


def test_action_ticket_view_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, admin, "ticket.view", "ticket:2"), Code.ALLOWED, "administrator")
    # Within groups.
    expect(check(c, dana, "ticket.view", "ticket:1"), Code.ALLOWED, "group 300")
    # Assigned only.
    expect(check(c, bob, "ticket.view", "ticket:2"), Code.ALLOWED, "assigned to bob@example.com")
    # Within organization.
    expect(check(c, org_ag, "ticket.view", "ticket:2"), Code.ALLOWED, "organization 500")
    # Non-Enterprise groups restriction.
    expect(check(c, sara, "ticket.view", "ticket:6"), Code.ALLOWED, "group 301")
    # End user: requester and collaborator.
    expect(check(c, end_usr, "ticket.view", "ticket:1"), Code.ALLOWED, "requested")
    expect(check(c, end_usr, "ticket.view", "ticket:4"), Code.ALLOWED, "collaborator")


def test_action_ticket_view_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "ticket.view", "ticket:2"), Code.DENIED, "tickets of their groups only")
    expect(check(c, bob, "ticket.view", "ticket:1"), Code.DENIED, "assigned tickets only")
    expect(check(c, org_ag, "ticket.view", "ticket:1"), Code.DENIED, "organization only")
    expect(check(c, sara, "ticket.view", "ticket:1"), Code.DENIED, "group 300")
    expect(check(c, end_usr, "ticket.view", "ticket:2"), Code.DENIED, "did not request")
    expect(check(c, end2, "ticket.view", "ticket:1"), Code.DENIED, "")


def test_public_groups(setup: Setup) -> None:
    _, f, c = setup()
    # Ticket 4 is in a public group dana is not in.
    expect(check(c, dana, "ticket.view", "ticket:4"), Code.DENIED, "group 302")
    _, f, c = setup()
    with f.mu:
        f.roles[ROLE_TIER1]["ticket_access"] = "within-groups-and-public-groups"
    expect(check(c, dana, "ticket.view", "ticket:4"), Code.ALLOWED, "public group 302")
    expect(check(c, dana, "ticket.view", "ticket:2"), Code.DENIED, "group 301")


def test_ungrouped_ticket_is_unknown_for_group_agents(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "ticket.view", "ticket:5"), Code.UNSUPPORTED, "in no group")
    # A light agent without a ticket restriction sees all tickets.
    expect(check(c, lite, "ticket.view", "ticket:5"), Code.ALLOWED, "all tickets")


def test_action_ticket_edit_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, admin, "ticket.edit", "ticket:1"), Code.ALLOWED, "administrator")
    expect(check(c, dana, "ticket.edit", "ticket:1"), Code.ALLOWED, "may change the ticket's properties")
    expect(check(c, sara, "ticket.edit", "ticket:6"), Code.ALLOWED, "")


def test_action_ticket_edit_deny(setup: Setup) -> None:
    _, _, c = setup()
    # Role forbids editing.
    expect(check(c, bob, "ticket.edit", "ticket:2"), Code.DENIED, "may not change ticket properties")
    # Closed tickets, even for administrators.
    expect(check(c, admin, "ticket.edit", "ticket:3"), Code.DENIED, "closed")
    expect(check(c, dana, "ticket.edit", "ticket:3"), Code.DENIED, "closed")
    # Light agents unless requester; end users never.
    expect(check(c, lite, "ticket.edit", "ticket:1"), Code.DENIED, "light agent")
    expect(check(c, end_usr, "ticket.edit", "ticket:1"), Code.DENIED, "end user")
    # Not visible at all.
    expect(check(c, dana, "ticket.edit", "ticket:2"), Code.DENIED, "groups only")


def test_modify_closed_tickets(setup: Setup) -> None:
    _, f, c = setup()
    with f.mu:
        f.roles[ROLE_TIER1]["modify_closed_tickets"] = True
    expect(check(c, dana, "ticket.edit", "ticket:3"), Code.ALLOWED, "modify closed tickets")
    # The setting covers property changes only, and only visible tickets.
    expect(check(c, dana, "ticket.comment_public", "ticket:3"), Code.DENIED, "closed")
    with f.mu:
        f.tickets[8] = FakeTicket("closed", group=GROUP_B)
    expect(check(c, dana, "ticket.edit", "ticket:8"), Code.DENIED, "groups only")


def test_closed_tickets_take_no_updates(setup: Setup) -> None:
    _, _, c = setup()
    for a in ("ticket.edit", "ticket.comment_public", "ticket.merge"):
        expect(check(c, admin, a, "ticket:3"), Code.DENIED, "closed")
        expect(check(c, dana, a, "ticket:3"), Code.DENIED, "closed")
    expect(check(c, end_usr, "ticket.comment_public", "ticket:3"), Code.DENIED, "closed")
    expect(check(c, admin, "ticket.view", "ticket:3"), Code.ALLOWED, "")
    expect(check(c, admin, "ticket.delete", "ticket:3"), Code.ALLOWED, "")


def test_action_ticket_comment_public_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "ticket.comment_public", "ticket:1"), Code.ALLOWED, "comment publicly")
    expect(check(c, sara, "ticket.comment_public", "ticket:6"), Code.ALLOWED, "")
    expect(check(c, end_usr, "ticket.comment_public", "ticket:1"), Code.ALLOWED, "requested")


def test_action_ticket_comment_public_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, bob, "ticket.comment_public", "ticket:2"), Code.DENIED, "privately")
    expect(check(c, lite, "ticket.comment_public", "ticket:1"), Code.DENIED, "light agent")
    expect(check(c, end_usr, "ticket.comment_public", "ticket:2"), Code.DENIED, "")


def test_action_ticket_merge_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "ticket.merge", "ticket:1"), Code.ALLOWED, "merge")
    expect(check(c, admin, "ticket.merge", "ticket:2"), Code.ALLOWED, "")


def test_action_ticket_merge_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, bob, "ticket.merge", "ticket:2"), Code.DENIED, "may not merge")
    expect(check(c, lite, "ticket.merge", "ticket:1"), Code.DENIED, "")
    expect(check(c, end_usr, "ticket.merge", "ticket:1"), Code.DENIED, "")


def test_action_ticket_delete_allow(setup: Setup) -> None:
    _, f, c = setup()
    expect(check(c, admin, "ticket.delete", "ticket:1"), Code.ALLOWED, "")
    with f.mu:
        f.roles[ROLE_TIER1]["ticket_deletion"] = True
    expect(check(c, dana, "ticket.delete", "ticket:1"), Code.ALLOWED, "delete")


def test_action_ticket_delete_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "ticket.delete", "ticket:1"), Code.DENIED, "may not delete")
    # Non-Enterprise plans do not expose the setting.
    expect(check(c, sara, "ticket.delete", "ticket:6"), Code.UNSUPPORTED, "does not expose")


def test_action_organization_edit_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, admin, "organization.edit", "organization:500"), Code.ALLOWED, "")
    expect(check(c, org_ag, "organization.edit", "organization:500"), Code.ALLOWED, "organizations")


def test_action_organization_edit_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "organization.edit", "organization:500"), Code.DENIED, "may not")
    expect(check(c, end_usr, "organization.edit", "organization:500"), Code.DENIED, "end user")
    expect(check(c, sara, "organization.edit", "organization:500"), Code.UNSUPPORTED, "")
    expect(check(c, admin, "organization.edit", "organization:9"), Code.RESOURCE_NOT_VISIBLE, "organization 9")


def test_action_user_edit_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, admin, "user.edit", "user:11"), Code.ALLOWED, "any profile")
    # full end-user profile access.
    expect(check(c, dana, "user.edit", "user:20"), Code.ALLOWED, "end-user profiles")
    # edit-within-org: end2 shares org 500.
    expect(check(c, org_ag, "user.edit", "user:21"), Code.ALLOWED, "own organization")
    # Own profile.
    expect(check(c, bob, "user.edit", "user:12"), Code.ALLOWED, "own profile")
    expect(check(c, end_usr, "user.edit", "user:20"), Code.ALLOWED, "own profile")


def test_action_user_edit_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, bob, "user.edit", "user:20"), Code.DENIED, "only view")
    expect(check(c, org_ag, "user.edit", "user:20"), Code.DENIED, "not one")
    # Team members are edited by administrators only.
    expect(check(c, dana, "user.edit", "user:12"), Code.DENIED, "administrators edit other team members")
    expect(check(c, end_usr, "user.edit", "user:21"), Code.DENIED, "own profile only")
    # Non-Enterprise: sara sees group tickets only, so read-only profiles.
    expect(check(c, sara, "user.edit", "user:20"), Code.DENIED, "only view")
    expect(check(c, admin, "user.edit", "user:404"), Code.RESOURCE_NOT_VISIBLE, "")


def test_action_macro_manage_allow(setup: Setup) -> None:
    _, f, c = setup()
    expect(check(c, admin, "macro.manage", "account"), Code.ALLOWED, "administrator")
    with f.mu:
        f.roles[ROLE_TIER1]["macro_access"] = "full"
    expect(check(c, dana, "macro.manage", "account"), Code.ALLOWED, "shared macros")


def test_action_macro_manage_deny(setup: Setup) -> None:
    _, _, c = setup()
    # manage-personal is not shared macros.
    expect(check(c, dana, "macro.manage", "account"), Code.DENIED, "may not")
    expect(check(c, end_usr, "macro.manage", "account"), Code.DENIED, "end user")
    expect(check(c, sara, "macro.manage", "account"), Code.UNSUPPORTED, "does not expose")


def test_action_view_manage_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "view.manage", "account"), Code.ALLOWED, "shared views")


def test_action_view_manage_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, bob, "view.manage", "account"), Code.DENIED, "")


def test_action_business_rules_manage_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, org_ag, "business_rules.manage", "account"), Code.ALLOWED, "business rules")
    expect(check(c, admin, "business_rules.manage", "account"), Code.ALLOWED, "")


def test_action_business_rules_manage_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "business_rules.manage", "account"), Code.DENIED, "")


def test_action_account_admin_allow(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, admin, "account.admin", "account"), Code.ALLOWED, "is an administrator")


def test_action_account_admin_deny(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, dana, "account.admin", "account"), Code.DENIED, "not an administrator")
    expect(check(c, end_usr, "account.admin", "account"), Code.DENIED, "")


# --- identity ---------------------------------------------------------------


def test_identity(setup: Setup) -> None:
    _, _, c = setup()
    expect(check(c, User(email="nobody@example.com"), "account.admin", "account"), Code.USER_NOT_FOUND, "no Zendesk user")
    expect(check(c, User(email="dup@example.com"), "account.admin", "account"), Code.USER_AMBIGUOUS, "2 Zendesk users")
    expect(check(c, User(email="not an email"), "account.admin", "account"), Code.INVALID_REQUEST, "")
    # Deleted and suspended users are denied everything.
    expect(check(c, User(email="gone@example.com"), "ticket.view", "ticket:1"), Code.DENIED, "deleted")
    expect(check(c, User(email="susp@example.com"), "ticket.view", "ticket:1"), Code.DENIED, "suspended")
    # The loose match by suffix does not resolve to the admin.
    expect(check(c, dana, "account.admin", "account"), Code.DENIED, "")
    # A secondary email identity finds its user.
    expect(check(c, User(email="alice@example.com"), "account.admin", "account"), Code.ALLOWED, "alice@example.com is an administrator")


def test_admins_skip_group_listing(setup: Setup) -> None:
    srv, _, c = setup()
    check(c, admin, "ticket.view", "ticket:1")
    for call in srv.calls():
        assert not call.path.endswith("/group_memberships"), f"groups listed for an administrator: {call.path}"


def test_identity_attrs(setup: Setup) -> None:
    _, _, c = setup()
    ident = c.resolve_identity(background(), dana)
    assert ident.id == "11" and ident.attr("role") == "agent" and ident.attr("custom_role_id") == "100" and ident.attr("organization_id") == "500", (
        f"identity {ident}"
    )
    assert list(ident.groups) == ["300"], f"groups {ident.groups}"
    for k, v in ident.attrs.items():
        itest.assert_no_canary(k + "=" + v)


def test_group_paging(setup: Setup) -> None:
    srv, f, c = setup()
    with f.mu:
        f.per_page = 1
        for u in f.users:
            if u.id == DANA_ID:
                u.groups = [GROUP_A, GROUP_B, GROUP_PU]
    ident = c.resolve_identity(background(), dana)
    assert len(ident.groups) == 3, f"groups {ident.groups}, want 3"
    pages = sum(1 for call in srv.calls() if call.path.endswith("/group_memberships"))
    assert pages == 3, f"{pages} membership pages, want 3"


def test_next_page_off_host_is_refused(setup: Setup) -> None:
    srv, _, _ = setup()
    srv.reset()

    def h(w: itest.ResponseWriter, r: itest.Request) -> None:
        write(w, {"group_memberships": [], "next_page": "https://evil.example.com/api/v2/users/11/group_memberships?page=2"})

    srv.handle("GET", "/api/v2/users/*", h)
    deps, _ = itest.deps(srv)
    hc = deps.http_client(itest.settings("zd", "zendesk", None, None))
    c = ZendeskConnection(httpx.Client(http=hc, base=srv.url))
    with pytest.raises(Exception) as ei:
        c._group_memberships(background(), 11)
    assert "outside its API" in str(ei.value), f"err {ei.value}"


def test_unknown_role_shapes(setup: Setup) -> None:
    _, f, c = setup()
    with f.mu:
        f.users += [
            FakeUser(60, "contrib@example.com", ROLE_AGENT, role_type=3, active=True),
            FakeUser(61, "norole@example.com", ROLE_AGENT, role_type=0, custom_role=999, active=True),
            FakeUser(62, "weird@example.com", "owner", active=True),
        ]
    expect(check(c, User(email="contrib@example.com"), "ticket.view", "ticket:1"), Code.UNSUPPORTED, "role type 3")
    expect(check(c, User(email="norole@example.com"), "ticket.view", "ticket:1"), Code.RESOURCE_NOT_VISIBLE, "custom role 999")
    expect(check(c, User(email="weird@example.com"), "ticket.view", "ticket:1"), Code.UNSUPPORTED, "does not know")


def test_roles_are_cached(setup: Setup) -> None:
    _, f, c = setup()
    check(c, dana, "ticket.view", "ticket:1")
    check(c, bob, "ticket.view", "ticket:2")
    with f.mu:
        assert f.roles_got == 1, f"custom_roles fetched {f.roles_got} times, want 1"
        # A role created after the fetch is found by one refetch.
        f.roles[900] = {"ticket_access": "all", "ticket_editing": True}
        f.users.append(FakeUser(70, "new@example.com", ROLE_AGENT, role_type=0, custom_role=900, active=True))
    expect(check(c, User(email="new@example.com"), "ticket.edit", "ticket:1"), Code.ALLOWED, "role-900")
    with f.mu:
        assert f.roles_got == 2, f"custom_roles fetched {f.roles_got} times, want 2"


def test_ticket_not_visible(setup: Setup) -> None:
    _, f, c = setup()
    expect(check(c, admin, "ticket.view", "ticket:404"), Code.RESOURCE_NOT_VISIBLE, "ticket 404")
    with f.mu:
        f.tickets[7] = FakeTicket("open")
    expect(check(c, admin, "ticket.view", "ticket:7"), Code.RESOURCE_NOT_VISIBLE, "HTTP 403")


def test_invalid_requests(setup: Setup) -> None:
    _, _, c = setup()
    errors = []
    for action, resource in [
        ("ticket.view", "ticket:abc"),
        ("ticket.view", "ticket:"),
        ("ticket.view", "organization:1"),
        ("ticket.view", "ticket:1?x=1"),
        ("account.admin", "account:1"),
        ("ticket.view", "ticket:1/2"),
        ("ticket.view", "ticket:-1"),
        ("ticket.view", "ticket:012"),
        ("ticket.view", "ticket:0"),
        ("ticket.view", "ticket:99999999999999999999"),
    ]:
        d = check(c, admin, action, resource)
        if d.code != Code.INVALID_REQUEST:
            errors.append(f"{action} {resource}: {d.code} {d.text}")
    assert not errors, "\n".join(errors)


def test_failures(setup: Setup) -> None:
    srv, _, c = setup()
    itest.failure_cases(srv, lambda: check(c, dana, "ticket.view", "ticket:1"))


def test_forbidden_is_credential_problem(setup: Setup) -> None:
    _, f, c = setup()
    with f.mu:
        f.status = 403
    expect(check(c, dana, "ticket.view", "ticket:1"), Code.CREDENTIAL_REJECTED, "use an administrator")


def test_oauth_mode(setup_mode: Callable[[str], Env]) -> None:
    _, _, c = setup_mode(AUTH_OAUTH)
    expect(check(c, admin, "account.admin", "account"), Code.ALLOWED, "")


def test_new_validation(srv: itest.Server) -> None:
    deps, _ = itest.deps(srv)
    cases: list[tuple[dict[str, str], bool]] = [
        ({"url": srv.url}, False),
        ({"url": srv.url}, True),  # token mode without username
        ({"url": srv.url, "username": "bot"}, True),  # not an email
        ({"url": srv.url, "auth_mode": "magic"}, True),  # unknown mode
        ({"username": "bot@example.com"}, True),  # no url
    ]
    for values, has_secret in cases:
        secrets: dict[str, Secret] = {}
        if has_secret:
            secrets["credential"] = literal("x")
        with pytest.raises(ValueError):
            Zendesk().new(background(), itest.settings("zd", "zendesk", values, secrets), deps)


def test_probe(setup: Setup) -> None:
    _, f, c = setup()
    res = c.probe(background())
    assert "bot@example.com (admin)" in res.summary, f"summary {res.summary!r}"
    itest.assert_no_canary(res.summary)
    with f.mu:
        f.users[0].role = ROLE_AGENT
    res = c.probe(background())
    assert len(res.warnings) >= 2 and "not an administrator" in res.warnings[0], f"warnings {res.warnings}"
    with f.mu:
        f.token = "other"
    with pytest.raises(Exception) as ei:
        c.probe(background())
    ie = as_error(ei.value, HallpassError)
    assert ie is not None and ie.code == Code.CREDENTIAL_REJECTED, f"bad token: {ei.value}"


def test_no_secret_in_logs() -> None:
    with itest.Server() as srv:
        f = Fake()
        srv.handle("GET", "/api/*", f.api)
        deps, logs = itest.deps(srv)
        s = itest.settings("zd", "zendesk", {"url": srv.url, "username": "bot@example.com"}, {"credential": literal(f.token)})
        c = Zendesk().new(background(), s, deps)
        check(c, dana, "ticket.view", "ticket:1")
        check(c, admin, "ticket.view", "ticket:404")
        itest.assert_no_canary(logs.text())
