"""Port of internal/integrations/pagerduty/pagerduty_test.go."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from hallpass.core.context import background
from hallpass.core.decision import Code, Decision
from hallpass.core.integration import Connection, User, validate_fields
from hallpass.core.secret import literal
from hallpass.integrations.pagerduty import PagerDuty
from hallpass.integrations.pagerduty.actions import (
    ROLE_LIMITED_USER,
    ROLE_OBSERVER,
    ROLE_OWNER,
    ROLE_READ_ONLY,
    ROLE_RESTRICTED,
    ROLE_USER,
    TEAM_ROLE_MANAGER,
    TEAM_ROLE_OBSERVER,
    TEAM_ROLE_RESPONDER,
)
from hallpass.integrations.pagerduty.pagerduty import ACCEPT
from tests import harness as itest
from tests.harness.spec import SpecOptions, spec_from_env

owner = User(email="owner@example.com")  # owner
manager = User(email="manager@example.com")  # user (Manager)
responder = User(email="responder@example.com")  # limited_user (Responder)
observer = User(email="observer@example.com")  # observer, team manager on PTEAM1, responder on PTEAM2
restrict = User(email="restrict@example.com")  # restricted_access, team observer on PTEAM1
stake = User(email="stake@example.com")  # read_only_user
nobody = User(email="nobody@example.com")  # observer, no teams


@dataclass
class PDFakeUser:
    id: str
    email: str
    role: str
    teams: list[str] = field(default_factory=list)


def _atoi(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return 0


class Fake:
    def __init__(self) -> None:
        self.mu = threading.Lock()
        self.errors: list[str] = []
        self.key = itest.CANARY + "key"
        self.page_size = 100
        self.users = [
            PDFakeUser("PUOWNER", "owner@example.com", ROLE_OWNER),
            PDFakeUser("PUMANAG", "manager@example.com", ROLE_USER),
            PDFakeUser("PURESP", "responder@example.com", ROLE_LIMITED_USER),
            PDFakeUser("PUOBS", "observer@example.com", ROLE_OBSERVER, ["PTEAM1", "PTEAM2"]),
            PDFakeUser("PUREST", "restrict@example.com", ROLE_RESTRICTED, ["PTEAM1"]),
            PDFakeUser("PUSTAKE", "stake@example.com", ROLE_READ_ONLY),
            PDFakeUser("PUNOBODY", "nobody@example.com", ROLE_OBSERVER),
            # A name match that must not count as an email match.
            PDFakeUser("PUOTHER", "other@example.com", ROLE_USER),
        ]
        # team -> user id -> role
        self.team_roles: dict[str, dict[str, str]] = {
            "PTEAM1": {"PUOBS": TEAM_ROLE_MANAGER, "PUREST": TEAM_ROLE_OBSERVER},
            "PTEAM2": {"PUOBS": TEAM_ROLE_RESPONDER},
        }
        # "<type>/<id>" -> team ids
        self.objects: dict[str, list[str]] = {
            "services/PSVC1": ["PTEAM1"],
            "services/PSVC2": ["PTEAM2"],
            "services/PSVC0": [],
            "escalation_policies/PEP1": ["PTEAM1"],
            "escalation_policies/PEP2": ["PTEAM2"],
            "schedules/PSCH1": ["PTEAM1"],
            "schedules/PSCH2": ["PTEAM2"],
            "teams/PTEAM1": ["PTEAM1"],
            "teams/PTEAM2": ["PTEAM2"],
        }
        # incident id -> service id
        self.incidents = {"PINC1": "PSVC1", "PINC2": "PSVC2", "PINC0": "PSVC0"}
        self.abilities = ["teams", "advanced_permissions", "read_only_users"]
        self.status = 0
        # no_expand makes incidents return their service as a bare reference.
        self.no_expand = False
        # incident_teams gives an incident teams of its own.
        self.incident_teams: dict[str, list[str]] = {}

    def api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        with self.mu:
            self._api(w, r)

    def _api(self, w: itest.ResponseWriter, r: itest.Request) -> None:
        if r.header.get("Authorization") != "Token token=" + self.key:
            pd_err(w, 401, 2001)
            return
        if r.header.get("Accept") != ACCEPT:
            self.errors.append(f"Accept {r.header.get('Accept')!r}")
        if self.status != 0:
            pd_err(w, self.status, 2010)
            return
        p = r.path
        offset = _atoi(r.q("offset"))
        limit = _atoi(r.q("limit"))
        if limit <= 0 or limit > self.page_size:
            limit = self.page_size

        def page(key: str, values: list[dict[str, Any]]) -> None:
            off = min(offset, len(values))
            end = min(off + limit, len(values))
            write(w, {key: values[off:end], "limit": limit, "offset": off, "more": end < len(values), "total": None})

        if p == "/abilities":
            write(w, {"abilities": self.abilities})
        elif p == "/users":
            values = []
            query = r.q("query")
            for u in self.users:
                # PagerDuty's query matches names too; "other" carries the
                # searched address in its name.
                if query != "" and query not in u.email and not (u.id == "PUOTHER" and query == "owner@example.com"):
                    continue
                m: dict[str, Any] = {"id": u.id, "type": "user", "email": u.email, "role": u.role, "name": itest.CANARY + " name"}
                if r.q("include[]") == "teams":
                    m["teams"] = refs(u.teams, "team")
                values.append(m)
            if query == "dup@example.com":
                values += [{"id": "PDUP1", "email": "dup@example.com", "role": ROLE_USER}, {"id": "PDUP2", "email": "Dup@example.com", "role": ROLE_USER}]
            page("users", values)
        elif p.startswith("/teams/") and p.endswith("/members"):
            team = p.removeprefix("/teams/").removesuffix("/members")
            roles = self.team_roles.get(team)
            if roles is None:
                pd_err(w, 404, 2100)
                return
            values = []
            for u in self.users:
                if u.id in roles:
                    values.append({"user": {"id": u.id, "type": "user_reference", "summary": itest.CANARY}, "role": roles[u.id]})
            page("members", values)
        elif p.startswith("/incidents/"):
            iid = p.removeprefix("/incidents/")
            svc = self.incidents.get(iid)
            if svc is None:
                pd_err(w, 404, 2100)
                return
            inc: dict[str, Any] = {"id": iid, "type": "incident", "status": "triggered", "title": itest.CANARY, "teams": refs(self.incident_teams.get(iid, []), "team")}
            if r.q("include[]") == "services" and not self.no_expand:
                inc["service"] = {"id": svc, "type": "service", "teams": refs(self.objects.get("services/" + svc, []), "team")}
            else:
                inc["service"] = {"id": svc, "type": "service_reference"}
            write(w, {"incident": inc})
        elif any(p.startswith(x) for x in ("/services/", "/escalation_policies/", "/schedules/", "/teams/")):
            teams = self.objects.get(p.removeprefix("/"))
            if teams is None:
                pd_err(w, 404, 2100)
                return
            parts = p.removeprefix("/").split("/", 1)
            key = parts[0].removesuffix("s")
            if key == "escalation_policie":
                key = "escalation_policy"
            body = {"id": parts[1], "type": key, "summary": itest.CANARY, "teams": refs(teams, "team")}
            write(w, {key: body})
        else:
            self.errors.append(f"fake: no route for {r.method} {p}")
            pd_err(w, 404, 2100)


def pd_err(w: itest.ResponseWriter, status: int, code: int) -> None:
    w.header().set("Content-Type", "application/json")
    w.write_header(status)
    w.write(f'{{"error":{{"code":{code},"message":"{itest.CANARY} message","errors":["{itest.CANARY} detail"]}}}}')


def write(w: itest.ResponseWriter, v: Any) -> None:
    w.header().set("Content-Type", "application/json")
    w.write(json.dumps(v) + "\n")


def refs(ids: list[str], typ: str) -> list[dict[str, Any]]:
    return [{"id": i, "type": typ + "_reference", "summary": itest.CANARY + i, "self": "https://api.pagerduty.com/" + typ + "s/" + i} for i in ids]


Env = tuple[itest.Server, Fake, Connection]


@pytest.fixture
def setup() -> Iterator[Callable[[], Env]]:
    made: list[tuple[itest.Server, Fake]] = []

    def make() -> Env:
        srv = itest.Server()
        srv.use_spec(spec_from_env("pagerduty"), SpecOptions())
        f = Fake()
        srv.handle("GET", "/*", f.api)
        made.append((srv, f))
        deps, _ = itest.deps(srv)
        s = itest.settings("pd", "pagerduty", {"url": srv.url}, {"credential": literal(f.key)})
        c = PagerDuty().new(background(), s, deps)
        return srv, f, c

    yield make
    for srv, f in made:
        srv.close()
        assert not f.errors, "\n".join(f.errors)
        assert not srv.spec_errors, "requests did not match the API description:\n" + "\n".join(srv.spec_errors)


def check(c: Connection, u: User, action: str, resource: str) -> Decision:
    return itest.check(c, PagerDuty(), u, action, resource)


def expect(d: Decision, code: Code, text: str) -> None:
    itest.expect_code(d, code)
    if text:
        assert text in d.text, f"text {d.text!r} does not contain {text!r}"
    itest.assert_no_canary(d.text)


# --- the action table -------------------------------------------------------


def test_action_incident_acknowledge_allow(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, responder, "incident.acknowledge", "incident:PINC0"), Code.ALLOWED, "Responder base role")
    # Observer with a responder team role on the incident's service team.
    expect(check(c, observer, "incident.acknowledge", "incident:PINC2"), Code.ALLOWED, "team responder")


def test_action_incident_acknowledge_deny(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, nobody, "incident.acknowledge", "incident:PINC1"), Code.DENIED, "on none of the teams")
    expect(check(c, stake, "incident.acknowledge", "incident:PINC1"), Code.DENIED, "read-only role")
    # A team observer may not respond.
    expect(check(c, restrict, "incident.acknowledge", "incident:PINC1"), Code.DENIED, "team observer")


def test_action_incident_resolve_allow(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, manager, "incident.resolve", "incident:PINC1"), Code.ALLOWED, "Manager base role")


def test_action_incident_resolve_deny(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, nobody, "incident.resolve", "incident:PINC0"), Code.DENIED, "belongs to no team")


def test_action_incident_reassign_allow(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, owner, "incident.reassign", "incident:PINC1"), Code.ALLOWED, "Account Owner")
    # Team manager on the service's team.
    expect(check(c, observer, "incident.reassign", "incident:PINC1"), Code.ALLOWED, "team manager")


def test_action_incident_reassign_deny(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, observer, "incident.reassign", "incident:PINC0"), Code.DENIED, "")


def test_action_service_edit_allow(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, manager, "service.edit", "service:PSVC1"), Code.ALLOWED, "")
    expect(check(c, observer, "service.edit", "service:PSVC1"), Code.ALLOWED, "team manager")


def test_action_service_edit_deny(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    # A Responder base role does not edit configuration.
    expect(check(c, responder, "service.edit", "service:PSVC1"), Code.DENIED, "on none of the teams")
    # A team responder does not either.
    expect(check(c, observer, "service.edit", "service:PSVC2"), Code.DENIED, "team responder")


def test_action_service_maintenance_allow(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, manager, "service.maintenance", "service:PSVC0"), Code.ALLOWED, "")
    expect(check(c, observer, "service.maintenance", "service:PSVC2"), Code.ALLOWED, "team responder")
    expect(check(c, responder, "service.maintenance", "service:PSVC2"), Code.UNSUPPORTED, "not documented")


def test_action_service_maintenance_deny(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, nobody, "service.maintenance", "service:PSVC1"), Code.DENIED, "")
    expect(check(c, stake, "service.maintenance", "service:PSVC1"), Code.DENIED, "")


def test_action_escalation_policy_edit_allow(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, observer, "escalation_policy.edit", "escalation_policy:PEP1"), Code.ALLOWED, "team manager")


def test_action_escalation_policy_edit_deny(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, observer, "escalation_policy.edit", "escalation_policy:PEP2"), Code.DENIED, "")


def test_action_schedule_edit_allow(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, manager, "schedule.edit", "schedule:PSCH2"), Code.ALLOWED, "")


def test_action_schedule_edit_deny(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, restrict, "schedule.edit", "schedule:PSCH1"), Code.DENIED, "team observer")


def test_action_schedule_override_allow(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, responder, "schedule.override", "schedule:PSCH1"), Code.ALLOWED, "")
    expect(check(c, observer, "schedule.override", "schedule:PSCH2"), Code.ALLOWED, "")


def test_action_schedule_override_deny(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, restrict, "schedule.override", "schedule:PSCH1"), Code.DENIED, "")


def test_action_team_manage_allow(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, observer, "team.manage", "team:PTEAM1"), Code.ALLOWED, "team manager")
    expect(check(c, owner, "team.manage", "team:PTEAM2"), Code.ALLOWED, "")


def test_action_team_manage_deny(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, observer, "team.manage", "team:PTEAM2"), Code.DENIED, "team responder")


def test_action_team_member_allow(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, restrict, "team.member", "team:PTEAM1"), Code.ALLOWED, "member of team PTEAM1")


def test_action_team_member_deny(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, manager, "team.member", "team:PTEAM1"), Code.DENIED, "not a member")


def test_action_account_admin_allow(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, owner, "account.admin", "account"), Code.ALLOWED, "Account Owner")


def test_action_account_admin_deny(setup: Callable[[], Env]) -> None:
    _, _, c = setup()
    expect(check(c, manager, "account.admin", "account"), Code.DENIED, "Manager")


# --- semantics -----------------------------------------------------------------


def test_incident_teams_from_service(setup: Callable[[], Env]) -> None:
    srv, _, c = setup()
    expect(check(c, observer, "incident.acknowledge", "incident:PINC2"), Code.ALLOWED, "")
    # The service came expanded with the incident: no separate service read.
    for call in srv.calls():
        assert not call.path.startswith("/services/"), "service read although the incident expanded it"
        if call.path.startswith("/incidents/"):
            assert call.q("include[]") == "services", f"incident read without include[]=services: {call.query}"


def test_incident_service_as_reference(setup: Callable[[], Env]) -> None:
    srv, f, c = setup()
    with f.mu:
        f.no_expand = True
        f.incident_teams = {"PINC2": ["PTEAM1"]}
    # The incident carries PTEAM1 itself and its service PSVC2 carries
    # PTEAM2; the observer is a manager on PTEAM1 and a responder on PTEAM2.
    # The service must still be read although the incident has teams.
    expect(check(c, restrict, "incident.acknowledge", "incident:PINC2"), Code.DENIED, "team observer")
    assert any(call.path == "/services/PSVC2" for call in srv.calls()), "the unexpanded service was not read"
    # A user on none of the object's teams costs no member reads.
    n = len(srv.calls())
    expect(check(c, nobody, "incident.acknowledge", "incident:PINC2"), Code.DENIED, "on none of the teams")
    for call in srv.calls()[n:]:
        assert not call.path.endswith("/members"), "member list read for a user on none of the teams"


def test_paging(setup: Callable[[], Env]) -> None:
    srv, f, c = setup()
    with f.mu:
        f.page_size = 1
    # Team PTEAM1 has two members; the restricted user is on the second page.
    expect(check(c, restrict, "schedule.edit", "schedule:PSCH1"), Code.DENIED, "team observer")
    pages = sum(1 for call in srv.calls() if call.path == "/teams/PTEAM1/members")
    assert pages >= 2, f"read {pages} member pages, want at least 2"


def test_identity(setup: Callable[[], Env]) -> None:
    srv, _, c = setup()
    expect(check(c, User(email=" Owner@Example.com "), "account.admin", "account"), Code.ALLOWED, "")
    lookup = None
    for call in srv.calls():
        if call.path == "/users":
            lookup = call
    assert lookup is not None and lookup.q("query") == "owner@example.com" and lookup.q("include[]") == "teams", f"lookup {lookup}"
    expect(check(c, User(email="ghost@example.com"), "account.admin", "account"), Code.USER_NOT_FOUND, "")
    expect(check(c, User(email="dup@example.com"), "account.admin", "account"), Code.USER_AMBIGUOUS, "")
    expect(check(c, User(email="bad email"), "account.admin", "account"), Code.INVALID_REQUEST, "")


def test_unknown_role(setup: Callable[[], Env]) -> None:
    _, f, c = setup()
    with f.mu:
        f.users.append(PDFakeUser("PUNEW", "new@example.com", "team_responder"))
    expect(check(c, User(email="new@example.com"), "incident.acknowledge", "incident:PINC1"), Code.UNSUPPORTED, "does not know")


def test_missing_objects_and_errors(setup: Callable[[], Env]) -> None:
    _, f, c = setup()
    expect(check(c, observer, "incident.acknowledge", "incident:PNOPE"), Code.RESOURCE_NOT_VISIBLE, "does not exist or hallpass cannot see it")
    expect(check(c, observer, "service.edit", "service:PNOPE"), Code.RESOURCE_NOT_VISIBLE, "")
    expect(check(c, observer, "team.member", "team:PNOPE"), Code.RESOURCE_NOT_VISIBLE, "")
    # Even account-wide roles are not allowed on an object hallpass cannot see.
    expect(check(c, manager, "service.edit", "service:PNOPE"), Code.RESOURCE_NOT_VISIBLE, "")
    expect(check(c, owner, "team.member", "team:PNOPE"), Code.RESOURCE_NOT_VISIBLE, "")
    # A team of the object that vanished is named.
    with f.mu:
        f.objects["services/PSVC1"] = ["PTEAM1", "PGONE"]
    expect(check(c, observer, "service.edit", "service:PSVC1"), Code.ALLOWED, "team manager")  # manager found first, PGONE never read
    with f.mu:
        f.objects["services/PSVC1"] = ["PTEAM1"]
    with f.mu:
        f.status = 403
    d = check(c, observer, "service.edit", "service:PSVC1")
    expect(d, Code.CREDENTIAL_REJECTED, "error 2010")
    with f.mu:
        f.status = 402
    expect(check(c, observer, "service.edit", "service:PSVC1"), Code.UNSUPPORTED, "lacks the ability")


def test_rejects_bad_resources(setup: Callable[[], Env]) -> None:
    srv, _, c = setup()
    expect(check(c, owner, "account.admin", "account"), Code.ALLOWED, "")
    n = len(srv.calls())
    cases = [
        ("incident.acknowledge", "service:PSVC1"),
        ("service.edit", "incident:PINC1"),
        ("account.admin", "account:x"),
        ("team.member", "team:"),
        ("team.member", "team:P TEAM"),
        ("team.member", "team:PTEAM1/x"),
        ("team.member", "team:PTEAM1?x=1"),
        ("incident.resolve", "incident:p-1"),
    ]
    errors = []
    for action, resource in cases:
        d = check(c, owner, action, resource)
        if d.code != Code.INVALID_REQUEST:
            errors.append(f"{action} {resource}: {d.code} ({d.text}), want invalid_request")
    for call in srv.calls()[n:]:
        if call.path != "/users":
            errors.append(f"rejected resource reached {call.path}")
    assert not errors, "\n".join(errors)
    # Lower-case ids are accepted and upper-cased.
    expect(check(c, owner, "team.member", "team:pteam1"), Code.DENIED, "PTEAM1")


def test_failures(setup: Callable[[], Env]) -> None:
    srv, _, c = setup()
    expect(check(c, observer, "service.edit", "service:PSVC1"), Code.ALLOWED, "")
    itest.failure_cases(srv, lambda: check(c, observer, "service.edit", "service:PSVC1"))


def test_probe(setup: Callable[[], Env]) -> None:
    _, f, c = setup()
    r = c.probe(background())
    assert "3 abilities" in r.summary, r.summary
    itest.assert_no_canary(r.summary)
    joined = "\n".join(r.warnings)
    assert "lacks the teams ability" not in joined and "Read-only API Key" in joined, f"warnings {r.warnings}"
    with f.mu:
        f.abilities = ["urgencies"]
    r = c.probe(background())
    joined = "\n".join(r.warnings)
    assert "lacks the teams ability" in joined and "advanced permissions" in joined, f"warnings {r.warnings}"
    with f.mu:
        f.status = 401
    with pytest.raises(Exception) as ei:
        c.probe(background())
    itest.assert_no_canary(str(ei.value))


def test_new_rejects_bad_settings(srv: itest.Server) -> None:
    deps, _ = itest.deps(srv)
    s = itest.settings("pd", "pagerduty", {}, None)
    with pytest.raises(Exception):
        PagerDuty().new(background(), s, deps)
    validate_fields(PagerDuty().fields())


def test_catalog() -> None:
    seen: set[str] = set()
    for a in PagerDuty().actions():
        assert a.name not in seen and a.description != "", f"action {a.name} duplicated or undescribed"
        seen.add(a.name)
