"""The pagerduty actions, roles and resource parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum

from hallpass.core.catalog import Action, Resource
from hallpass.core.decision import Code, HallpassError, errorf
from hallpass.core.errors import go_quote, go_trim_space

# Base roles, as the API spells them. The web UI calls user "Manager",
# limited_user "Responder", read_only_user "Full Stakeholder" and
# read_only_limited_user "Limited Stakeholder".
ROLE_OWNER = "owner"
ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLE_LIMITED_USER = "limited_user"
ROLE_OBSERVER = "observer"
ROLE_RESTRICTED = "restricted_access"
ROLE_READ_ONLY = "read_only_user"
ROLE_READ_ONLY_LTD = "read_only_limited_user"
TEAM_ROLE_MANAGER = "manager"
TEAM_ROLE_RESPONDER = "responder"
TEAM_ROLE_OBSERVER = "observer"


class Need(IntEnum):
    """What an action requires."""

    # Act on incidents and create overrides. Base user and limited_user
    # hold it everywhere; observer and restricted_access hold it through a
    # responder or manager team role on the object's team.
    RESPOND = 0
    # Create, change and delete configuration. Base user holds it
    # everywhere; every flexible role below holds it through a manager team
    # role on the object's team.
    MANAGE = 1
    # Set a maintenance window on a service. Base user holds it everywhere;
    # team responders and managers hold it for their team's services;
    # whether base limited_user holds it account-wide is not documented, so
    # that case is unknown.
    MAINTENANCE = 2
    # Owner or admin base role.
    ACCOUNT_ADMIN = 3
    # A member of the team.
    TEAM_MEMBER = 4


@dataclass(frozen=True)
class PDAction:
    """One named question."""

    name: str
    desc: str
    # The type the action takes.
    resource: str
    need: Need


ACTION_LIST: tuple[PDAction, ...] = (
    PDAction("incident.acknowledge", "acknowledge the incident", "incident", Need.RESPOND),
    PDAction("incident.resolve", "resolve the incident", "incident", Need.RESPOND),
    PDAction("incident.reassign", "reassign or escalate the incident", "incident", Need.RESPOND),
    PDAction("service.edit", "change or delete the service and its integrations", "service", Need.MANAGE),
    PDAction("service.maintenance", "create a maintenance window for the service", "service", Need.MAINTENANCE),
    PDAction("escalation_policy.edit", "change or delete the escalation policy", "escalation_policy", Need.MANAGE),
    PDAction("schedule.edit", "change or delete the schedule", "schedule", Need.MANAGE),
    PDAction("schedule.override", "create an override on the schedule", "schedule", Need.RESPOND),
    PDAction("team.manage", "change the team, its members and their team roles", "team", Need.MANAGE),
    PDAction("team.member", "is a member of the team", "team", Need.TEAM_MEMBER),
    PDAction("account.admin", "is an account owner or global admin", "account", Need.ACCOUNT_ADMIN),
)

ACTIONS: dict[str, PDAction] = {a.name: a for a in ACTION_LIST}


def catalog_actions() -> list[Action]:
    """The catalog entries of the pagerduty integration."""
    return [Action(a.name, a.desc + " (" + a.resource + ")") for a in ACTION_LIST]


# A PagerDuty object id (P + upper-case alphanumerics) or, for incidents,
# an incident number.
ID_RE = re.compile(r"[A-Z0-9]{1,32}")


def id_ok(s: str) -> bool:
    """Go: idRe.MatchString (^[A-Z0-9]{1,32}$)."""
    return ID_RE.fullmatch(s) is not None


def invalid(text: str) -> HallpassError:
    return errorf(Code.INVALID_REQUEST, text)


def go_upper(s: str) -> str:
    """Go's strings.ToUpper: the simple, one-rune-for-one mapping (str.upper
    turns "ß" into "SS"; Go leaves it)."""
    if s.isascii():
        return s.upper()
    out = []
    for c in s:
        u = c.upper()
        out.append(u if len(u) == 1 else c)
    return "".join(out)


@dataclass(frozen=True)
class Target:
    """A parsed question."""

    action: PDAction
    id: str = ""

    def __str__(self) -> str:
        """Names the target for decision texts."""
        if self.action.resource == "account":
            return "the account"
        return self.action.resource.replace("_", " ") + " " + self.id


def parse_target(action_name: str, r: Resource) -> Target:
    """Validate the resource for the action."""
    a = ACTIONS.get(action_name)
    if a is None:
        raise invalid(f"unknown action {go_quote(action_name)}")
    if r.query:
        raise invalid(f"resource {go_quote(r.raw)} must not carry a query")
    if r.type != a.resource:
        raise invalid(f"action {a.name} takes an {a.resource}: resource, not {r.type}:")
    if r.type == "account":
        if r.id != "":
            raise invalid("account takes no id")
        return Target(a)
    rid = go_upper(go_trim_space(r.id))
    if not id_ok(rid):
        raise invalid(f"{r.type}: id must be a PagerDuty id such as PABC123")
    return Target(a, rid)
