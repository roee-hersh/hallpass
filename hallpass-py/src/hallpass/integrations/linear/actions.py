"""The linear actions and resource parsing (Go: linear/actions.go)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hallpass.core.catalog import Action, Resource
from hallpass.core.decision import Code, HallpassError, errorf
from hallpass.core.errors import go_lower, go_quote, go_trim_space


@dataclass(frozen=True)
class LinearAction:
    """One named question."""

    name: str
    desc: str
    # The type the action takes: team, issue, project or workspace.
    resource: str


ACTION_LIST: tuple[LinearAction, ...] = (
    LinearAction("team.view", "see the team and its issues", "team"),
    LinearAction("team.member", "is a member of the team", "team"),
    LinearAction("team.admin", "manage the team's settings and members", "team"),
    LinearAction("issue.view", "see the issue", "issue"),
    LinearAction("issue.edit", "edit and comment on the issue", "issue"),
    LinearAction("project.view", "see the project", "project"),
    LinearAction("workspace.member", "is a full member of the workspace (not a guest or an app)", "workspace"),
    LinearAction("workspace.admin", "is a workspace administrator or owner", "workspace"),
    LinearAction("workspace.owner", "is a workspace owner", "workspace"),
)

ACTIONS: dict[str, LinearAction] = {a.name: a for a in ACTION_LIST}


def catalog_actions() -> list[Action]:
    """Actions of the linear integration."""
    return [Action(a.name, a.desc + " (" + a.resource + ")") for a in ACTION_LIST]


# Go's regexp ^...$ anchors at the ends of the text; fullmatch does the same.
# Linear's internal id.
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# A team key such as ENG.
TEAM_KEY_RE = re.compile(r"[A-Z][A-Z0-9]{0,9}")
# A human issue identifier such as ENG-123.
ISSUE_KEY_RE = re.compile(r"[A-Z][A-Z0-9]{0,9}-[1-9][0-9]{0,8}")
# A project slug id.
SLUG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,79}")


def go_upper(s: str) -> str:
    """Go's strings.ToUpper: the simple, one-rune-for-one uppercase mapping
    (str.upper() turns "ß" into "SS" and U+FB00 into "FF"; Go does not)."""
    if s.isascii():
        return s.upper()
    out = []
    for c in s:
        u = c.upper()
        out.append(u if len(u) == 1 else c)
    return "".join(out)


def invalid(text: str) -> HallpassError:
    return errorf(Code.INVALID_REQUEST, text)


@dataclass(frozen=True)
class Target:
    """A parsed question."""

    action: LinearAction
    # The resource's id, key or identifier, exactly as it will be sent in a
    # GraphQL variable.
    id: str = ""
    # Set when id is a Linear uuid rather than a key.
    by_id: bool = False

    def __str__(self) -> str:
        """Names the target for decision texts."""
        if self.action.resource == "workspace":
            return "the workspace"
        return self.action.resource + " " + self.id


def parse_target(action_name: str, r: Resource) -> Target:
    """Validate the resource for the action. Raises HallpassError
    (invalid_request)."""
    a = ACTIONS.get(action_name)
    if a is None:
        raise invalid(f"unknown action {go_quote(action_name)}")
    if r.query:
        raise invalid(f"resource {go_quote(r.raw)} must not carry a query")
    if r.type != a.resource:
        raise invalid(f"action {a.name} takes a {a.resource}: resource, not {r.type}:")
    if r.type == "workspace":
        if r.id != "":
            raise invalid("workspace takes no id")
        return Target(action=a)
    id = go_trim_space(r.id)
    if UUID_RE.fullmatch(go_lower(id)):
        return Target(action=a, id=go_lower(id), by_id=True)
    if r.type == "team":
        id = go_upper(id)
        if not TEAM_KEY_RE.fullmatch(id):
            raise invalid("team: takes a team key such as ENG or a Linear id")
    elif r.type == "issue":
        id = go_upper(id)
        if not ISSUE_KEY_RE.fullmatch(id):
            raise invalid("issue: takes an identifier such as ENG-123 or a Linear id")
    elif r.type == "project":
        if not SLUG_RE.fullmatch(id):
            raise invalid("project: takes a slug id or a Linear id")
    return Target(action=a, id=id)
