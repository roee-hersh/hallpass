"""The gitlab action table, resource parsing and protected-branch pattern
matching (Go: internal/integrations/gitlab/actions.go)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hallpass.core.catalog import Action, Resource, go_bytes, split_branch
from hallpass.core.errors import go_quote

# GitLab access levels. Planner (15) and Security Manager (25) are not
# cumulative with the levels around them, so every action lists the exact
# set of levels that grants it; nothing compares with >=.
LEVEL_NONE = 0
LEVEL_MINIMAL = 5
LEVEL_GUEST = 10
LEVEL_PLANNER = 15
LEVEL_REPORTER = 20
LEVEL_SECURITY_MANAGER = 25
LEVEL_DEVELOPER = 30
LEVEL_MAINTAINER = 40
LEVEL_OWNER = 50
# LEVEL_ADMIN appears only in protected-branch access entries ("Admins").
LEVEL_ADMIN = 60

_LEVEL_NAMES = {
    LEVEL_NONE: "no access",
    LEVEL_MINIMAL: "Minimal Access",
    LEVEL_GUEST: "Guest",
    LEVEL_PLANNER: "Planner",
    LEVEL_REPORTER: "Reporter",
    LEVEL_SECURITY_MANAGER: "Security Manager",
    LEVEL_DEVELOPER: "Developer",
    LEVEL_MAINTAINER: "Maintainer",
    LEVEL_OWNER: "Owner",
    LEVEL_ADMIN: "Admin",
}


def level_name(level: int) -> str:
    n = _LEVEL_NAMES.get(level)
    return n if n is not None else f"level {level}"


def level_names(levels: tuple[int, ...]) -> str:
    return ", ".join(level_name(level) for level in levels)


# Level sets shared by several actions.
GUEST_UP = (LEVEL_GUEST, LEVEL_PLANNER, LEVEL_REPORTER, LEVEL_SECURITY_MANAGER, LEVEL_DEVELOPER, LEVEL_MAINTAINER, LEVEL_OWNER)
PLANNER_UP = (LEVEL_PLANNER, LEVEL_REPORTER, LEVEL_SECURITY_MANAGER, LEVEL_DEVELOPER, LEVEL_MAINTAINER, LEVEL_OWNER)
DEVELOPER_UP = (LEVEL_DEVELOPER, LEVEL_MAINTAINER, LEVEL_OWNER)
MAINTAINER_UP = (LEVEL_MAINTAINER, LEVEL_OWNER)
OWNER_ONLY = (LEVEL_OWNER,)

# Resource scopes.
SCOPE_PROJECT = "project"
SCOPE_GROUP = "group"

# Protected-branch rule kinds.
BRANCH_PUSH = "push"
BRANCH_MERGE = "merge"


@dataclass(frozen=True)
class ActionSpec:
    """One row of the action table."""

    name: str
    desc: str
    # The resource type the action applies to.
    scope: str
    # The exact set of access levels that grants the action.
    levels: tuple[int, ...]
    # Levels at which GitLab grants the action only under conditions
    # hallpass does not evaluate; the answer is unknown.
    conditional: tuple[int, ...] = ()
    # Project visibilities that grant the action to authenticated
    # non-members (external users excepted on internal).
    non_member: tuple[str, ...] = ()
    # The protected-branch rule consulted when the resource has an @branch
    # suffix: BRANCH_PUSH, BRANCH_MERGE or "".
    branch: str = ""

    def grants(self, level: int) -> bool:
        return level in self.levels

    def is_conditional(self, level: int) -> bool:
        return level in self.conditional

    def grants_non_member(self, visibility: str) -> bool:
        return visibility in self.non_member


ACTION_LIST: tuple[ActionSpec, ...] = (
    ActionSpec("project.read", "view the project, its code and issues", SCOPE_PROJECT, GUEST_UP, non_member=("public", "internal")),
    ActionSpec("issue.create", "create an issue", SCOPE_PROJECT, GUEST_UP, non_member=("public", "internal")),
    # UNVERIFIED: Security Manager (25) is assumed to edit issues like Reporter.
    ActionSpec("issue.edit", "edit any issue (assign, label, close)", SCOPE_PROJECT, PLANNER_UP),
    ActionSpec("mr.create", "create a merge request", SCOPE_PROJECT, DEVELOPER_UP),
    ActionSpec("mr.approve", "approve a merge request", SCOPE_PROJECT, DEVELOPER_UP, conditional=(LEVEL_PLANNER, LEVEL_REPORTER)),
    ActionSpec("repo.push", "push to a branch (add @branch to the resource for protected-branch rules)", SCOPE_PROJECT, DEVELOPER_UP, branch=BRANCH_PUSH),
    ActionSpec("mr.merge", "merge into a branch (add @branch to the resource for protected-branch rules)", SCOPE_PROJECT, DEVELOPER_UP, branch=BRANCH_MERGE),
    ActionSpec("branch.protect", "protect or unprotect branches", SCOPE_PROJECT, MAINTAINER_UP),
    ActionSpec("project.admin", "change project settings", SCOPE_PROJECT, MAINTAINER_UP),
    ActionSpec("member.manage", "add, change or remove project members", SCOPE_PROJECT, MAINTAINER_UP),
    ActionSpec("project.delete", "delete the project", SCOPE_PROJECT, OWNER_ONLY),
    ActionSpec("pipeline.run", "run a pipeline", SCOPE_PROJECT, DEVELOPER_UP),
    ActionSpec("variable.manage", "manage CI/CD variables", SCOPE_PROJECT, MAINTAINER_UP),
    ActionSpec("runner.manage", "manage project runners", SCOPE_PROJECT, MAINTAINER_UP),
    ActionSpec("group.member", "be a member of the group at any level", SCOPE_GROUP, GUEST_UP),
    ActionSpec("group.admin", "change group settings and members (Owner)", SCOPE_GROUP, OWNER_ONLY),
    # UNVERIFIED: the group's "allowed to create projects" setting defaults to Developer.
    ActionSpec("group.project.create", "create a project in the group", SCOPE_GROUP, DEVELOPER_UP),
)

ACTIONS: dict[str, ActionSpec] = {a.name: a for a in ACTION_LIST}


def catalog_actions() -> list[Action]:
    return [Action(a.name, a.desc) for a in ACTION_LIST]


# PATH_RE is a namespace path: segments of [A-Za-z0-9_.-] that do not start
# with "-", separated by "/".
PATH_RE = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_.-]*(/[A-Za-z0-9_.][A-Za-z0-9_.-]*)*")
NUMERIC_RE = re.compile(r"[0-9]+")
# BRANCH_RE rejects control characters, spaces and the characters git
# forbids in ref names.
BRANCH_RE = re.compile(r"[^\x00-\x20\x7f~^:?*\[\\]+")

MAX_PATH_LENGTH = 512


@dataclass(frozen=True)
class Target:
    """A parsed resource: the project or group and an optional branch."""

    scope: str
    id: str  # path or numeric id, as sent
    branch: str = ""

    def __str__(self) -> str:
        return self.scope + " " + self.id


def parse_target(spec: ActionSpec, res: Resource) -> Target:
    """Validate the resource against the action's scope; ValueError when it
    does not fit.

        project:<path-or-id>[@branch]
        group:<path-or-id>
    """
    if res.type != spec.scope:
        raise ValueError(f"action {spec.name} takes a {spec.scope}:<path-or-id> resource, not {res.type}:")
    if res.query:
        raise ValueError("gitlab resources take no query parameters")
    rid, branch = res.id, ""
    if spec.scope == SCOPE_PROJECT:
        rid, branch = split_branch(res.id)
    try:
        validate_path(rid)
    except ValueError as e:
        raise ValueError(f"{spec.scope} {go_quote(rid)}: {e}") from None
    if branch != "":
        try:
            validate_branch(branch)
        except ValueError as e:
            raise ValueError(f"branch {go_quote(branch)}: {e}") from None
    elif res.id.endswith("@"):
        raise ValueError("branch after @ is empty")
    return Target(spec.scope, rid, branch)


def validate_path(rid: str) -> None:
    if rid == "":
        raise ValueError("id is empty")
    if len(go_bytes(rid)) > MAX_PATH_LENGTH:
        raise ValueError(f"id is longer than {MAX_PATH_LENGTH} bytes")
    if NUMERIC_RE.fullmatch(rid):
        return
    if not PATH_RE.fullmatch(rid):
        raise ValueError("must be a numeric id or a path such as acme/webapp")
    for seg in rid.split("/"):
        if seg in (".", ".."):
            raise ValueError("path segments . and .. are not allowed")


def validate_branch(b: str) -> None:
    if len(go_bytes(b)) > 255:
        raise ValueError("longer than 255 bytes")
    if not BRANCH_RE.fullmatch(b):
        raise ValueError("contains a space, control character or one of ~ ^ : ? * [ \\")
    if b.startswith("-"):
        raise ValueError("must not start with -")
    if ".." in b or "@{" in b:
        raise ValueError("must not contain .. or @{")
    if b.startswith("/") or b.endswith("/") or b.endswith(".") or b.endswith(".lock"):
        raise ValueError("must not start with /, or end with /, . or .lock")


def match_wildcard(pattern: str, name: str) -> bool:
    """Whether name matches a GitLab protected-branch pattern, where "*"
    matches any sequence of characters (including "/") and every other
    character matches itself. Byte-wise, as Go compares strings."""
    return _match_wildcard(go_bytes(pattern), go_bytes(name))


def _match_wildcard(pattern: bytes, name: bytes) -> bool:
    while pattern:
        if pattern[0] != 0x2A:  # '*'
            if not name or name[0] != pattern[0]:
                return False
            pattern, name = pattern[1:], name[1:]
            continue
        # Collapse runs of "*"; a trailing "*" matches the rest.
        pattern = pattern.lstrip(b"*")
        if not pattern:
            return True
        return any(_match_wildcard(pattern, name[i:]) for i in range(len(name) + 1))
    return name == b""
