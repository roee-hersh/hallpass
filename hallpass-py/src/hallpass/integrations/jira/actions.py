"""The jira actions (native permission keys) and resource parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum

from hallpass.core.catalog import Resource
from hallpass.core.errors import go_quote

__all__ = [
    "ACTIONS",
    "ACTION_LIST",
    "ISSUE_KEY_PATTERN",
    "ISSUE_KEY_RE",
    "PROJECT_KEY_PATTERN",
    "PROJECT_KEY_RE",
    "JiraAction",
    "JiraResource",
    "ResKind",
    "parse_resource",
]


@dataclass(frozen=True)
class JiraAction:
    """One Jira permission key. global ones are checked with
    globalPermissions on the resource "global"; the rest are project
    permissions checked on project:<KEY> or issue:<KEY-N>."""

    name: str
    desc: str
    global_: bool = False


ACTION_LIST: tuple[JiraAction, ...] = (
    JiraAction("BROWSE_PROJECTS", "view the project and its issues"),
    JiraAction("CREATE_ISSUES", "create issues in the project"),
    JiraAction("EDIT_ISSUES", "edit issues"),
    JiraAction("DELETE_ISSUES", "delete issues"),
    JiraAction("ASSIGN_ISSUES", "assign issues to users"),
    JiraAction("ASSIGNABLE_USER", "be assigned issues"),
    JiraAction("TRANSITION_ISSUES", "transition issues through the workflow"),
    JiraAction("RESOLVE_ISSUES", "resolve and reopen issues, set fix versions"),
    JiraAction("CLOSE_ISSUES", "close issues"),
    JiraAction("MOVE_ISSUES", "move issues between projects or issue types"),
    JiraAction("LINK_ISSUES", "link issues"),
    JiraAction("ADD_COMMENTS", "add comments"),
    JiraAction("EDIT_ALL_COMMENTS", "edit any comment"),
    JiraAction("DELETE_ALL_COMMENTS", "delete any comment"),
    JiraAction("CREATE_ATTACHMENTS", "attach files"),
    JiraAction("WORK_ON_ISSUES", "log work on issues"),
    JiraAction("MANAGE_WATCHERS", "manage the watcher list"),
    JiraAction("VIEW_VOTERS_AND_WATCHERS", "view voters and watchers"),
    JiraAction("SCHEDULE_ISSUES", "schedule issues (due date, rank)"),
    JiraAction("SET_ISSUE_SECURITY", "set the security level of issues"),
    JiraAction("MANAGE_SPRINTS_PERMISSION", "manage sprints"),
    JiraAction("ADMINISTER_PROJECTS", "administer the project"),
    JiraAction("ADMINISTER", "administer Jira (global)", global_=True),
    JiraAction("SYSTEM_ADMIN", "administer Jira system settings (global)", global_=True),
    JiraAction("USER_PICKER", "browse users and groups (global)", global_=True),
    JiraAction("CREATE_SHARED_OBJECTS", "share filters and dashboards (global)", global_=True),
    JiraAction("MANAGE_GROUP_FILTER_SUBSCRIPTIONS", "manage group filter subscriptions (global)", global_=True),
    JiraAction("BULK_CHANGE", "make bulk changes (global)", global_=True),
)

ACTIONS: dict[str, JiraAction] = {a.name: a for a in ACTION_LIST}

# The Go patterns, as error messages print them. The compiled forms are
# used with fullmatch: Go's $ matches only at the end of the text, while
# Python's also matches before a trailing newline.
PROJECT_KEY_PATTERN = "^[A-Z][A-Z0-9_]{1,9}$"
ISSUE_KEY_PATTERN = "^[A-Z][A-Z0-9_]{1,9}-[1-9][0-9]*$"
PROJECT_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]{1,9}")
ISSUE_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]{1,9}-[1-9][0-9]*")


class ResKind(IntEnum):
    GLOBAL = 0
    PROJECT = 1
    ISSUE = 2


@dataclass(frozen=True)
class JiraResource:
    """A parsed project:<KEY>, issue:<KEY-N> or global."""

    kind: ResKind
    key: str = ""

    def describe(self) -> str:
        if self.kind == ResKind.PROJECT:
            return "project " + self.key
        if self.kind == ResKind.ISSUE:
            return "issue " + self.key
        return "this site"


def parse_resource(res: Resource) -> JiraResource:
    """The resource as a Jira target; ValueError with Go's message otherwise."""
    if res.type == "global":
        if res.id != "":
            raise ValueError("global takes no id")
        return JiraResource(ResKind.GLOBAL)
    if res.type == "project":
        if not PROJECT_KEY_RE.fullmatch(res.id):
            raise ValueError(f"project key {go_quote(res.id)} must match {PROJECT_KEY_PATTERN}")
        return JiraResource(ResKind.PROJECT, res.id)
    if res.type == "issue":
        if not ISSUE_KEY_RE.fullmatch(res.id):
            raise ValueError(f"issue key {go_quote(res.id)} must match {ISSUE_KEY_PATTERN}")
        return JiraResource(ResKind.ISSUE, res.id)
    raise ValueError(f"resource type {go_quote(res.type)}; use project:<KEY>, issue:<KEY-N> or global")
