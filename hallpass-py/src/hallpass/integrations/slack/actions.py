"""The slack actions and resource validation (Go: slack/actions.go)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hallpass.core.catalog import Action, Resource
from hallpass.core.errors import go_quote

# Resource types the slack integration accepts.
RES_CHANNEL = "channel"
RES_WORKSPACE = "workspace"
RES_USERGROUP = "usergroup"


@dataclass(frozen=True)
class SlackAction:
    """One named question and the resource type it takes."""

    name: str
    desc: str
    resource: str


ACTION_LIST: tuple[SlackAction, ...] = (
    SlackAction("user.active", "the user has an active, joined, non-bot account", RES_WORKSPACE),
    SlackAction("workspace.admin", "the user is a workspace admin or owner", RES_WORKSPACE),
    SlackAction("org.admin", "the user is an Enterprise Grid org admin or owner", RES_WORKSPACE),
    SlackAction("channel.read", "read the channel's history", RES_CHANNEL),
    SlackAction("channel.join", "join the channel", RES_CHANNEL),
    SlackAction("message.post", "post a top-level message in the channel", RES_CHANNEL),
    SlackAction("message.post_thread", "reply in a thread in the channel", RES_CHANNEL),
    SlackAction("file.upload", "upload a file to the channel", RES_CHANNEL),
    SlackAction("usergroup.member", "the user is a member of the user group", RES_USERGROUP),
    SlackAction("channel.invite", "invite someone to the channel", RES_CHANNEL),
    SlackAction("channel.create", "create a channel in the workspace", RES_WORKSPACE),
    SlackAction("channel.archive", "archive the channel", RES_CHANNEL),
    SlackAction("channel.rename", "rename the channel", RES_CHANNEL),
)

ACTIONS: dict[str, SlackAction] = {a.name: a for a in ACTION_LIST}


def catalog_actions() -> list[Action]:
    """Actions of the slack integration."""
    return [Action(a.name, a.desc + " (" + a.resource + ")") for a in ACTION_LIST]


# Go's regexp ^...$ anchors at the ends of the text; fullmatch does the same.
CHANNEL_ID_RE = re.compile(r"[CG][A-Z0-9]{8,}")
USERGROUP_ID_RE = re.compile(r"S[A-Z0-9]{8,}")
USER_ID_RE = re.compile(r"[UW][A-Z0-9]{8,}")


def validate_resource(action_name: str, res: Resource) -> SlackAction:
    """Check that the resource matches the action's type and that the id is
    safe to put into a query string. Raises ValueError."""
    a = ACTIONS.get(action_name)
    if a is None:
        raise ValueError(f"unknown action {go_quote(action_name)}")
    if res.type != a.resource:
        raise ValueError(f"action {action_name} takes a {describe_resource(a.resource)} resource, not {res.type}")
    if res.query:
        raise ValueError("slack resources take no query parameters")
    if a.resource == RES_WORKSPACE:
        if res.id != "":
            raise ValueError("the workspace resource takes no id: use workspace")
    elif a.resource == RES_CHANNEL:
        if not CHANNEL_ID_RE.fullmatch(res.id):
            raise ValueError(f"channel id {go_quote(res.id)} must be a Slack channel id such as C0123456789")
    elif a.resource == RES_USERGROUP:
        if not USERGROUP_ID_RE.fullmatch(res.id):
            raise ValueError(f"usergroup id {go_quote(res.id)} must be a Slack user group id such as S0123456789")
    return a


def describe_resource(typ: str) -> str:
    if typ == RES_WORKSPACE:
        return "workspace"
    if typ == RES_CHANNEL:
        return "channel:<id>"
    if typ == RES_USERGROUP:
        return "usergroup:<id>"
    return typ
