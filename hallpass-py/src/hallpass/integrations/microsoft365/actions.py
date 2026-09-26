"""The microsoft365 action table and resource parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hallpass.core.catalog import Action, Resource
from hallpass.core.decision import Code, HallpassError, errorf
from hallpass.core.errors import go_quote

__all__ = [
    "ACTION_LIST",
    "ACTION_RESOURCES",
    "CHANNEL_ID_RE",
    "DRIVE_ID_RE",
    "EMAIL_RE",
    "GUID_RE",
    "Ref",
    "catalog_actions",
    "parse_ref",
]


@dataclass(frozen=True)
class ActionDef:
    name: str
    desc: str
    # The resource types the action accepts; check rejects anything else as
    # invalid_request.
    resources: tuple[str, ...]


# The fixed action table.
ACTION_LIST: tuple[ActionDef, ...] = (
    ActionDef("user.active", "the account exists and is enabled (user:<email> or mailbox:<email>)", ("user", "mailbox")),
    ActionDef("group.member", "transitive member of an Entra group (group:<guid>)", ("group",)),
    ActionDef("role.member", "holds an Entra directory role (role:<role template guid>)", ("role",)),
    ActionDef("team.member", "member of a team (team:<guid>)", ("team",)),
    ActionDef("team.owner", "owner of a team (team:<guid>)", ("team",)),
    ActionDef("channel.read", "can read a channel (team:<guid>/channel/<channel id>)", ("team",)),
    ActionDef("channel.message.post", "can post a message in a channel (team:<guid>/channel/<channel id>)", ("team",)),
    ActionDef("channel.owner", "owner of a channel, or of its team for standard channels (team:<guid>/channel/<channel id>)", ("team",)),
    ActionDef("file.read", "can read a drive item (drive:<drive id>/item/<item id>)", ("drive",)),
    ActionDef("file.edit", "can edit a drive item (drive:<drive id>/item/<item id>)", ("drive",)),
    ActionDef("file.share", "can share a drive item (drive:<drive id>/item/<item id>)", ("drive",)),
    ActionDef("file.delete", "can delete a drive item (drive:<drive id>/item/<item id>)", ("drive",)),
    ActionDef("mail.send_as_self", "can send mail from their own mailbox (mailbox:<email>)", ("mailbox",)),
    ActionDef("mail.send_as", "Exchange Send As on a mailbox: always unknown, no Graph API (mailbox:<email>)", ("mailbox",)),
    ActionDef("mail.send_on_behalf", "Exchange Send on Behalf on a mailbox: always unknown, no Graph API (mailbox:<email>)", ("mailbox",)),
    ActionDef("mailbox.full_access", "Exchange Full Access on a mailbox: always unknown, no Graph API (mailbox:<email>)", ("mailbox",)),
    ActionDef("calendar.read", "read another mailbox's calendar: always unknown, no Graph API for delegation (mailbox:<email>)", ("mailbox",)),
    ActionDef("calendar.write", "write another mailbox's calendar: always unknown, no Graph API for delegation (mailbox:<email>)", ("mailbox",)),
)

ACTION_RESOURCES: dict[str, tuple[str, ...]] = {a.name: a.resources for a in ACTION_LIST}


def catalog_actions() -> list[Action]:
    return [Action(name=a.name, description=a.desc) for a in ACTION_LIST]


# Go's ^...$ patterns; used with fullmatch (Python's $ also matches before a
# trailing newline).
GUID_RE = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
CHANNEL_ID_RE = re.compile(r"[A-Za-z0-9:@._-]{1,200}")
DRIVE_ID_RE = re.compile(r"[A-Za-z0-9!_.-]{1,200}")
# EMAIL_RE accepts ordinary addresses and guest UPNs (which contain #EXT#).
EMAIL_RE = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_{|}~.-]{1,64}@[A-Za-z0-9.-]{1,255}")


@dataclass(frozen=True)
class Ref:
    """A parsed resource."""

    typ: str
    # The primary identifier: a GUID for group/role/team, an email or GUID
    # for user/mailbox, a drive id for drive.
    id: str
    # Set for team:<id>/channel/<id>.
    channel: str = ""
    # Set for drive:<id>/item/<id>.
    item: str = ""

    def describe(self) -> str:
        """The resource for decision texts."""
        if self.channel != "":
            return f"channel {self.channel} of team {self.id}"
        if self.item != "":
            return f"item {self.item} in drive {self.id}"
        return self.typ + " " + self.id


def _invalid(text: str) -> HallpassError:
    return errorf(Code.INVALID_REQUEST, text)


def parse_ref(action: str, r: Resource) -> Ref:
    """Validate the resource for the action."""
    allowed = ACTION_RESOURCES.get(action)
    if allowed is None:
        raise _invalid(f"unknown action {go_quote(action)}")
    if r.type not in allowed:
        raise _invalid(f"action {action} takes a {' or '.join(allowed)} resource, not {r.type}:")
    if r.query:
        raise _invalid(f"resource {go_quote(r.raw)} must not carry a query")
    typ, rid, channel, item = r.type, r.id, "", ""
    if typ in ("user", "mailbox"):
        if not EMAIL_RE.fullmatch(rid) and not GUID_RE.fullmatch(rid):
            raise _invalid(f"{typ}: id must be an email address or a GUID")
    elif typ in ("group", "role"):
        if not GUID_RE.fullmatch(rid):
            raise _invalid(f"{typ}: id must be a GUID")
    elif typ == "team":
        team_id, sep, rest = r.id.partition("/")
        if not GUID_RE.fullmatch(team_id):
            raise _invalid("team: id must be a GUID, optionally followed by /channel/<channel id>")
        rid = team_id
        if sep:
            if not rest.startswith("channel/") or not CHANNEL_ID_RE.fullmatch(rest[len("channel/") :]):
                raise _invalid("team: expected team:<guid>/channel/<channel id>")
            channel = rest[len("channel/") :]
        if action.startswith("channel.") and channel == "":
            raise _invalid(f"{action} needs team:<guid>/channel/<channel id>")
        if action.startswith("team.") and channel != "":
            raise _invalid(f"{action} takes team:<guid> without a channel")
    elif typ == "drive":
        drive_id, sep, rest = r.id.partition("/")
        ok = rest.startswith("item/")
        it = rest[len("item/") :] if ok else rest
        if not sep or not ok or not DRIVE_ID_RE.fullmatch(drive_id) or not DRIVE_ID_RE.fullmatch(it):
            raise _invalid("drive: expected drive:<drive id>/item/<item id>")
        rid, item = drive_id, it
    else:
        raise _invalid(f"unsupported resource type {go_quote(typ)}")
    return Ref(typ, rid, channel, item)
