"""The googleworkspace action table and resource parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hallpass.core.catalog import Action, Resource
from hallpass.core.decision import Code, HallpassError, errorf
from hallpass.core.errors import go_lower, go_quote, go_trim_space

__all__ = ["ACTION_INDEX", "ACTION_LIST", "CALENDAR_ID_RE", "EMAIL_RE", "FILE_ID_RE", "ActionDef", "catalog_actions", "parse_ref"]


@dataclass(frozen=True)
class ActionDef:
    name: str
    desc: str
    resource: str
    # The Drive capabilities field the action maps to.
    capability: str = ""


# The fixed action table with the resource type each accepts.
ACTION_LIST: tuple[ActionDef, ...] = (
    ActionDef("user.active", "the account exists and is neither suspended nor archived (user:<email>)", "user"),
    ActionDef("drive.file.read", "can see a Drive file's metadata (file:<id>)", "file"),
    ActionDef("drive.file.download", "can download a Drive file (file:<id>)", "file", "canDownload"),
    ActionDef("drive.file.edit", "can edit a Drive file (file:<id>)", "file", "canEdit"),
    ActionDef("drive.file.comment", "can comment on a Drive file (file:<id>)", "file", "canComment"),
    ActionDef("drive.file.share", "can share a Drive file (file:<id>)", "file", "canShare"),
    ActionDef("drive.file.trash", "can move a Drive file to the trash (file:<id>)", "file", "canTrash"),
    ActionDef("drive.file.delete", "can permanently delete a Drive file (file:<id>)", "file", "canDelete"),
    ActionDef("drive.file.rename", "can rename a Drive file (file:<id>)", "file", "canRename"),
    ActionDef("drive.file.copy", "can copy a Drive file (file:<id>)", "file", "canCopy"),
    ActionDef("drive.folder.add_child", "can add files to a Drive folder (file:<id>)", "file", "canAddChildren"),
    ActionDef("drive.folder.list", "can list a Drive folder's children (file:<id>)", "file", "canListChildren"),
    ActionDef("calendar.read", "can read events of a calendar (calendar:<id>)", "calendar"),
    ActionDef("calendar.event.write", "can create and change events of a calendar (calendar:<id>)", "calendar"),
    ActionDef("calendar.share", "owns a calendar and can change its sharing (calendar:<id>)", "calendar"),
    ActionDef("mail.send_as", "can send mail as an address (mailbox:<email>)", "mailbox"),
    ActionDef("mail.delegate_access", "is an accepted Gmail delegate of a mailbox (mailbox:<email>)", "mailbox"),
    ActionDef("group.member", "member of a Google group (group:<email>)", "group"),
)

ACTION_INDEX: dict[str, int] = {a.name: i for i, a in enumerate(ACTION_LIST)}


def catalog_actions() -> list[Action]:
    return [Action(name=a.name, description=a.desc) for a in ACTION_LIST]


# Go's ^...$ patterns, used with fullmatch.
FILE_ID_RE = re.compile(r"[A-Za-z0-9_-]{10,200}")
CALENDAR_ID_RE = re.compile(r"[A-Za-z0-9._%+@#-]{1,320}")
EMAIL_RE = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_{|}~.-]{1,64}@[A-Za-z0-9.-]{1,255}")


def _invalid(text: str) -> HallpassError:
    return errorf(Code.INVALID_REQUEST, text)


def parse_ref(action: str, r: Resource) -> str:
    """Validate the resource for the action and return the id."""
    i = ACTION_INDEX.get(action)
    if i is None:
        raise _invalid(f"unknown action {go_quote(action)}")
    a = ACTION_LIST[i]
    if r.type != a.resource:
        raise _invalid(f"action {action} takes a {a.resource}: resource, not {r.type}:")
    if r.query:
        raise _invalid(f"resource {go_quote(r.raw)} must not carry a query")
    rid = r.id
    if r.type in ("user", "mailbox", "group"):
        rid = go_lower(go_trim_space(rid))
        if not EMAIL_RE.fullmatch(rid):
            raise _invalid(f"{r.type}: id must be an email address")
    elif r.type == "file":
        if not FILE_ID_RE.fullmatch(rid):
            raise _invalid("file: id must be a Drive file id")
    elif r.type == "calendar":
        if not CALENDAR_ID_RE.fullmatch(rid):
            raise _invalid("calendar: id must be a calendar id (an email or primary)")
    return rid
