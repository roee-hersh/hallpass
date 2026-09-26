"""The confluence actions and resource parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from hallpass.core.catalog import Resource
from hallpass.core.errors import go_quote

__all__ = [
    "ACTIONS",
    "ACTION_LIST",
    "CONTENT_ID_RE",
    "SPACE_KEY_PATTERN",
    "SPACE_KEY_RE",
    "ConfluenceAction",
    "ConfluenceResource",
    "ResKind",
    "parse_resource",
]


class ResKind(str, Enum):
    PAGE = "page"
    BLOGPOST = "blogpost"
    SPACE = "space"

    def __str__(self) -> str:
        return self.value

    def id_shape(self) -> str:
        return "KEY" if self == ResKind.SPACE else "id"


@dataclass(frozen=True)
class ConfluenceAction:
    """One Confluence operation. Page and blog post actions are asked of the
    content permission check with operation; space actions are matched
    against the space permission list by operation key and target type."""

    name: str
    desc: str
    resource: ResKind
    # The content check operation, or the space permission operation key.
    operation: str
    # The space permission targetType (space actions only).
    target: str = ""


ACTION_LIST: tuple[ConfluenceAction, ...] = (
    ConfluenceAction("page.read", "view a page", ResKind.PAGE, "read"),
    ConfluenceAction("page.update", "edit a page", ResKind.PAGE, "update"),
    ConfluenceAction("page.delete", "delete a page", ResKind.PAGE, "delete"),
    ConfluenceAction("blogpost.read", "view a blog post", ResKind.BLOGPOST, "read"),
    ConfluenceAction("blogpost.update", "edit a blog post", ResKind.BLOGPOST, "update"),
    ConfluenceAction("blogpost.delete", "delete a blog post", ResKind.BLOGPOST, "delete"),
    ConfluenceAction("space.read", "view the space (space permission read/space)", ResKind.SPACE, "read", "space"),
    ConfluenceAction("page.create", "add pages in the space (create/page)", ResKind.SPACE, "create", "page"),
    ConfluenceAction("blogpost.create", "add blog posts in the space (create/blogpost)", ResKind.SPACE, "create", "blogpost"),
    ConfluenceAction("comment.create", "add comments in the space (create/comment)", ResKind.SPACE, "create", "comment"),
    ConfluenceAction("attachment.create", "add attachments in the space (create/attachment)", ResKind.SPACE, "create", "attachment"),
    ConfluenceAction("space.export", "export the space (export/space)", ResKind.SPACE, "export", "space"),
    ConfluenceAction("page.restrict", "add or remove content restrictions in the space (restrict_content/space)", ResKind.SPACE, "restrict_content", "space"),
    ConfluenceAction("space.admin", "administer the space (administer/space)", ResKind.SPACE, "administer", "space"),
)

ACTIONS: dict[str, ConfluenceAction] = {a.name: a for a in ACTION_LIST}

# Go: ^[1-9][0-9]{0,18}$ and ^[A-Za-z0-9~_-]{1,255}$, matched in full (Go's
# $ matches only at the end of the text; Python's also before a newline).
CONTENT_ID_RE = re.compile(r"[1-9][0-9]{0,18}")
SPACE_KEY_PATTERN = "^[A-Za-z0-9~_-]{1,255}$"
SPACE_KEY_RE = re.compile(r"[A-Za-z0-9~_-]{1,255}")


@dataclass(frozen=True)
class ConfluenceResource:
    """A parsed page:<id>, blogpost:<id> or space:<KEY>."""

    kind: ResKind
    id: str


def parse_resource(res: Resource) -> ConfluenceResource:
    """The resource as a Confluence target; ValueError with Go's message
    otherwise."""
    if res.type in ("page", "blogpost"):
        if not CONTENT_ID_RE.fullmatch(res.id):
            raise ValueError(f"{res.type} id {go_quote(res.id)} must be a numeric content id")
        return ConfluenceResource(ResKind(res.type), res.id)
    if res.type == "space":
        if not SPACE_KEY_RE.fullmatch(res.id):
            raise ValueError(f"space key {go_quote(res.id)} must match {SPACE_KEY_PATTERN}")
        return ConfluenceResource(ResKind.SPACE, res.id)
    raise ValueError(f"resource type {go_quote(res.type)}; use page:<id>, blogpost:<id> or space:<KEY>")
