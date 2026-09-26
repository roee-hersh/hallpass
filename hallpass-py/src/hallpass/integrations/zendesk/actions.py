"""The zendesk actions and resource parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hallpass.core.catalog import Action, Resource
from hallpass.core.decision import Code, HallpassError, errorf
from hallpass.core.errors import go_quote, go_trim_space


@dataclass(frozen=True)
class ZDAction:
    """One named question."""

    name: str
    desc: str
    # The type the action takes: ticket, organization, user or account.
    resource: str


ACTION_LIST: tuple[ZDAction, ...] = (
    ZDAction("ticket.view", "see the ticket", "ticket"),
    ZDAction("ticket.edit", "change the ticket's properties: status, assignee, fields", "ticket"),
    ZDAction("ticket.comment_public", "add a public comment to the ticket", "ticket"),
    ZDAction("ticket.merge", "merge the ticket into another", "ticket"),
    ZDAction("ticket.delete", "delete the ticket", "ticket"),
    ZDAction("organization.edit", "add or change organizations", "organization"),
    ZDAction("user.edit", "edit the end user's profile", "user"),
    ZDAction("macro.manage", "create and change shared macros", "account"),
    ZDAction("view.manage", "create and change shared views", "account"),
    ZDAction("business_rules.manage", "change triggers, automations and other business rules", "account"),
    ZDAction("account.admin", "is an administrator", "account"),
)

ACTIONS: dict[str, ZDAction] = {a.name: a for a in ACTION_LIST}


def catalog_actions() -> list[Action]:
    """The catalog entries of the zendesk integration."""
    return [Action(a.name, a.desc + " (" + a.resource + ")") for a in ACTION_LIST]


# A Zendesk numeric id: decimal digits without a leading zero, so the id
# compares equal to the ids Zendesk returns.
ID_RE = re.compile(r"[1-9][0-9]{0,18}")


def id_ok(s: str) -> bool:
    """Go: idRe.MatchString (^[1-9][0-9]{0,18}$). [0-9] is ASCII only, as
    in Go."""
    return ID_RE.fullmatch(s) is not None


def invalid(text: str) -> HallpassError:
    return errorf(Code.INVALID_REQUEST, text)


@dataclass(frozen=True)
class Target:
    """A parsed question."""

    action: ZDAction
    id: str = ""

    def __str__(self) -> str:
        """Names the target for decision texts."""
        if self.action.resource == "account":
            return "the account"
        return self.action.resource + " " + self.id


def parse_target(action_name: str, r: Resource) -> Target:
    """Validate the resource for the action."""
    a = ACTIONS.get(action_name)
    if a is None:
        raise invalid(f"unknown action {go_quote(action_name)}")
    if r.query:
        raise invalid(f"resource {go_quote(r.raw)} must not carry a query")
    if r.type != a.resource:
        raise invalid(f"action {a.name} takes a {a.resource}: resource, not {r.type}:")
    if r.type == "account":
        if r.id != "":
            raise invalid("account takes no id")
        return Target(a)
    rid = go_trim_space(r.id)
    if not id_ok(rid):
        raise invalid(f"{r.type}: id must be a positive Zendesk id in plain decimal")
    return Target(a, rid)
