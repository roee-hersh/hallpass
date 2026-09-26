"""The datadog actions and resource parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from hallpass.core.catalog import Action, Resource
from hallpass.core.decision import Code, HallpassError, errorf
from hallpass.core.errors import go_quote


@dataclass(frozen=True)
class DDAction:
    """One named question: a permission the user's roles must carry and,
    for a restrictable asset, the relation a restriction policy or the
    asset's legacy restricted_roles must grant."""

    name: str
    desc: str
    # The type the action takes: monitor, dashboard, slo, notebook or org.
    resource: str
    # The permission name one of the user's roles must hold.
    permission: str
    # What the asset's restriction must grant: "editor" for changes,
    # "viewer" for reads, "" for org-wide questions.
    relation: str


ACTION_LIST: tuple[DDAction, ...] = (
    DDAction("monitor.edit", "change, delete or resolve the monitor (monitors_write)", "monitor", "monitors_write", "editor"),
    DDAction("monitor.mute", "mute the monitor or set a downtime on it (monitors_downtime)", "monitor", "monitors_downtime", "editor"),
    DDAction("monitor.read", "view the monitor (monitors_read)", "monitor", "monitors_read", "viewer"),
    DDAction("dashboard.edit", "change or delete the dashboard (dashboards_write)", "dashboard", "dashboards_write", "editor"),
    DDAction("dashboard.read", "view the dashboard (dashboards_read)", "dashboard", "dashboards_read", "viewer"),
    DDAction("slo.edit", "change or delete the SLO (slos_write)", "slo", "slos_write", "editor"),
    DDAction("notebook.edit", "change or delete the notebook (notebooks_write)", "notebook", "notebooks_write", "editor"),
    DDAction("logs.read", "read log data (logs_read_data)", "org", "logs_read_data", ""),
    DDAction("users.manage", "disable users and change roles (user_access_manage)", "org", "user_access_manage", ""),
    DDAction("apikeys.manage", "create and change API keys (api_keys_write)", "org", "api_keys_write", ""),
)

ACTIONS: dict[str, DDAction] = {a.name: a for a in ACTION_LIST}

RAW_PATTERN = "raw:<permission>"


def catalog_actions() -> list[Action]:
    """The catalog entries of the datadog integration."""
    out = [
        Action(
            RAW_PATTERN,
            "one permission by name on the org (raw:synthetics_write) or on a restrictable asset, where it must be the asset's write permission "
            "to be checked against its restrictions (raw:monitors_write on monitor:<id>)",
            pattern=True,
        )
    ]
    out += [Action(a.name, a.desc + " (" + a.resource + ")") for a in ACTION_LIST]
    return out


PERMISSION_RE = re.compile(r"[a-z][a-z0-9_]{2,63}")
# A Datadog asset id: numeric (monitors, notebooks) or alphanumeric with
# hyphens and underscores (dashboards, SLOs).
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


def permission_ok(s: str) -> bool:
    """Go: permissionRe.MatchString (^[a-z][a-z0-9_]{2,63}$)."""
    return PERMISSION_RE.fullmatch(s) is not None


def id_ok(s: str) -> bool:
    """Go: idRe.MatchString (^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$)."""
    return ID_RE.fullmatch(s) is not None


def match_action(name: str) -> Action | None:
    """Accept raw:<permission>."""
    try:
        parse_raw(name)
    except HallpassError:
        return None
    return Action(RAW_PATTERN, "permission " + name.removeprefix("raw:"), pattern=True)


def parse_raw(name: str) -> str:
    if not name.startswith("raw:"):
        raise invalid(f"unknown action {go_quote(name)}")
    p = name[len("raw:") :]
    if not permission_ok(p):
        raise invalid(f"raw action {go_quote(name)} must name a permission such as monitors_write")
    return p


def invalid(text: str) -> HallpassError:
    return errorf(Code.INVALID_REQUEST, text)


@dataclass(frozen=True)
class AssetType:
    # The restriction policy resource type.
    policy_type: str
    # The permissions that change the asset, which a restriction governs as
    # editing.
    write_permissions: tuple[str, ...]


ASSET_TYPES: dict[str, AssetType] = {
    "monitor": AssetType("monitor", ("monitors_write", "monitors_downtime")),
    "dashboard": AssetType("dashboard", ("dashboards_write",)),
    "slo": AssetType("slo", ("slos_write",)),
    "notebook": AssetType("notebook", ("notebooks_write",)),
}


@dataclass(frozen=True)
class Target:
    """A parsed question: the action (whose permission and relation apply)
    and the asset, empty for org questions."""

    action: DDAction
    typ: str
    id: str = ""

    def permission(self) -> str:
        return self.action.permission

    def relation(self) -> str:
        return self.action.relation

    def __str__(self) -> str:
        """Names the target for decision texts."""
        if self.typ == "org":
            return "the org"
        return self.typ + " " + self.id


def parse_target(action_name: str, r: Resource) -> Target:
    """Validate the resource for the action."""
    if r.query:
        raise invalid(f"resource {go_quote(r.raw)} must not carry a query")
    if r.type == "org" and r.id != "":
        raise invalid("org takes no id")
    if r.type not in ASSET_TYPES and r.type != "org":
        raise invalid(f"resource type {go_quote(r.type)} is not one of monitor, dashboard, slo, notebook, org")
    rid = ""
    if r.type != "org":
        if not id_ok(r.id):
            raise invalid(f"{r.type}: id must be the asset's id")
        rid = r.id
    if action_name.startswith("raw:"):
        p = parse_raw(action_name)
        a = DDAction(action_name, "hold " + p, r.type, p, "")
        if r.type != "org":
            # On an asset a raw permission is checked against the asset's
            # restrictions as a change when it is one of the type's write
            # permissions, as a read otherwise, exactly as the named action
            # carrying that permission would be.
            a = replace(a, relation="editor" if p in ASSET_TYPES[r.type].write_permissions else "viewer")
        return Target(a, r.type, rid)
    named = ACTIONS.get(action_name)
    if named is None:
        raise invalid(f"unknown action {go_quote(action_name)}")
    if named.resource != r.type:
        raise invalid(f"action {named.name} takes a {named.resource}: resource, not {r.type}:")
    return Target(named, r.type, rid)
