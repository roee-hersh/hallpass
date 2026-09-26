"""The snowflake object kinds, action table and resource parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from hallpass.core.catalog import Action, Resource
from hallpass.core.decision import Code, HallpassError, errorf
from hallpass.core.errors import go_quote, go_trim_space
from hallpass.integrations.snowflake.sql import parse_name, quote_name

__all__ = ["ACTIONS", "ACTION_LIST", "KINDS", "RAW_PATTERN", "ObjectKind", "SnowflakeAction", "Target", "catalog_actions", "match_action", "parse_raw", "parse_target"]


@dataclass(frozen=True)
class ObjectKind:
    """A resource type: the granted_on values SHOW GRANTS uses for it and how
    many dotted parts its name has."""

    # The SHOW GRANTS granted_on values the kind covers.
    granted_on: tuple[str, ...]
    parts: int


KINDS: dict[str, ObjectKind] = {
    # table: covers every relation SELECT and DML apply to.
    "table": ObjectKind(("TABLE", "VIEW", "MATERIALIZED VIEW", "EXTERNAL TABLE", "DYNAMIC TABLE", "EVENT TABLE", "ICEBERG TABLE", "HYBRID TABLE"), 3),
    "schema": ObjectKind(("SCHEMA",), 2),
    "database": ObjectKind(("DATABASE",), 1),
    "warehouse": ObjectKind(("WAREHOUSE",), 1),
    "role": ObjectKind(("ROLE",), 1),
    "account": ObjectKind(("ACCOUNT",), 0),
}


@dataclass(frozen=True)
class SnowflakeAction:
    """One named question: a privilege on a kind of object."""

    name: str
    desc: str
    kind: str
    # Privileges any of which answers the question; OWNERSHIP always does.
    privileges: tuple[str, ...] = field(default=())


ACTION_LIST: tuple[SnowflakeAction, ...] = (
    SnowflakeAction("table.select", "read the table or view", "table", ("SELECT",)),
    SnowflakeAction("table.insert", "insert rows", "table", ("INSERT",)),
    SnowflakeAction("table.update", "update rows", "table", ("UPDATE",)),
    SnowflakeAction("table.delete", "delete rows", "table", ("DELETE",)),
    SnowflakeAction("table.truncate", "truncate the table", "table", ("TRUNCATE",)),
    SnowflakeAction("schema.usage", "use the schema", "schema", ("USAGE",)),
    SnowflakeAction("schema.create_table", "create tables in the schema", "schema", ("CREATE TABLE",)),
    SnowflakeAction("schema.create_view", "create views in the schema", "schema", ("CREATE VIEW",)),
    SnowflakeAction("database.usage", "use the database", "database", ("USAGE",)),
    SnowflakeAction("database.create_schema", "create schemas in the database", "database", ("CREATE SCHEMA",)),
    SnowflakeAction("warehouse.usage", "run queries on the warehouse", "warehouse", ("USAGE",)),
    SnowflakeAction("warehouse.operate", "start, suspend and resize the warehouse", "warehouse", ("OPERATE",)),
    SnowflakeAction("warehouse.modify", "alter the warehouse", "warehouse", ("MODIFY",)),
    SnowflakeAction("role.use", "activate the role (granted directly or through another role)", "role", ()),
    SnowflakeAction("account.create_database", "create databases", "account", ("CREATE DATABASE",)),
    SnowflakeAction("account.manage_grants", "grant and revoke privileges on any object", "account", ("MANAGE GRANTS",)),
)

ACTIONS: dict[str, SnowflakeAction] = {a.name: a for a in ACTION_LIST}

RAW_PATTERN = "raw:<privilege>"


def catalog_actions() -> list[Action]:
    """The catalog entries of the snowflake integration."""
    out = []
    for a in ACTION_LIST:
        desc = a.desc
        if a.privileges:
            desc += " (" + " or ".join(a.privileges) + ")"
        out.append(Action(name=a.name, description=desc + " on " + a.kind + ":"))
    out.append(
        Action(
            name=RAW_PATTERN,
            pattern=True,
            description="any privilege on a typed resource, e.g. raw:REFERENCES on table:, raw:CREATE_STAGE on schema:, raw:MONITOR on warehouse:",
        )
    )
    return out


# A privilege name as raw: spells it: upper-case words joined by underscores.
_PRIVILEGE_RE = re.compile(r"[A-Z][A-Z_]{1,62}")


def parse_raw(name: str) -> SnowflakeAction | None:
    """raw:<PRIVILEGE>, or None."""
    if not name.startswith("raw:"):
        return None
    p = name[len("raw:") :]
    if not _PRIVILEGE_RE.fullmatch(p) or "__" in p or p.endswith("_"):
        return None
    priv = p.replace("_", " ")
    if priv == "OWNERSHIP":
        return None
    return SnowflakeAction(name=name, desc="hold " + priv, kind="", privileges=(priv,))


def match_action(name: str) -> Action | None:
    """Accept raw:<PRIVILEGE>."""
    a = parse_raw(name)
    if a is None:
        return None
    return Action(name=RAW_PATTERN, pattern=True, description=a.desc)


def invalid(text: str) -> HallpassError:
    return errorf(Code.INVALID_REQUEST, text)


@dataclass(frozen=True)
class Target:
    """A parsed question."""

    action: SnowflakeAction
    kind: str
    # The object's resolved dotted name; empty for account.
    name: tuple[str, ...] = ()

    def __str__(self) -> str:
        """The target for decision texts."""
        if self.kind == "account":
            return "the account"
        return self.kind + " " + quote_name(self.name)


def parse_target(action_name: str, r: Resource) -> Target:
    """Validate the action and resource; raise invalid_request."""
    a = ACTIONS.get(action_name)
    if a is None:
        a = parse_raw(action_name)
        if a is None:
            raise invalid(f"unknown action {go_quote(action_name)}")
        a = replace(a, kind=r.type)
    if r.query:
        raise invalid(f"resource {go_quote(r.raw)} must not carry a query")
    k = KINDS.get(r.type)
    if k is None:
        raise invalid(f"resource type {go_quote(r.type)} is not table:, schema:, database:, warehouse:, role: or account")
    if a.kind != r.type:
        raise invalid(f"action {a.name} takes a {a.kind}: resource, not {r.type}:")
    if r.type == "role" and action_name.startswith("raw:"):
        raise invalid("raw: privileges do not apply to role:; use role.use")
    if k.parts == 0:
        if go_trim_space(r.id) != "":
            raise invalid("account takes no id")
        return Target(action=a, kind=r.type)
    try:
        name = parse_name(r.id, k.parts)
    except ValueError as e:
        raise invalid(f"{r.type}: {e}") from None
    return Target(action=a, kind=r.type, name=name)
