"""The databricks action catalog, the parsing of a question, and the
privilege and permission-level rules.

Two permission systems live in one workspace. Unity Catalog securables
(catalog, schema, table, volume, function, model) carry privileges such as
SELECT and MODIFY, inherited down the hierarchy. Workspace objects
(clusters, jobs, warehouses, notebooks, ...) carry permission levels such as
CAN_ATTACH_TO and CAN_MANAGE from the Permissions API.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from hallpass.core.catalog import Action, Resource
from hallpass.core.decision import Code, HallpassError, errorf
from hallpass.core.errors import go_quote

__all__ = [
    "ACTION_INDEX",
    "ACTION_LIST",
    "PRIV_ALL_PRIVILEGES",
    "RAW_PATTERN",
    "RAW_RE",
    "UC_NAME_RE",
    "UC_TYPES",
    "WS_ID_RE",
    "WS_TYPES",
    "DatabricksAction",
    "HeldPrivileges",
    "Ref",
    "catalog_actions",
    "covers",
    "known_level",
    "levels_of",
    "match_action",
    "parse_raw",
    "parse_ref",
    "resource_types",
    "satisfies_level",
    "satisfies_privileges",
]


@dataclass(frozen=True)
class _UCType:
    securable: str
    parts: int


# A hallpass resource type -> the Unity Catalog securable type in the API
# path and the number of dot-separated name parts it takes.
UC_TYPES: dict[str, _UCType] = {
    "catalog": _UCType("catalog", 1),
    "schema": _UCType("schema", 2),
    "table": _UCType("table", 3),
    "volume": _UCType("volume", 3),
    "function": _UCType("function", 3),
    "model": _UCType("model", 3),
}


@dataclass(frozen=True)
class _WSType:
    object: str
    chains: tuple[tuple[str, ...], ...]


# A hallpass resource type -> the Permissions API object type and the
# permission levels it knows, weakest first. A stronger level implies every
# weaker one in the same chain; CAN_MANAGE and IS_OWNER imply everything.
WS_TYPES: dict[str, _WSType] = {
    "cluster": _WSType("clusters", (("CAN_ATTACH_TO", "CAN_RESTART", "CAN_MANAGE"),)),
    "policy": _WSType("cluster-policies", (("CAN_USE",),)),
    "pool": _WSType("instance-pools", (("CAN_ATTACH_TO", "CAN_MANAGE"),)),
    "job": _WSType("jobs", (("CAN_VIEW", "CAN_MANAGE_RUN", "IS_OWNER", "CAN_MANAGE"),)),
    "pipeline": _WSType("pipelines", (("CAN_VIEW", "CAN_RUN", "IS_OWNER", "CAN_MANAGE"),)),
    "warehouse": _WSType("warehouses", (("CAN_VIEW", "CAN_MONITOR", "CAN_MANAGE"), ("CAN_VIEW", "CAN_USE", "IS_OWNER", "CAN_MANAGE"))),
    "notebook": _WSType("notebooks", (("CAN_READ", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE"),)),
    "directory": _WSType("directories", (("CAN_READ", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE"),)),
    "repo": _WSType("repos", (("CAN_READ", "CAN_RUN", "CAN_EDIT", "CAN_MANAGE"),)),
    "endpoint": _WSType("serving-endpoints", (("CAN_VIEW", "CAN_QUERY", "CAN_MANAGE"),)),
    "experiment": _WSType("experiments", (("CAN_READ", "CAN_EDIT", "CAN_MANAGE"),)),
    "registered_model": _WSType(
        "registered-models", (("CAN_READ", "CAN_EDIT", "CAN_MANAGE_STAGING_VERSIONS", "CAN_MANAGE_PRODUCTION_VERSIONS", "CAN_MANAGE"),)
    ),
}


@dataclass(frozen=True)
class DatabricksAction:
    """One named question."""

    name: str
    desc: str
    # The resource types the action applies to.
    types: tuple[str, ...]
    # The Unity Catalog privileges that must all be held (for a UC action);
    # level is the permission level needed (for a workspace action).
    privileges: tuple[str, ...] = ()
    level: str = ""


PRIV_SELECT = "SELECT"
PRIV_MODIFY = "MODIFY"
PRIV_USE_CATALOG = "USE_CATALOG"
PRIV_USE_SCHEMA = "USE_SCHEMA"
PRIV_CREATE_TABLE = "CREATE_TABLE"
PRIV_CREATE_SCHEMA = "CREATE_SCHEMA"
PRIV_READ_VOLUME = "READ_VOLUME"
PRIV_WRITE_VOLUME = "WRITE_VOLUME"
PRIV_EXECUTE = "EXECUTE"
PRIV_MANAGE = "MANAGE"
PRIV_ALL_PRIVILEGES = "ALL_PRIVILEGES"
# The legacy name that stood for both USE_CATALOG and USE_SCHEMA before they
# were split.
PRIV_USAGE = "USAGE"

_UC_ALL = ("catalog", "schema", "table", "volume", "function", "model")
_NB = ("notebook", "directory", "repo")

ACTION_LIST = (
    DatabricksAction(
        "table.read", "read a table or view: SELECT with USE_SCHEMA and USE_CATALOG", ("table",), (PRIV_SELECT, PRIV_USE_SCHEMA, PRIV_USE_CATALOG)
    ),
    DatabricksAction(
        "table.write", "change a table's data: MODIFY with USE_SCHEMA and USE_CATALOG", ("table",), (PRIV_MODIFY, PRIV_USE_SCHEMA, PRIV_USE_CATALOG)
    ),
    DatabricksAction(
        "table.create",
        "create a table in a schema: CREATE_TABLE with USE_SCHEMA and USE_CATALOG",
        ("schema",),
        (PRIV_CREATE_TABLE, PRIV_USE_SCHEMA, PRIV_USE_CATALOG),
    ),
    DatabricksAction("schema.create", "create a schema in a catalog: CREATE_SCHEMA with USE_CATALOG", ("catalog",), (PRIV_CREATE_SCHEMA, PRIV_USE_CATALOG)),
    DatabricksAction("catalog.use", "use a catalog: USE_CATALOG", ("catalog",), (PRIV_USE_CATALOG,)),
    DatabricksAction(
        "volume.read",
        "read files in a volume: READ_VOLUME with USE_SCHEMA and USE_CATALOG",
        ("volume",),
        (PRIV_READ_VOLUME, PRIV_USE_SCHEMA, PRIV_USE_CATALOG),
    ),
    DatabricksAction(
        "volume.write",
        "write files in a volume: WRITE_VOLUME with USE_SCHEMA and USE_CATALOG",
        ("volume",),
        (PRIV_WRITE_VOLUME, PRIV_USE_SCHEMA, PRIV_USE_CATALOG),
    ),
    DatabricksAction(
        "function.execute", "call a function: EXECUTE with USE_SCHEMA and USE_CATALOG", ("function",), (PRIV_EXECUTE, PRIV_USE_SCHEMA, PRIV_USE_CATALOG)
    ),
    DatabricksAction("uc.manage", "manage grants on a Unity Catalog securable: MANAGE, or ownership", _UC_ALL, (PRIV_MANAGE,)),
    DatabricksAction("cluster.attach", "attach to a cluster (CAN_ATTACH_TO)", ("cluster",), level="CAN_ATTACH_TO"),
    DatabricksAction("cluster.restart", "restart a cluster (CAN_RESTART)", ("cluster",), level="CAN_RESTART"),
    DatabricksAction("cluster.manage", "manage a cluster (CAN_MANAGE)", ("cluster",), level="CAN_MANAGE"),
    DatabricksAction("job.view", "view a job and its runs (CAN_VIEW)", ("job",), level="CAN_VIEW"),
    DatabricksAction("job.run", "trigger and cancel a job's runs (CAN_MANAGE_RUN)", ("job",), level="CAN_MANAGE_RUN"),
    DatabricksAction("job.manage", "edit and delete a job (CAN_MANAGE)", ("job",), level="CAN_MANAGE"),
    DatabricksAction("warehouse.use", "run queries on a SQL warehouse (CAN_USE)", ("warehouse",), level="CAN_USE"),
    DatabricksAction("warehouse.manage", "manage a SQL warehouse (CAN_MANAGE)", ("warehouse",), level="CAN_MANAGE"),
    DatabricksAction("notebook.read", "read a notebook, directory or repo (CAN_READ)", _NB, level="CAN_READ"),
    DatabricksAction("notebook.run", "run a notebook, or notebooks in a directory or repo (CAN_RUN)", _NB, level="CAN_RUN"),
    DatabricksAction("notebook.edit", "edit a notebook, directory or repo (CAN_EDIT)", _NB, level="CAN_EDIT"),
    DatabricksAction("pipeline.run", "start and stop a pipeline (CAN_RUN)", ("pipeline",), level="CAN_RUN"),
    DatabricksAction("endpoint.query", "query a model serving endpoint (CAN_QUERY)", ("endpoint",), level="CAN_QUERY"),
)

ACTION_INDEX = {a.name: i for i, a in enumerate(ACTION_LIST)}

RAW_PATTERN = "raw:<PRIVILEGE or LEVEL>"


def catalog_actions() -> list[Action]:
    """The actions of the databricks integration."""
    out = [
        Action(
            RAW_PATTERN,
            "one Unity Catalog privilege on a catalog/schema/table/volume/function/model (raw:SELECT, raw:CREATE_VOLUME) "
            "or one permission level on a workspace object (raw:CAN_RESTART, raw:IS_OWNER)",
            pattern=True,
        )
    ]
    out.extend(Action(a.name, a.desc + " (" + ", ".join(a.types) + ")") for a in ACTION_LIST)
    return out


RAW_RE = re.compile(r"[A-Z][A-Z0-9_]{1,63}")


def match_action(name: str) -> Action | None:
    """Accept raw:<PRIVILEGE or LEVEL>."""
    try:
        parse_raw(name)
    except ValueError:
        return None
    return Action(RAW_PATTERN, "privilege or permission level " + name.removeprefix("raw:"), pattern=True)


def parse_raw(name: str) -> str:
    if not name.startswith("raw:"):
        raise ValueError(f"unknown action {go_quote(name)}")
    p = name[len("raw:") :]
    if not RAW_RE.fullmatch(p):
        raise ValueError(f"raw action {go_quote(name)} must name a privilege or permission level in upper case, such as raw:SELECT or raw:CAN_RESTART")
    return p


# One part of a Unity Catalog name. Names are quoted in SQL with backticks
# and may hold more, but hallpass only places them in a URL path segment, so
# it keeps to the unquoted identifier shape.
UC_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,255}")
# A workspace object id: cluster ids like 0123-456789-abcde1f2, numeric job,
# notebook and warehouse ids, UUIDs, endpoint names.
WS_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")


def _invalid(text: str) -> HallpassError:
    return errorf(Code.INVALID_REQUEST, text)


@dataclass(frozen=True)
class Ref:
    """One parsed question."""

    # Set for a Unity Catalog question.
    uc: bool = False
    securable: str = ""  # catalog, schema, table, ...
    full_name: str = ""  # catalog.schema.table
    privileges: tuple[str, ...] = ()  # every one must be held
    # object and id are set for a workspace object question.
    object: str = ""  # clusters, jobs, ...
    id: str = ""
    level: str = ""
    chains: tuple[tuple[str, ...], ...] = ()


def parse_ref(action_name: str, r: Resource) -> Ref:
    """Validate the action and the resource together; HallpassError
    (invalid_request) otherwise."""
    if r.query:
        raise _invalid(f"resource {go_quote(r.raw)} must not carry a query")
    uc = UC_TYPES.get(r.type)
    ws = WS_TYPES.get(r.type)
    if uc is not None:
        parts = r.id.split(".")
        if len(parts) != uc.parts:
            raise _invalid(f"{r.type}: id must have {uc.parts} dot-separated parts, as in {_uc_example(r.type)}")
        for p in parts:
            if not UC_NAME_RE.fullmatch(p):
                raise _invalid(f"{r.type}: {go_quote(p)} is not a Unity Catalog name")
        out = Ref(uc=True, securable=uc.securable, full_name=r.id)
    elif ws is not None:
        if not WS_ID_RE.fullmatch(r.id):
            raise _invalid(f"{r.type}: id must be the object's id")
        out = Ref(object=ws.object, id=r.id, chains=ws.chains)
    else:
        raise _invalid(f"resource type {go_quote(r.type)} is not one of {', '.join(resource_types())}")
    if action_name.startswith("raw:"):
        try:
            p = parse_raw(action_name)
        except ValueError as e:
            raise _invalid(str(e)) from e
        if out.uc:
            return Ref(uc=True, securable=out.securable, full_name=out.full_name, privileges=(p,))
        if not known_level(out.chains, p):
            raise _invalid(f"{p} is not a permission level of {r.type}; the levels are {', '.join(levels_of(out.chains))}")
        return Ref(object=out.object, id=out.id, level=p, chains=out.chains)
    i = ACTION_INDEX.get(action_name)
    if i is None:
        raise _invalid(f"unknown action {go_quote(action_name)}")
    a = ACTION_LIST[i]
    if r.type not in a.types:
        raise _invalid(f"action {a.name} takes a {' or '.join(a.types)} resource, not {r.type}:")
    return Ref(
        uc=out.uc,
        securable=out.securable,
        full_name=out.full_name,
        privileges=a.privileges,
        object=out.object,
        id=out.id,
        level=a.level,
        chains=out.chains,
    )


def _uc_example(typ: str) -> str:
    uc = UC_TYPES.get(typ)
    parts = uc.parts if uc is not None else 0
    if parts == 1:
        return typ + ":main"
    if parts == 2:
        return typ + ":main.sales"
    return typ + ":main.sales.orders"


def resource_types() -> list[str]:
    return sorted([*UC_TYPES, *WS_TYPES])


def known_level(chains: tuple[tuple[str, ...], ...], level: str) -> bool:
    """Whether the level exists for an object with these chains. CAN_MANAGE
    and IS_OWNER exist for every type."""
    return level in ("CAN_MANAGE", "IS_OWNER") or level in levels_of(chains)


def levels_of(chains: tuple[tuple[str, ...], ...]) -> list[str]:
    """The distinct levels of the chains, in chain order."""
    out: list[str] = []
    for chain in chains:
        for lv in chain:
            if lv not in out:
                out.append(lv)
    return out


def _index(chain: tuple[str, ...], v: str) -> int:
    try:
        return chain.index(v)
    except ValueError:
        return -1


def satisfies_level(held: list[str], need: str, chains: tuple[tuple[str, ...], ...]) -> tuple[bool, str]:
    """Whether one of the held permission levels implies need for an object
    with the given chains. CAN_MANAGE and IS_OWNER imply every level but
    IS_OWNER itself, which names the one owner; within a chain a level
    implies the ones before it."""
    for h in held:
        if h == need:
            return True, h
        if need == "IS_OWNER":
            continue
        if h in ("CAN_MANAGE", "IS_OWNER"):
            return True, h
        for chain in chains:
            hi, ni = _index(chain, h), _index(chain, need)
            if hi >= 0 and ni >= 0 and hi > ni:
                return True, h
    return False, ""


@dataclass
class HeldPrivileges:
    """What the user holds on a securable: named privileges, and the
    securable types (the securable's own, or an ancestor's) on which
    ALL_PRIVILEGES was granted."""

    named: set[str] = field(default_factory=set)
    # The securable types carrying an ALL_PRIVILEGES grant that reaches this
    # securable: "table" for a grant on the table itself, "schema" or
    # "catalog" for an inherited one.
    all_on: list[str] = field(default_factory=list)


def covers(scope: str, privilege: str, owner: bool) -> bool:
    """Whether a grant of everything on a securable of type scope
    (ALL_PRIVILEGES there, or ownership of it) stands for the privilege when
    asked about a descendant. USE_CATALOG lives on the catalog and
    USE_SCHEMA on the schema, so a grant lower down never carries them.
    ALL_PRIVILEGES does not include MANAGE; ownership does."""
    if privilege == PRIV_USE_CATALOG:
        return scope == "catalog"
    if privilege == PRIV_USE_SCHEMA:
        return scope in ("catalog", "schema")
    if privilege == PRIV_MANAGE:
        return owner
    return True


def satisfies_privileges(held: HeldPrivileges, need: tuple[str, ...] | list[str]) -> tuple[bool, list[str]]:
    """Whether the held privileges cover every needed one, and which are
    missing. The legacy USAGE covers USE_CATALOG and USE_SCHEMA."""
    missing: list[str] = []
    for n in need:
        if n in held.named or (n in (PRIV_USE_CATALOG, PRIV_USE_SCHEMA) and PRIV_USAGE in held.named):
            continue
        if any(covers(scope, n, False) for scope in held.all_on):
            continue
        missing.append(n)
    return not missing, missing
