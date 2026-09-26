"""The argocd actions and how a check becomes an enforcer request."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hallpass.core.catalog import Resource
from hallpass.core.errors import go_quote

from . import rbac

__all__ = ["ACTIONS", "ACTION_LIST", "ACT_ROLLBACK", "OBJ_RE", "RESOURCE_TYPES", "ActionDef", "EnforceRequest", "build_request", "parse_pattern"]

# Resolved at check time to sync or rollback depending on
# server.rbac.rollback.enforce.enable.
ACT_ROLLBACK = "\x00rollback"


@dataclass(frozen=True)
class ActionDef:
    name: str
    desc: str
    res: str
    act: str


ACTION_LIST: tuple[ActionDef, ...] = (
    ActionDef("app.get", "view an application", rbac.RESOURCE_APPLICATIONS, rbac.ACTION_GET),
    ActionDef("app.create", "create an application", rbac.RESOURCE_APPLICATIONS, rbac.ACTION_CREATE),
    ActionDef("app.update", "update an application", rbac.RESOURCE_APPLICATIONS, rbac.ACTION_UPDATE),
    ActionDef("app.delete", "delete an application", rbac.RESOURCE_APPLICATIONS, rbac.ACTION_DELETE),
    ActionDef("app.sync", "sync an application", rbac.RESOURCE_APPLICATIONS, rbac.ACTION_SYNC),
    ActionDef(
        "app.rollback",
        "roll an application back (sync, or rollback when server.rbac.rollback.enforce.enable is on)",
        rbac.RESOURCE_APPLICATIONS,
        ACT_ROLLBACK,
    ),
    ActionDef("app.override", "override application parameters", rbac.RESOURCE_APPLICATIONS, rbac.ACTION_OVERRIDE),
    ActionDef("logs.get", "read pod logs of an application", rbac.RESOURCE_LOGS, rbac.ACTION_GET),
    ActionDef("exec.create", "exec into a pod of an application", rbac.RESOURCE_EXEC, rbac.ACTION_CREATE),
    ActionDef("appset.get", "view an ApplicationSet", rbac.RESOURCE_APPLICATION_SETS, rbac.ACTION_GET),
    ActionDef("appset.create", "create an ApplicationSet", rbac.RESOURCE_APPLICATION_SETS, rbac.ACTION_CREATE),
    ActionDef("appset.update", "update an ApplicationSet", rbac.RESOURCE_APPLICATION_SETS, rbac.ACTION_UPDATE),
    ActionDef("appset.delete", "delete an ApplicationSet", rbac.RESOURCE_APPLICATION_SETS, rbac.ACTION_DELETE),
    ActionDef("project.get", "view a project", rbac.RESOURCE_PROJECTS, rbac.ACTION_GET),
    ActionDef("project.create", "create a project", rbac.RESOURCE_PROJECTS, rbac.ACTION_CREATE),
    ActionDef("project.update", "update a project", rbac.RESOURCE_PROJECTS, rbac.ACTION_UPDATE),
    ActionDef("project.delete", "delete a project", rbac.RESOURCE_PROJECTS, rbac.ACTION_DELETE),
    ActionDef("cluster.get", "view a cluster", rbac.RESOURCE_CLUSTERS, rbac.ACTION_GET),
    ActionDef("cluster.create", "add a cluster", rbac.RESOURCE_CLUSTERS, rbac.ACTION_CREATE),
    ActionDef("cluster.update", "update a cluster", rbac.RESOURCE_CLUSTERS, rbac.ACTION_UPDATE),
    ActionDef("cluster.delete", "remove a cluster", rbac.RESOURCE_CLUSTERS, rbac.ACTION_DELETE),
    ActionDef("repo.get", "view a repository", rbac.RESOURCE_REPOSITORIES, rbac.ACTION_GET),
    ActionDef("repo.create", "add a repository", rbac.RESOURCE_REPOSITORIES, rbac.ACTION_CREATE),
    ActionDef("repo.update", "update a repository", rbac.RESOURCE_REPOSITORIES, rbac.ACTION_UPDATE),
    ActionDef("repo.delete", "remove a repository", rbac.RESOURCE_REPOSITORIES, rbac.ACTION_DELETE),
    ActionDef("writerepo.get", "view a write repository", rbac.RESOURCE_WRITE_REPOSITORIES, rbac.ACTION_GET),
    ActionDef("writerepo.create", "add a write repository", rbac.RESOURCE_WRITE_REPOSITORIES, rbac.ACTION_CREATE),
    ActionDef("writerepo.update", "update a write repository", rbac.RESOURCE_WRITE_REPOSITORIES, rbac.ACTION_UPDATE),
    ActionDef("writerepo.delete", "remove a write repository", rbac.RESOURCE_WRITE_REPOSITORIES, rbac.ACTION_DELETE),
    ActionDef("certificate.get", "view a certificate", rbac.RESOURCE_CERTIFICATES, rbac.ACTION_GET),
    ActionDef("certificate.create", "add a certificate", rbac.RESOURCE_CERTIFICATES, rbac.ACTION_CREATE),
    ActionDef("certificate.update", "update a certificate", rbac.RESOURCE_CERTIFICATES, rbac.ACTION_UPDATE),
    ActionDef("certificate.delete", "remove a certificate", rbac.RESOURCE_CERTIFICATES, rbac.ACTION_DELETE),
    ActionDef("account.get", "view an account", rbac.RESOURCE_ACCOUNTS, rbac.ACTION_GET),
    ActionDef("account.update", "update an account", rbac.RESOURCE_ACCOUNTS, rbac.ACTION_UPDATE),
    ActionDef("gpgkey.get", "view a GPG key", rbac.RESOURCE_GPG_KEYS, rbac.ACTION_GET),
    ActionDef("gpgkey.create", "add a GPG key", rbac.RESOURCE_GPG_KEYS, rbac.ACTION_CREATE),
    ActionDef("gpgkey.delete", "remove a GPG key", rbac.RESOURCE_GPG_KEYS, rbac.ACTION_DELETE),
    ActionDef("extension.invoke", "invoke an extension", rbac.RESOURCE_EXTENSIONS, rbac.ACTION_INVOKE),
)

ACTIONS: dict[str, ActionDef] = {a.name: a for a in ACTION_LIST}

# Maps hallpass resource types to Argo CD resources.
RESOURCE_TYPES: dict[str, str] = {
    "applications": rbac.RESOURCE_APPLICATIONS,
    "applicationsets": rbac.RESOURCE_APPLICATION_SETS,
    "logs": rbac.RESOURCE_LOGS,
    "exec": rbac.RESOURCE_EXEC,
    "projects": rbac.RESOURCE_PROJECTS,
    "clusters": rbac.RESOURCE_CLUSTERS,
    "repositories": rbac.RESOURCE_REPOSITORIES,
    "write_repositories": rbac.RESOURCE_WRITE_REPOSITORIES,
    "certificates": rbac.RESOURCE_CERTIFICATES,
    "accounts": rbac.RESOURCE_ACCOUNTS,
    "gpgkeys": rbac.RESOURCE_GPG_KEYS,
    "extensions": rbac.RESOURCE_EXTENSIONS,
}


@dataclass
class EnforceRequest:
    """What goes into the enforcer."""

    res: str
    act: str
    obj: str = ""
    # Fine-grained update/delete carry the top-level verb for v2 inheritance.
    fine_grained: bool = False
    top_act: str = ""


SEGMENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")
# Bounds the object string. It is matched as a value, never as a pattern,
# so it only needs to be printable. Always used with fullmatch.
OBJ_RE = re.compile(r"[^\x00-\x20\x7f]{1,512}")


def parse_pattern(name: str) -> EnforceRequest | None:
    """Recognise app.action/<g>/<k>/<a>, app.update/<g>/<k>/<ns>/<n> and
    app.delete/<g>/<k>/<ns>/<n>."""
    prefix, sep, rest = name.partition("/")
    if not sep:
        return None
    parts = rest.split("/")
    for p in parts:
        if p != "" and SEGMENT_RE.fullmatch(p) is None:
            return None
    if prefix == "app.action":
        if len(parts) != 3 or parts[1] == "" or parts[2] == "":
            return None
        return EnforceRequest(res=rbac.RESOURCE_APPLICATIONS, act=rbac.ACTION_ACTION + "/" + rest)
    if prefix in ("app.update", "app.delete"):
        if len(parts) != 4 or parts[1] == "" or parts[3] == "":
            return None
        verb = prefix[len("app.") :]
        return EnforceRequest(res=rbac.RESOURCE_APPLICATIONS, act=verb + "/" + rest, fine_grained=True, top_act=verb)
    return None


def build_request(action_name: str, res: Resource) -> EnforceRequest:
    """Combine the action and the resource. Raises ValueError."""
    a = ACTIONS.get(action_name)
    if a is not None:
        req = EnforceRequest(res=a.res, act=a.act)
    else:
        p = parse_pattern(action_name)
        if p is None:
            raise ValueError(f"unknown action {go_quote(action_name)}")
        req = p
    argo_res = RESOURCE_TYPES.get(res.type)
    if argo_res is None:
        raise ValueError(
            f"resource type {go_quote(res.type)}; use one of applications, applicationsets, logs, exec, projects, clusters, repositories, "
            "write_repositories, certificates, accounts, gpgkeys, extensions"
        )
    # logs and exec take an applications resource too, since the object is the same.
    if argo_res != req.res and not (req.res in (rbac.RESOURCE_LOGS, rbac.RESOURCE_EXEC) and argo_res == rbac.RESOURCE_APPLICATIONS):
        raise ValueError(f"action {action_name} applies to {req.res}, but the resource is {res.type}")
    if res.id == "":
        raise ValueError("resource needs an id, e.g. applications:<project>/<name>")
    if OBJ_RE.fullmatch(res.id) is None:
        raise ValueError("resource id contains whitespace or control characters")
    if req.res in rbac.PROJECT_SCOPED and req.res not in (rbac.RESOURCE_CLUSTERS, rbac.RESOURCE_REPOSITORIES) and "/" not in res.id:
        raise ValueError(f"{res.type} resources are <project>/<name>")
    req.obj = res.id
    return req
