"""The azure integration's actions (named Azure operations, raw:<operation>
and data:<operation>) and the scopes they are asked about."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hallpass.core.catalog import Action, Resource
from hallpass.core.decision import Code, HallpassError, errorf
from hallpass.core.errors import go_lower, go_quote, go_trim_space

__all__ = [
    "ACTIONS",
    "ACTION_LIST",
    "DATA_PATTERN",
    "GUID_RE",
    "OPERATION_RE",
    "RAW_PATTERN",
    "AzAction",
    "Target",
    "catalog_actions",
    "dots",
    "equal_fold",
    "match_action",
    "parse_raw",
    "parse_resource_id",
    "parse_target",
]


@dataclass(frozen=True)
class AzAction:
    """One named question: an Azure operation on the control plane
    (actions) or the data plane (dataActions)."""

    name: str
    desc: str
    operation: str
    data: bool


ACTION_LIST: tuple[AzAction, ...] = (
    AzAction("vm.read", "read the virtual machine", "Microsoft.Compute/virtualMachines/read", False),
    AzAction("vm.start", "start the virtual machine", "Microsoft.Compute/virtualMachines/start/action", False),
    AzAction("vm.restart", "restart the virtual machine", "Microsoft.Compute/virtualMachines/restart/action", False),
    AzAction("vm.deallocate", "deallocate (stop) the virtual machine", "Microsoft.Compute/virtualMachines/deallocate/action", False),
    AzAction("vm.delete", "delete the virtual machine", "Microsoft.Compute/virtualMachines/delete", False),
    AzAction("storage.listkeys", "list the storage account's access keys", "Microsoft.Storage/storageAccounts/listkeys/action", False),
    AzAction("storage.blob.read", "read blobs (data plane)", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", True),
    AzAction("storage.blob.write", "write blobs (data plane)", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write", True),
    AzAction(
        "keyvault.secret.read",
        "read a Key Vault secret's value (data plane, RBAC permission model)",
        "Microsoft.KeyVault/vaults/secrets/getSecret/action",
        True,
    ),
    AzAction(
        "keyvault.secret.write",
        "set a Key Vault secret (data plane, RBAC permission model)",
        "Microsoft.KeyVault/vaults/secrets/setSecret/action",
        True,
    ),
    AzAction(
        "aks.admin_credentials",
        "fetch the AKS cluster admin credential",
        "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action",
        False,
    ),
    AzAction(
        "aks.user_credentials",
        "fetch the AKS cluster user credential",
        "Microsoft.ContainerService/managedClusters/listClusterUserCredential/action",
        False,
    ),
    AzAction("rbac.write", "create or change role assignments", "Microsoft.Authorization/roleAssignments/write", False),
    AzAction("resourcegroup.delete", "delete the resource group", "Microsoft.Resources/subscriptions/resourceGroups/delete", False),
    AzAction("deployment.write", "create or change an ARM deployment", "Microsoft.Resources/deployments/write", False),
)

ACTIONS: dict[str, AzAction] = {a.name: a for a in ACTION_LIST}

RAW_PATTERN = "raw:<operation>"
DATA_PATTERN = "data:<operation>"


def catalog_actions() -> list[Action]:
    out = [Action(name=a.name, description=a.desc + " (" + a.operation + ")") for a in ACTION_LIST]
    out.append(Action(name=RAW_PATTERN, pattern=True, description="any control-plane operation, e.g. raw:Microsoft.Network/publicIPAddresses/delete"))
    out.append(
        Action(
            name=DATA_PATTERN,
            pattern=True,
            description="any data-plane operation, e.g. data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
        )
    )
    return out


# A resource provider operation: a namespace, then resource types and a
# verb. Wildcards are for role definitions only. (fullmatch throughout: Go's
# $ never matches before a trailing newline.)
OPERATION_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*(\.[A-Za-z0-9]+)+(/[A-Za-z0-9][A-Za-z0-9_.-]*)+")


def parse_raw(name: str) -> AzAction | None:
    """raw:<operation> and data:<operation>."""
    for prefix in ("raw:", "data:"):
        if not name.startswith(prefix):
            continue
        op = name[len(prefix) :]
        if not OPERATION_RE.fullmatch(op) or len(op) > 256:
            return None
        return AzAction(name=name, desc="perform " + op, operation=op, data=prefix == "data:")
    return None


def match_action(name: str) -> Action | None:
    """Accepts raw:<operation> and data:<operation>."""
    a = parse_raw(name)
    if a is None:
        return None
    return Action(name=DATA_PATTERN if a.data else RAW_PATTERN, pattern=True, description=a.desc)


GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_RG_RE = re.compile(r"[-\w.()]{1,90}", re.ASCII)
_MG_RE = re.compile(r"[A-Za-z0-9_().-]{1,90}")
_NS_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*(\.[A-Za-z0-9]+)+")
_SEGMENT_RE = re.compile(r"[A-Za-z0-9_.()-]{1,260}")


def _fold(c: str) -> str:
    """One rune under simple case folding (its orbit's representative)."""
    f = c.casefold()
    if len(f) == 1:
        return f
    lo = c.lower()
    return lo if len(lo) == 1 else c


def equal_fold(a: str, b: str) -> bool:
    """Go's strings.EqualFold: equal under simple Unicode case folding."""
    if len(a) != len(b):
        return False
    return all(x == y or _fold(x) == _fold(y) for x, y in zip(a, b, strict=True))


def _invalid(text: str) -> HallpassError:
    return errorf(Code.INVALID_REQUEST, text)


@dataclass(frozen=True)
class Target:
    """A parsed question.

    scope is the ARM scope, leading slash included, exactly as ARM spells it
    in assignment scopes: /subscriptions/<id>/resourceGroups/<rg>/providers/...
    Every segment is limited to [-\\w.()], which needs no escaping in a URL
    path, so the same string is the request path. kind is managementgroup,
    subscription, resourcegroup or resource."""

    action: AzAction
    scope: str
    kind: str

    def __str__(self) -> str:
        return self.kind + " " + self.scope


def parse_target(action_name: str, r: Resource) -> Target:
    """Validate the action and build the scope from the resource."""
    a = ACTIONS.get(action_name)
    if a is None:
        a = parse_raw(action_name)
        if a is None:
            raise _invalid(f"unknown action {go_quote(action_name)}")
    if r.query:
        raise _invalid(f"resource {go_quote(r.raw)} must not carry a query")
    rid = go_trim_space(r.id)
    if r.type == "managementgroup":
        if not _MG_RE.fullmatch(rid) or dots(rid):
            raise _invalid("managementgroup: takes the group's name or id")
        scope = "/providers/Microsoft.Management/managementGroups/" + rid
    elif r.type == "subscription":
        if not GUID_RE.fullmatch(rid):
            raise _invalid("subscription: takes the subscription id (a GUID)")
        scope = "/subscriptions/" + go_lower(rid)
    elif r.type == "resourcegroup":
        sub, sep, rg = rid.partition("/")
        if not sep or not GUID_RE.fullmatch(sub) or not _RG_RE.fullmatch(rg) or rg.endswith("."):
            raise _invalid("resourcegroup: takes <subscription id>/<resource group name>")
        scope = "/subscriptions/" + go_lower(sub) + "/resourceGroups/" + rg
    elif r.type == "resource":
        scope = parse_resource_id(rid)
    else:
        raise _invalid(f"resource type {go_quote(r.type)} is not managementgroup:, subscription:, resourcegroup: or resource:")
    return Target(action=a, scope=scope, kind=r.type)


def parse_resource_id(rid: str) -> str:
    """A full ARM resource id:
    /subscriptions/<id>/resourceGroups/<rg>/providers/<ns>/<type>/<name>[/<type>/<name>...]"""
    segs = rid.removeprefix("/").split("/")
    if (
        len(segs) < 7
        or not equal_fold(segs[0], "subscriptions")
        or not GUID_RE.fullmatch(segs[1])
        or not equal_fold(segs[2], "resourceGroups")
        or not _RG_RE.fullmatch(segs[3])
        or segs[3].endswith(".")
        or not equal_fold(segs[4], "providers")
        or not _NS_RE.fullmatch(segs[5])
    ):
        raise _invalid("resource: takes a full ARM id /subscriptions/<id>/resourceGroups/<rg>/providers/<namespace>/<type>/<name>")
    rest = segs[6:]
    if len(rest) % 2 != 0:
        raise _invalid("resource: the id must end in <type>/<name> pairs")
    out = ["subscriptions", go_lower(segs[1]), "resourceGroups", segs[3], "providers", segs[5]]
    for seg in rest:
        if not _SEGMENT_RE.fullmatch(seg) or dots(seg):
            raise _invalid(f"resource: segment {go_quote(seg)} is not a resource type or name")
        out.append(seg)
    return "/" + "/".join(out)


def dots(seg: str) -> bool:
    """Whether a segment is made of dots only (., ..), which a front end may
    fold into the parent path."""
    return seg.strip(".") == ""
