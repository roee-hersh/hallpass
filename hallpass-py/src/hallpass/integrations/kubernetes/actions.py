"""Named actions and the parsing of raw actions and resource references."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hallpass.core.catalog import Resource
from hallpass.core.errors import go_quote

__all__ = [
    "ALIASES",
    "ALIAS_LIST",
    "Alias",
    "Attributes",
    "RawSpec",
    "build_attributes",
    "join_res",
    "parse_raw",
    "split_resource",
]


@dataclass(frozen=True)
class Alias:
    """A named action that expands to a verb and resource. An empty
    resource means "take resource/group from the request"."""

    name: str
    desc: str
    verb: str
    resource: str = ""
    group: str = ""
    subresource: str = ""


ALIAS_LIST: tuple[Alias, ...] = (
    Alias("pods.exec", "run a command in a pod (create pods/exec)", "create", resource="pods", subresource="exec"),
    Alias("pods.logs", "read pod logs (get pods/log)", "get", resource="pods", subresource="log"),
    Alias("pods.portforward", "port-forward to a pod (create pods/portforward)", "create", resource="pods", subresource="portforward"),
    Alias("pods.attach", "attach to a pod (create pods/attach)", "create", resource="pods", subresource="attach"),
    Alias("scale", "scale the resource named in the request (update <resource>/scale)", "update", subresource="scale"),
    Alias("secrets.read", "read a secret (get secrets)", "get", resource="secrets"),
    Alias("secrets.list", "list secrets (list secrets)", "list", resource="secrets"),
    Alias("impersonate", "impersonate the subject named in the request, default users (impersonate <resource>)", "impersonate"),
    Alias("deployment.create", "create a deployment (create deployments.apps)", "create", resource="deployments", group="apps"),
    Alias("deployment.update", "update a deployment (update deployments.apps)", "update", resource="deployments", group="apps"),
    Alias("deployment.delete", "delete a deployment (delete deployments.apps)", "delete", resource="deployments", group="apps"),
    Alias("deployment.restart", "restart a deployment (patch deployments.apps)", "patch", resource="deployments", group="apps"),
    Alias("namespace.create", "create a namespace (create namespaces)", "create", resource="namespaces"),
    Alias("namespace.delete", "delete a namespace (delete namespaces)", "delete", resource="namespaces"),
    Alias("rbac.bind", "bind a role (create rolebindings.rbac.authorization.k8s.io)", "create", resource="rolebindings", group="rbac.authorization.k8s.io"),
)

ALIASES: dict[str, Alias] = {a.name: a for a in ALIAS_LIST}

# Go's regexps are anchored with ^...$ and have no trailing-newline
# exception; these are always used with fullmatch.
VERB_RE = re.compile(r"[a-z]{1,32}")
RESOURCE_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
GROUP_RE = re.compile(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")
NAME_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._:-]{0,252}[A-Za-z0-9])?")
NAMESPACE_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
PATH_RE = re.compile(r"/[A-Za-z0-9/._~*-]{0,1000}")


def _ok(r: re.Pattern[str], s: str) -> bool:
    return r.fullmatch(s) is not None


@dataclass(frozen=True)
class RawSpec:
    """A parsed raw:<verb>:<resource>[.<group>][/<subresource>] action."""

    verb: str
    resource: str = ""
    group: str = ""
    subresource: str = ""


def parse_raw(name: str) -> RawSpec:
    """Accept raw:<verb>:<resource>... and, for non-resource paths, the
    verb-only form raw:<verb>. Raises ValueError."""
    parts = name.split(":", 2)
    if len(parts) < 2 or parts[0] != "raw":
        raise ValueError("raw action must be raw:<verb>:<resource>[.<group>][/<subresource>] or raw:<verb> for non-resource paths")
    verb = parts[1]
    if not _ok(VERB_RE, verb):
        raise ValueError(f"verb {go_quote(verb)} must be lowercase letters")
    if len(parts) == 2:
        return RawSpec(verb=verb)
    res, group, sub = split_resource(parts[2])
    return RawSpec(verb=verb, resource=res, group=group, subresource=sub)


def split_resource(s: str) -> tuple[str, str, str]:
    """Parse "deployments.apps/scale" into resource, group and subresource.
    The group is everything after the first dot, as kubectl does."""
    if s == "":
        raise ValueError("resource is empty")
    res, _, sub = s.partition("/")
    res, _, group = res.partition(".")
    if not _ok(RESOURCE_RE, res):
        raise ValueError(f"resource {go_quote(res)} must be a lowercase plural such as pods or deployments")
    if group != "" and not _ok(GROUP_RE, group):
        raise ValueError(f"API group {go_quote(group)} is not a valid group name")
    if sub != "" and not _ok(RESOURCE_RE, sub):
        raise ValueError(f"subresource {go_quote(sub)} is not valid")
    return res, group, sub


@dataclass
class Attributes:
    """What goes into the review."""

    namespace: str = ""
    verb: str = ""
    group: str = ""
    resource: str = ""
    name: str = ""
    subresource: str = ""
    non_resource_path: str = ""


def build_attributes(action_name: str, res: Resource) -> Attributes:
    """Combine the action and the resource reference. Raises ValueError.

    namespace:<ns>[?resource=<res>[.<group>]&name=<n>&subresource=<s>]
    cluster[?resource=<res>[.<group>]&name=<n>&subresource=<s>]
    nonresource:<path>
    """
    a = Attributes()
    if action_name.startswith("raw:"):
        spec = parse_raw(action_name)
        a.verb, act_res, act_group, act_sub = spec.verb, spec.resource, spec.group, spec.subresource
    else:
        al = ALIASES.get(action_name)
        if al is None:
            raise ValueError(f"unknown action {go_quote(action_name)}")
        a.verb, act_res, act_group, act_sub = al.verb, al.resource, al.group, al.subresource

    if res.type == "nonresource":
        if not _ok(PATH_RE, res.id):
            raise ValueError(f"nonresource path {go_quote(res.id)} must start with / and contain only URL path characters")
        if act_res != "":
            raise ValueError(f"action {action_name} names a resource but the request is a non-resource path; use raw:<verb>")
        a.non_resource_path = res.id
        return a
    if res.type == "namespace":
        if not _ok(NAMESPACE_RE, res.id):
            raise ValueError(f"namespace {go_quote(res.id)} is not a valid namespace name")
        a.namespace = res.id
    elif res.type == "cluster":
        if res.id != "":
            raise ValueError("cluster resources take no id: use cluster?resource=nodes")
    else:
        raise ValueError(f"resource type {go_quote(res.type)}; use namespace:<ns>, cluster or nonresource:<path>")

    req_res, req_group, req_sub = "", "", ""
    q = res.q("resource")
    if q != "":
        req_res, req_group, req_sub = split_resource(q)
    s = res.q("subresource")
    if s != "":
        if not _ok(RESOURCE_RE, s):
            raise ValueError(f"subresource {go_quote(s)} is not valid")
        req_sub = s
    n = res.q("name")
    if n != "":
        if not _ok(NAME_RE, n):
            raise ValueError(f"name {go_quote(n)} is not a valid object name")
        a.name = n
    if res.q("namespace") != "":
        raise ValueError("put the namespace in the resource id: namespace:<ns>")

    if act_res != "" and req_res != "" and (act_res != req_res or act_group != req_group):
        raise ValueError(f"action {action_name} targets {join_res(act_res, act_group)} but the request names {join_res(req_res, req_group)}")
    if act_res != "":
        a.resource, a.group = act_res, act_group
    elif req_res != "":
        a.resource, a.group = req_res, req_group
    elif action_name == "impersonate":
        a.resource = "users"
    elif action_name.startswith("raw:") and ":" not in action_name[4:]:
        raise ValueError(f"action {action_name} is the non-resource form; use it with nonresource:<path>, or add ?resource=<plural>[.<group>] to the request")
    else:
        raise ValueError(f"action {action_name} needs a resource: add ?resource=<plural>[.<group>] to the request")
    if act_sub != "" and req_sub != "" and act_sub != req_sub:
        raise ValueError(f"action {action_name} targets subresource {act_sub} but the request names {req_sub}")
    a.subresource = act_sub if act_sub != "" else req_sub
    return a


def join_res(res: str, group: str) -> str:
    if group == "":
        return res
    return res + "." + group
