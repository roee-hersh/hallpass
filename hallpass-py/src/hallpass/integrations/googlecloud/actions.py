"""The googlecloud action table, the raw:<permission> pattern and the
resource to full-resource-name mapping."""

from __future__ import annotations

import re
from dataclasses import dataclass

from hallpass.core.catalog import Action, Resource, go_bytes
from hallpass.core.decision import Code, HallpassError, errorf
from hallpass.core.errors import go_lower, go_quote

__all__ = [
    "ACTION_INDEX",
    "ACTION_LIST",
    "HIERARCHY_TYPES",
    "MAX_PIECE",
    "PERMISSION_RE",
    "PERMISSION_V2_RE",
    "RAW_PATTERN",
    "SET_IAM_POLICY_PERMISSIONS",
    "ActionDef",
    "Ref",
    "catalog_actions",
    "full_resource_name",
    "has_dot_segment",
    "is_object_name",
    "is_project",
    "match_action",
    "parse_raw",
    "parse_ref",
    "well_formed",
]


@dataclass(frozen=True)
class ActionDef:
    """One named question and the IAM permission it asks about."""

    name: str
    desc: str
    # The IAM permission, or "" for iam.set whose permission depends on the
    # resource type.
    permission: str
    # The resource types the action is meant for. project, folder,
    # organization and name are accepted by every action: a permission can
    # be checked at any level of the hierarchy.
    types: tuple[str, ...]


ACTION_LIST: tuple[ActionDef, ...] = (
    ActionDef("project.view", "see a project (resourcemanager.projects.get)", "resourcemanager.projects.get", ("project",)),
    ActionDef(
        "iam.set",
        "change the IAM policy of the resource (<type>.setIamPolicy)",
        "",
        ("project", "folder", "organization", "bucket", "secret", "serviceaccount", "table"),
    ),
    ActionDef("storage.read", "read objects (storage.objects.get)", "storage.objects.get", ("bucket", "object")),
    ActionDef("storage.write", "create objects (storage.objects.create)", "storage.objects.create", ("bucket", "object")),
    ActionDef("storage.delete", "delete objects (storage.objects.delete)", "storage.objects.delete", ("bucket", "object")),
    ActionDef("storage.list", "list objects (storage.objects.list)", "storage.objects.list", ("bucket",)),
    ActionDef("bucket.delete", "delete a bucket (storage.buckets.delete)", "storage.buckets.delete", ("bucket",)),
    ActionDef("bigquery.read", "read table data (bigquery.tables.getData)", "bigquery.tables.getData", ("dataset", "table")),
    ActionDef("bigquery.write", "change table data (bigquery.tables.updateData)", "bigquery.tables.updateData", ("dataset", "table")),
    ActionDef("bigquery.delete", "delete a table (bigquery.tables.delete)", "bigquery.tables.delete", ("dataset", "table")),
    ActionDef("secret.read", "access secret versions (secretmanager.versions.access)", "secretmanager.versions.access", ("secret",)),
    ActionDef("serviceaccount.actas", "act as a service account (iam.serviceAccounts.actAs)", "iam.serviceAccounts.actAs", ("serviceaccount",)),
    ActionDef("compute.start", "start a VM (compute.instances.start)", "compute.instances.start", ("instance",)),
    ActionDef("compute.stop", "stop a VM (compute.instances.stop)", "compute.instances.stop", ("instance",)),
    ActionDef("compute.delete", "delete a VM (compute.instances.delete)", "compute.instances.delete", ("instance",)),
    ActionDef("run.deploy", "deploy a Cloud Run service (run.services.update)", "run.services.update", ("service",)),
    ActionDef("gke.access", "get a GKE cluster and its credentials (container.clusters.get)", "container.clusters.get", ("cluster",)),
)

ACTION_INDEX: dict[str, int] = {a.name: i for i, a in enumerate(ACTION_LIST)}

# The permission iam.set asks about per type.
SET_IAM_POLICY_PERMISSIONS = {
    "project": "resourcemanager.projects.setIamPolicy",
    "folder": "resourcemanager.folders.setIamPolicy",
    "organization": "resourcemanager.organizations.setIamPolicy",
    "bucket": "storage.buckets.setIamPolicy",
    "secret": "secretmanager.secrets.setIamPolicy",
    "serviceaccount": "iam.serviceAccounts.setIamPolicy",
    "table": "bigquery.tables.setIamPolicy",
}

# Accepted by every action besides its own types.
HIERARCHY_TYPES = frozenset({"project", "folder", "organization", "name"})

RAW_PATTERN = "raw:<permission>"


def catalog_actions() -> list[Action]:
    out = [
        Action(
            name=RAW_PATTERN,
            pattern=True,
            description="any IAM permission, e.g. raw:storage.objects.delete, raw:iam.serviceAccounts.actAs, raw:compute.instances.setMetadata",
        )
    ]
    for a in ACTION_LIST:
        out.append(Action(name=a.name, description=a.desc + " (" + ", ".join(a.types) + ")"))
    return out


# The v1 permission format (service.resource.verb) and the v2 one
# (service.googleapis.com/resource.verb). Go's ^...$, used with fullmatch.
PERMISSION_RE = re.compile(r"[a-z][a-zA-Z0-9]{0,63}(?:\.[a-zA-Z0-9]{1,64}){2,4}")
PERMISSION_V2_RE = re.compile(r"[a-z][a-z0-9-]{0,62}\.googleapis\.com/[a-zA-Z0-9]{1,64}(?:\.[a-zA-Z0-9]{1,64}){1,3}")


def match_action(name: str) -> Action | None:
    """Accept raw:<permission>."""
    try:
        parse_raw(name)
    except ValueError:
        return None
    return Action(name=RAW_PATTERN, pattern=True, description="IAM permission " + name.removeprefix("raw:"))


def parse_raw(name: str) -> str:
    if not name.startswith("raw:"):
        raise ValueError(f"unknown action {go_quote(name)}")
    p = name[len("raw:") :]
    if not PERMISSION_RE.fullmatch(p) and not PERMISSION_V2_RE.fullmatch(p):
        raise ValueError(f"raw action {go_quote(name)} must name an IAM permission such as storage.objects.get")
    return p


_PROJECT_ID_RE = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
_NUMBER_RE = re.compile(r"[0-9]{1,20}")
_BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]")
_DATASET_RE = re.compile(r"[A-Za-z0-9_]+")
_TABLE_RE = re.compile(r"[A-Za-z0-9_-]+")
_SECRET_RE = re.compile(r"[A-Za-z0-9_-]{1,255}")
_LOCATION_RE = re.compile(r"[a-z0-9-]{1,63}")
_SHORT_NAME_RE = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
_SA_EMAIL_RE = re.compile(r"([a-z][a-z0-9-]{4,28}[a-z0-9])@([a-z][a-z0-9-]{4,28}[a-z0-9])\.iam\.gserviceaccount\.com")
# The start of every full resource name: a googleapis.com service host
# followed by a path (a prefix match).
_HOST_RE = re.compile(r"//[a-z][a-z0-9-]{0,62}\.googleapis\.com/.")
# Restricts the path of a name: resource, which arrives verbatim, to the
# characters Google's documented full resource names use.
_NAME_CHARS_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._@:/+=~-]*")

# Bounds every name the regexes above leave unbounded (object names, dataset
# and table ids, full resource names). catalog caps the whole resource at
# 1024 bytes already; this keeps each piece explicit.
MAX_PIECE = 1024


def _blen(s: str) -> int:
    """len(s) in bytes, as Go counts it."""
    return len(go_bytes(s))


def _within(rx: re.Pattern[str], s: str) -> bool:
    """s matches rx and is at most MAX_PIECE bytes."""
    return _blen(s) <= MAX_PIECE and rx.fullmatch(s) is not None


def is_project(s: str) -> bool:
    """A project id (6-30 lowercase letters, digits and hyphens) or a
    project number."""
    return _PROJECT_ID_RE.fullmatch(s) is not None or _NUMBER_RE.fullmatch(s) is not None


def is_object_name(s: str) -> bool:
    """A Cloud Storage object name: any bytes but control characters, at
    most 1024 bytes, without "." or ".." segments. The name only ever
    travels inside a JSON body."""
    if s == "" or _blen(s) > MAX_PIECE:
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in s):
        return False
    return not has_dot_segment(s)


def has_dot_segment(s: str) -> bool:
    """Whether any "/"-separated segment is "." or ".."."""
    return any(seg in (".", "..") for seg in s.split("/"))


def well_formed(full: str) -> bool:
    """The invariant every full resource name hallpass sends satisfies,
    whichever type built it: a googleapis.com host, no control characters,
    no dot segments, at most MAX_PIECE bytes."""
    if _blen(full) > MAX_PIECE or not _HOST_RE.match(full) or has_dot_segment(full):
        return False
    return not any(ord(c) < 0x20 or ord(c) == 0x7F for c in full)


def _invalid(text: str) -> HallpassError:
    return errorf(Code.INVALID_REQUEST, text)


@dataclass(frozen=True)
class Ref:
    """One parsed question: the permission and the full resource name."""

    permission: str
    resource: str


def parse_ref(action_name: str, r: Resource) -> Ref:
    """Validate the action and the resource and build the access tuple."""
    if r.query:
        raise _invalid(f"resource {go_quote(r.raw)} must not carry a query")
    full = full_resource_name(r)
    if not well_formed(full):
        raise _invalid(f"resource {go_quote(r.raw)} does not form a valid full resource name")
    if action_name.startswith("raw:"):
        try:
            return Ref(parse_raw(action_name), full)
        except ValueError as e:
            raise _invalid(str(e)) from None
    i = ACTION_INDEX.get(action_name)
    if i is None:
        raise _invalid(f"unknown action {go_quote(action_name)}")
    a = ACTION_LIST[i]
    if a.name == "iam.set":
        p = SET_IAM_POLICY_PERMISSIONS.get(r.type)
        if p is None:
            if r.type == "name":
                raise _invalid("iam.set needs a typed resource to pick the setIamPolicy permission; use raw:<service>.<type>.setIamPolicy with name:")
            raise _invalid(f"iam.set is not defined for {r.type}: resources")
        return Ref(p, full)
    if r.type not in a.types and r.type not in HIERARCHY_TYPES:
        raise _invalid(f"action {a.name} takes {', '.join(a.types)} or a project, folder, organization or name resource, not {r.type}:")
    return Ref(a.permission, full)


def full_resource_name(r: Resource) -> str:
    """A hallpass resource as a full resource name.

    project:<id>                         //cloudresourcemanager.googleapis.com/projects/<id>
    folder:<number>                      //cloudresourcemanager.googleapis.com/folders/<number>
    organization:<number>                //cloudresourcemanager.googleapis.com/organizations/<number>
    bucket:<name>                        //storage.googleapis.com/projects/_/buckets/<name>
    object:<bucket>/<name>               //storage.googleapis.com/projects/_/buckets/<bucket>/objects/<name>
    dataset:<project>/<dataset>          //bigquery.googleapis.com/projects/<p>/datasets/<d>
    table:<project>/<dataset>/<table>    //bigquery.googleapis.com/projects/<p>/datasets/<d>/tables/<t>
    secret:<project>/<name>              //secretmanager.googleapis.com/projects/<p>/secrets/<name>
    serviceaccount:<email>               //iam.googleapis.com/projects/<p>/serviceAccounts/<email>
    instance:<project>/<zone>/<name>     //compute.googleapis.com/projects/<p>/zones/<z>/instances/<name>
    service:<project>/<location>/<name>  //run.googleapis.com/projects/<p>/locations/<l>/services/<name>
    cluster:<project>/<location>/<name>  //container.googleapis.com/projects/<p>/locations/<l>/clusters/<name>
    name:<full resource name>            verbatim
    """
    id, t = r.id, r.type
    if t == "project":
        if not is_project(id):
            raise _invalid("project: id must be a project id (6-30 lowercase letters, digits and hyphens) or a project number")
        return "//cloudresourcemanager.googleapis.com/projects/" + id
    if t in ("folder", "organization"):
        if not _NUMBER_RE.fullmatch(id):
            raise _invalid(f"{t}: id must be a number")
        return "//cloudresourcemanager.googleapis.com/" + t + "s/" + id
    if t == "bucket":
        if not _BUCKET_RE.fullmatch(id):
            raise _invalid("bucket: id must be a bucket name")
        return "//storage.googleapis.com/projects/_/buckets/" + id
    if t == "object":
        bucket, sep, obj = id.partition("/")
        if not sep or not _BUCKET_RE.fullmatch(bucket) or not is_object_name(obj):
            raise _invalid("object: id must be <bucket>/<object name>, without . or .. segments")
        return "//storage.googleapis.com/projects/_/buckets/" + bucket + "/objects/" + obj
    if t == "dataset":
        parts = id.split("/")
        if len(parts) != 2 or not is_project(parts[0]) or not _within(_DATASET_RE, parts[1]):
            raise _invalid("dataset: id must be <project>/<dataset>")
        return "//bigquery.googleapis.com/projects/" + parts[0] + "/datasets/" + parts[1]
    if t == "table":
        parts = id.split("/")
        if len(parts) != 3 or not is_project(parts[0]) or not _within(_DATASET_RE, parts[1]) or not _within(_TABLE_RE, parts[2]):
            raise _invalid("table: id must be <project>/<dataset>/<table>")
        return "//bigquery.googleapis.com/projects/" + parts[0] + "/datasets/" + parts[1] + "/tables/" + parts[2]
    if t == "secret":
        parts = id.split("/")
        if len(parts) != 2 or not is_project(parts[0]) or not _SECRET_RE.fullmatch(parts[1]):
            raise _invalid("secret: id must be <project>/<secret name>")
        return "//secretmanager.googleapis.com/projects/" + parts[0] + "/secrets/" + parts[1]
    if t == "serviceaccount":
        m = _SA_EMAIL_RE.fullmatch(go_lower(id))
        if m is None:
            raise _invalid("serviceaccount: id must be a <name>@<project>.iam.gserviceaccount.com address; use name: for Google-managed accounts")
        return "//iam.googleapis.com/projects/" + m.group(2) + "/serviceAccounts/" + go_lower(id)
    if t in ("instance", "service", "cluster"):
        parts = id.split("/")
        if len(parts) != 3 or not is_project(parts[0]) or not _LOCATION_RE.fullmatch(parts[1]) or not _SHORT_NAME_RE.fullmatch(parts[2]):
            raise _invalid(f"{t}: id must be <project>/<location>/<name>")
        if t == "instance":
            return "//compute.googleapis.com/projects/" + parts[0] + "/zones/" + parts[1] + "/instances/" + parts[2]
        if t == "service":
            return "//run.googleapis.com/projects/" + parts[0] + "/locations/" + parts[1] + "/services/" + parts[2]
        return "//container.googleapis.com/projects/" + parts[0] + "/locations/" + parts[1] + "/clusters/" + parts[2]
    if t == "name":
        host, _, path = id.removeprefix("//").partition("/")
        if not well_formed(id) or host == "" or not _NAME_CHARS_RE.fullmatch(path):
            raise _invalid("name: id must be a full resource name such as //cloudresourcemanager.googleapis.com/projects/my-project")
        return id
    raise _invalid(
        f"resource type {go_quote(t)} is not one of project, folder, organization, bucket, object, dataset, "
        "table, secret, serviceaccount, instance, service, cluster, name"
    )
