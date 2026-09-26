"""The salesforce action table and resource parsing."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from hallpass.core.catalog import Resource
from hallpass.core.errors import go_quote
from hallpass.integrations.salesforce.soql import validate_api_name, validate_email, validate_id, validate_permission_name

__all__ = ["ACTIONS", "ACTION_LIST", "Kind", "SFAction", "Target", "parse_target"]


class Kind(IntEnum):
    """Groups actions by the Salesforce object that answers them."""

    RECORD = 0  # UserRecordAccess
    OBJECT = 1  # ObjectPermissions
    FIELD = 2  # FieldPermissions
    SYSTEM = 3  # PermissionSet.PermissionsXxx
    PERM_SET = 4  # PermissionSetAssignment
    USER = 5  # the User row itself


@dataclass(frozen=True)
class SFAction:
    """One entry of the table."""

    name: str
    desc: str
    kind: Kind
    # The boolean the action reads from the answering object (HasReadAccess,
    # PermissionsCreate, ...). Empty for SYSTEM, PERM_SET and USER.
    column: str = ""


ACTION_LIST: tuple[SFAction, ...] = (
    SFAction("record.read", "read a record (UserRecordAccess.HasReadAccess)", Kind.RECORD, "HasReadAccess"),
    SFAction("record.edit", "edit a record (UserRecordAccess.HasEditAccess)", Kind.RECORD, "HasEditAccess"),
    SFAction("record.delete", "delete a record (UserRecordAccess.HasDeleteAccess)", Kind.RECORD, "HasDeleteAccess"),
    SFAction("record.transfer", "transfer a record's ownership (UserRecordAccess.HasTransferAccess)", Kind.RECORD, "HasTransferAccess"),
    SFAction("record.share", "share a record, i.e. full access (UserRecordAccess.HasAllAccess)", Kind.RECORD, "HasAllAccess"),
    SFAction("object.read", "read the object (ObjectPermissions.PermissionsRead)", Kind.OBJECT, "PermissionsRead"),
    SFAction("object.create", "create records of the object (ObjectPermissions.PermissionsCreate)", Kind.OBJECT, "PermissionsCreate"),
    SFAction("object.edit", "edit records of the object (ObjectPermissions.PermissionsEdit)", Kind.OBJECT, "PermissionsEdit"),
    SFAction("object.delete", "delete records of the object (ObjectPermissions.PermissionsDelete)", Kind.OBJECT, "PermissionsDelete"),
    SFAction("object.view_all", "view all records of the object (ObjectPermissions.PermissionsViewAllRecords)", Kind.OBJECT, "PermissionsViewAllRecords"),
    SFAction(
        "object.modify_all", "modify all records of the object (ObjectPermissions.PermissionsModifyAllRecords)", Kind.OBJECT, "PermissionsModifyAllRecords"
    ),
    SFAction("field.read", "read a field (FieldPermissions.PermissionsRead)", Kind.FIELD, "PermissionsRead"),
    SFAction("field.edit", "edit a field (FieldPermissions.PermissionsEdit)", Kind.FIELD, "PermissionsEdit"),
    SFAction(
        "system.permission",
        "hold a system or app permission through any assigned profile or permission set (PermissionSet.PermissionsXxx)",
        Kind.SYSTEM,
    ),
    SFAction("permset.assigned", "be assigned a permission set by API name (PermissionSetAssignment)", Kind.PERM_SET),
    SFAction("user.active", "be an active, unfrozen user", Kind.USER),
)

ACTIONS: dict[str, SFAction] = {a.name: a for a in ACTION_LIST}


@dataclass
class Target:
    """A parsed and validated resource. Every field is safe to place in a
    SOQL statement without further escaping: ids and API names are
    regex-validated, email is validated and escaped by the caller."""

    record_id: str = ""  # record:<Id>
    object: str = ""  # object:<ApiName>, field:<Object>.<Field>
    field: str = ""  # field:<Object>.<Field>
    perm: str = ""  # permission:<PermissionsXxx>
    perm_set: str = ""  # permset:<Name> or permset:<ns>__<Name>: the Name part
    perm_set_ns: str = ""  # permset:<ns>__<Name>: the namespace prefix, "" for none
    email: str = ""  # user:<email>, raw (not escaped)

    def perm_set_full(self) -> str:
        """The permission set as it was asked for."""
        if self.perm_set_ns != "":
            return self.perm_set_ns + "__" + self.perm_set
        return self.perm_set


def parse_target(a: SFAction, res: Resource) -> Target:
    """Validate the resource against what the action needs; raise
    ValueError.

        record:<Id>                     record.*, user.active
        object:<ApiName>                object.*
        field:<Object>.<Field>          field.*
        permission:<PermissionsXxx>     system.permission
        permset:<ApiName>               permset.assigned (also permset:<ns>__<ApiName>)
        user:<email>                    user.active
    """
    t = Target()
    if res.query:
        raise ValueError(f"resource {go_quote(res.raw)} takes no query parameters")
    if a.kind == Kind.RECORD:
        if res.type != "record":
            raise ValueError(f"action {a.name} needs a record:<Id> resource, not {res.type}:")
        validate_id(res.id)
        t.record_id = res.id
    elif a.kind == Kind.OBJECT:
        if res.type != "object":
            raise ValueError(f"action {a.name} needs an object:<ApiName> resource, not {res.type}:")
        validate_api_name(res.id)
        t.object = res.id
    elif a.kind == Kind.FIELD:
        if res.type != "field":
            raise ValueError(f"action {a.name} needs a field:<Object>.<Field> resource, not {res.type}:")
        obj, dot, fld = res.id.partition(".")
        if not dot:
            raise ValueError(f"field resource {go_quote(res.raw)} must be field:<Object>.<Field>")
        try:
            validate_api_name(obj)
        except ValueError as e:
            raise ValueError(f"object: {e}") from None
        try:
            validate_api_name(fld)
        except ValueError as e:
            raise ValueError(f"field: {e}") from None
        t.object, t.field = obj, fld
    elif a.kind == Kind.SYSTEM:
        if res.type != "permission":
            raise ValueError(f"action {a.name} needs a permission:<PermissionsXxx> resource, not {res.type}:")
        validate_permission_name(res.id)
        t.perm = res.id
    elif a.kind == Kind.PERM_SET:
        if res.type != "permset":
            raise ValueError(f"action {a.name} needs a permset:<ApiName> or permset:<ns>__<ApiName> resource, not {res.type}:")
        # A managed package's set is <NamespacePrefix>__<Name>; developer
        # names themselves never contain two consecutive underscores, so the
        # first "__" is the separator.
        name = res.id
        ns, sep, rest = res.id.partition("__")
        if sep:
            try:
                validate_api_name(ns)
            except ValueError as e:
                raise ValueError(f"namespace prefix: {e}") from None
            if "__" in rest:
                raise ValueError(f"permset resource {go_quote(res.raw)} must be permset:<ApiName> or permset:<ns>__<ApiName>")
            t.perm_set_ns, name = ns, rest
        validate_api_name(name)
        t.perm_set = name
    elif a.kind == Kind.USER:
        if res.type == "user":
            validate_email(res.id)
            t.email = res.id
        elif res.type == "record":
            validate_id(res.id)
            t.record_id = res.id
        else:
            raise ValueError(f"action {a.name} needs a user:<email> or record:<UserId> resource, not {res.type}:")
    return t
