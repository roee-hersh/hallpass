package salesforce

import (
	"fmt"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// kind groups actions by the Salesforce object that answers them.
type kind int

const (
	kindRecord  kind = iota // UserRecordAccess
	kindObject              // ObjectPermissions
	kindField               // FieldPermissions
	kindSystem              // PermissionSet.PermissionsXxx
	kindPermSet             // PermissionSetAssignment
	kindUser                // the User row itself
)

// action is one entry of the table.
type action struct {
	name, desc string
	kind       kind
	// column is the boolean the action reads from the answering object
	// (HasReadAccess, PermissionsCreate, ...). Empty for kindSystem,
	// kindPermSet and kindUser.
	column string
}

var actionList = []action{
	{name: "record.read", desc: "read a record (UserRecordAccess.HasReadAccess)", kind: kindRecord, column: "HasReadAccess"},
	{name: "record.edit", desc: "edit a record (UserRecordAccess.HasEditAccess)", kind: kindRecord, column: "HasEditAccess"},
	{name: "record.delete", desc: "delete a record (UserRecordAccess.HasDeleteAccess)", kind: kindRecord, column: "HasDeleteAccess"},
	{name: "record.transfer", desc: "transfer a record's ownership (UserRecordAccess.HasTransferAccess)", kind: kindRecord, column: "HasTransferAccess"},
	{name: "record.share", desc: "share a record, i.e. full access (UserRecordAccess.HasAllAccess)", kind: kindRecord, column: "HasAllAccess"},
	{name: "object.read", desc: "read the object (ObjectPermissions.PermissionsRead)", kind: kindObject, column: "PermissionsRead"},
	{name: "object.create", desc: "create records of the object (ObjectPermissions.PermissionsCreate)", kind: kindObject, column: "PermissionsCreate"},
	{name: "object.edit", desc: "edit records of the object (ObjectPermissions.PermissionsEdit)", kind: kindObject, column: "PermissionsEdit"},
	{name: "object.delete", desc: "delete records of the object (ObjectPermissions.PermissionsDelete)", kind: kindObject, column: "PermissionsDelete"},
	{name: "object.view_all", desc: "view all records of the object (ObjectPermissions.PermissionsViewAllRecords)", kind: kindObject, column: "PermissionsViewAllRecords"},
	{name: "object.modify_all", desc: "modify all records of the object (ObjectPermissions.PermissionsModifyAllRecords)", kind: kindObject, column: "PermissionsModifyAllRecords"},
	{name: "field.read", desc: "read a field (FieldPermissions.PermissionsRead)", kind: kindField, column: "PermissionsRead"},
	{name: "field.edit", desc: "edit a field (FieldPermissions.PermissionsEdit)", kind: kindField, column: "PermissionsEdit"},
	{name: "system.permission", desc: "hold a system or app permission through any assigned profile or permission set (PermissionSet.PermissionsXxx)", kind: kindSystem},
	{name: "permset.assigned", desc: "be assigned a permission set by API name (PermissionSetAssignment)", kind: kindPermSet},
	{name: "user.active", desc: "be an active, unfrozen user", kind: kindUser},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

// target is a parsed and validated resource. Every field is safe to place
// in a SOQL statement without further escaping: ids and API names are
// regex-validated, email is validated and escaped by the caller.
type target struct {
	recordID string // record:<Id>
	object   string // object:<ApiName>, field:<Object>.<Field>
	field    string // field:<Object>.<Field>
	perm     string // permission:<PermissionsXxx>
	permSet  string // permset:<ApiName>
	email    string // user:<email>, raw (not escaped)
}

// parseTarget validates the resource against what the action needs.
//
//	record:<Id>                     record.*, user.active
//	object:<ApiName>                object.*
//	field:<Object>.<Field>          field.*
//	permission:<PermissionsXxx>     system.permission
//	permset:<ApiName>               permset.assigned
//	user:<email>                    user.active
func parseTarget(a action, res catalog.Resource) (target, error) {
	var t target
	if len(res.Query) > 0 {
		return t, fmt.Errorf("resource %q takes no query parameters", res.Raw)
	}
	switch a.kind {
	case kindRecord:
		if res.Type != "record" {
			return t, fmt.Errorf("action %s needs a record:<Id> resource, not %s:", a.name, res.Type)
		}
		if err := validateID(res.ID); err != nil {
			return t, err
		}
		t.recordID = res.ID
	case kindObject:
		if res.Type != "object" {
			return t, fmt.Errorf("action %s needs an object:<ApiName> resource, not %s:", a.name, res.Type)
		}
		if err := validateAPIName(res.ID); err != nil {
			return t, err
		}
		t.object = res.ID
	case kindField:
		if res.Type != "field" {
			return t, fmt.Errorf("action %s needs a field:<Object>.<Field> resource, not %s:", a.name, res.Type)
		}
		obj, field, ok := strings.Cut(res.ID, ".")
		if !ok {
			return t, fmt.Errorf("field resource %q must be field:<Object>.<Field>", res.Raw)
		}
		if err := validateAPIName(obj); err != nil {
			return t, fmt.Errorf("object: %w", err)
		}
		if err := validateAPIName(field); err != nil {
			return t, fmt.Errorf("field: %w", err)
		}
		t.object, t.field = obj, field
	case kindSystem:
		if res.Type != "permission" {
			return t, fmt.Errorf("action %s needs a permission:<PermissionsXxx> resource, not %s:", a.name, res.Type)
		}
		if err := validatePermissionName(res.ID); err != nil {
			return t, err
		}
		t.perm = res.ID
	case kindPermSet:
		if res.Type != "permset" {
			return t, fmt.Errorf("action %s needs a permset:<ApiName> resource, not %s:", a.name, res.Type)
		}
		if err := validateAPIName(res.ID); err != nil {
			return t, err
		}
		t.permSet = res.ID
	case kindUser:
		switch res.Type {
		case "user":
			if err := validateEmail(res.ID); err != nil {
				return t, err
			}
			t.email = res.ID
		case "record":
			if err := validateID(res.ID); err != nil {
				return t, err
			}
			t.recordID = res.ID
		default:
			return t, fmt.Errorf("action %s needs a user:<email> or record:<UserId> resource, not %s:", a.name, res.Type)
		}
	}
	return t, nil
}
