package snowflake

import (
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// objectKind describes a resource type: the granted_on values SHOW GRANTS
// uses for it and how many dotted parts its name has.
type objectKind struct {
	// grantedOn are the SHOW GRANTS granted_on values the kind covers.
	grantedOn []string
	parts     int
}

var kinds = map[string]objectKind{
	// table: covers every relation SELECT and DML apply to.
	"table":     {[]string{"TABLE", "VIEW", "MATERIALIZED VIEW", "EXTERNAL TABLE", "DYNAMIC TABLE", "EVENT TABLE", "ICEBERG TABLE", "HYBRID TABLE"}, 3},
	"schema":    {[]string{"SCHEMA"}, 2},
	"database":  {[]string{"DATABASE"}, 1},
	"warehouse": {[]string{"WAREHOUSE"}, 1},
	"role":      {[]string{"ROLE"}, 1},
	"account":   {[]string{"ACCOUNT"}, 0},
}

// action is one named question: a privilege on a kind of object.
type action struct {
	name, desc, kind string
	// privileges any of which answers the question; OWNERSHIP always does.
	privileges []string
}

var actionList = []action{
	{"table.select", "read the table or view", "table", []string{"SELECT"}},
	{"table.insert", "insert rows", "table", []string{"INSERT"}},
	{"table.update", "update rows", "table", []string{"UPDATE"}},
	{"table.delete", "delete rows", "table", []string{"DELETE"}},
	{"table.truncate", "truncate the table", "table", []string{"TRUNCATE"}},
	{"schema.usage", "use the schema", "schema", []string{"USAGE"}},
	{"schema.create_table", "create tables in the schema", "schema", []string{"CREATE TABLE"}},
	{"schema.create_view", "create views in the schema", "schema", []string{"CREATE VIEW"}},
	{"database.usage", "use the database", "database", []string{"USAGE"}},
	{"database.create_schema", "create schemas in the database", "database", []string{"CREATE SCHEMA"}},
	{"warehouse.usage", "run queries on the warehouse", "warehouse", []string{"USAGE"}},
	{"warehouse.operate", "start, suspend and resize the warehouse", "warehouse", []string{"OPERATE"}},
	{"warehouse.modify", "alter the warehouse", "warehouse", []string{"MODIFY"}},
	{"role.use", "activate the role (granted directly or through another role)", "role", nil},
	{"account.create_database", "create databases", "account", []string{"CREATE DATABASE"}},
	{"account.manage_grants", "grant and revoke privileges on any object", "account", []string{"MANAGE GRANTS"}},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

const rawPattern = "raw:<privilege>"

// Actions of the snowflake integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList)+1)
	for _, a := range actionList {
		desc := a.desc
		if len(a.privileges) > 0 {
			desc += " (" + strings.Join(a.privileges, " or ") + ")"
		}
		out = append(out, catalog.Action{Name: a.name, Description: desc + " on " + a.kind + ":"})
	}
	out = append(out, catalog.Action{Name: rawPattern, Pattern: true,
		Description: "any privilege on a typed resource, e.g. raw:REFERENCES on table:, raw:CREATE_STAGE on schema:, raw:MONITOR on warehouse:"})
	return out
}

// privilegeRe is a privilege name as raw: spells it: upper-case words
// joined by underscores.
var privilegeRe = regexp.MustCompile(`^[A-Z][A-Z_]{1,62}$`)

// parseRaw parses raw:<PRIVILEGE>.
func parseRaw(name string) (action, bool) {
	p, ok := strings.CutPrefix(name, "raw:")
	if !ok || !privilegeRe.MatchString(p) || strings.Contains(p, "__") || strings.HasSuffix(p, "_") {
		return action{}, false
	}
	priv := strings.ReplaceAll(p, "_", " ")
	if priv == "OWNERSHIP" {
		return action{}, false
	}
	return action{name: name, desc: "hold " + priv, privileges: []string{priv}}, true
}

// MatchAction accepts raw:<PRIVILEGE>.
func (Integration) MatchAction(name string) (catalog.Action, bool) {
	a, ok := parseRaw(name)
	if !ok {
		return catalog.Action{}, false
	}
	return catalog.Action{Name: rawPattern, Pattern: true, Description: a.desc}, true
}

func invalid(format string, args ...any) error {
	return integration.Errorf(integration.CodeInvalidRequest, format, args...)
}

// target is a parsed question.
type target struct {
	action action
	kind   string
	// name is the object's resolved dotted name; nil for account.
	name []string
}

// parseTarget validates the action and resource.
func parseTarget(actionName string, r catalog.Resource) (target, error) {
	a, ok := actions[actionName]
	if !ok {
		if a, ok = parseRaw(actionName); !ok {
			return target{}, invalid("unknown action %q", actionName)
		}
		a.kind = r.Type
	}
	if len(r.Query) > 0 {
		return target{}, invalid("resource %q must not carry a query", r.Raw)
	}
	k, ok := kinds[r.Type]
	if !ok {
		return target{}, invalid("resource type %q is not table:, schema:, database:, warehouse:, role: or account", r.Type)
	}
	if a.kind != r.Type {
		return target{}, invalid("action %s takes a %s: resource, not %s:", a.name, a.kind, r.Type)
	}
	if r.Type == "role" && strings.HasPrefix(actionName, "raw:") {
		return target{}, invalid("raw: privileges do not apply to role:; use role.use")
	}
	t := target{action: a, kind: r.Type}
	if k.parts == 0 {
		if strings.TrimSpace(r.ID) != "" {
			return target{}, invalid("account takes no id")
		}
		return t, nil
	}
	name, err := parseName(r.ID, k.parts)
	if err != nil {
		return target{}, invalid("%s: %v", r.Type, err)
	}
	t.name = name
	return t, nil
}

// String names the target for decision texts.
func (t target) String() string {
	if t.kind == "account" {
		return "the account"
	}
	return t.kind + " " + quoteName(t.name)
}
