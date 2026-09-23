package datadog

import (
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// action is one named question: a permission the user's roles must carry
// and, for a restrictable asset, the relation a restriction policy or the
// asset's legacy restricted_roles must grant.
type action struct {
	name, desc string
	// resource is the type the action takes: monitor, dashboard, slo,
	// notebook or org.
	resource string
	// permission is the permission name one of the user's roles must hold.
	permission string
	// relation is what the asset's restriction must grant: "editor" for
	// changes, "viewer" for reads, "" for org-wide questions.
	relation string
}

var actionList = []action{
	{"monitor.edit", "change, delete or resolve the monitor (monitors_write)", "monitor", "monitors_write", "editor"},
	{"monitor.mute", "mute the monitor or set a downtime on it (monitors_downtime)", "monitor", "monitors_downtime", "editor"},
	{"monitor.read", "view the monitor (monitors_read)", "monitor", "monitors_read", "viewer"},
	{"dashboard.edit", "change or delete the dashboard (dashboards_write)", "dashboard", "dashboards_write", "editor"},
	{"dashboard.read", "view the dashboard (dashboards_read)", "dashboard", "dashboards_read", "viewer"},
	{"slo.edit", "change or delete the SLO (slos_write)", "slo", "slos_write", "editor"},
	{"notebook.edit", "change or delete the notebook (notebooks_write)", "notebook", "notebooks_write", "editor"},
	{"logs.read", "read log data (logs_read_data)", "org", "logs_read_data", ""},
	{"users.manage", "disable users and change roles (user_access_manage)", "org", "user_access_manage", ""},
	{"apikeys.manage", "create and change API keys (api_keys_write)", "org", "api_keys_write", ""},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

const rawPattern = "raw:<permission>"

// Actions of the datadog integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList)+1)
	out = append(out, catalog.Action{Name: rawPattern, Pattern: true,
		Description: "one permission by name on the org (raw:synthetics_write) or on a restrictable asset, where it must be the asset's write permission to be checked against its restrictions (raw:monitors_write on monitor:<id>)"})
	for _, a := range actionList {
		out = append(out, catalog.Action{Name: a.name, Description: a.desc + " (" + a.resource + ")"})
	}
	return out
}

var (
	permissionRe = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	// idRe is a Datadog asset id: numeric (monitors, notebooks) or
	// alphanumeric with hyphens and underscores (dashboards, SLOs).
	idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
)

// MatchAction accepts raw:<permission>.
func (Integration) MatchAction(name string) (catalog.Action, bool) {
	if _, err := parseRaw(name); err != nil {
		return catalog.Action{}, false
	}
	return catalog.Action{Name: rawPattern, Pattern: true, Description: "permission " + strings.TrimPrefix(name, "raw:")}, true
}

func parseRaw(name string) (string, error) {
	p, ok := strings.CutPrefix(name, "raw:")
	if !ok {
		return "", invalid("unknown action %q", name)
	}
	if !permissionRe.MatchString(p) {
		return "", invalid("raw action %q must name a permission such as monitors_write", name)
	}
	return p, nil
}

func invalid(format string, args ...any) error {
	return integration.Errorf(integration.CodeInvalidRequest, format, args...)
}

// assetTypes maps a resource type to the restriction policy resource type
// and the permission that writes it.
var assetTypes = map[string]struct {
	policyType      string
	writePermission string
}{
	"monitor":   {"monitor", "monitors_write"},
	"dashboard": {"dashboard", "dashboards_write"},
	"slo":       {"slo", "slos_write"},
	"notebook":  {"notebook", "notebooks_write"},
}

// target is a parsed question.
type target struct {
	action     action
	permission string
	relation   string
	// typ and id name the asset; empty for org questions.
	typ, id string
}

// parseTarget validates the resource for the action.
func parseTarget(actionName string, r catalog.Resource) (target, error) {
	if len(r.Query) > 0 {
		return target{}, invalid("resource %q must not carry a query", r.Raw)
	}
	if r.Type == "org" && r.ID != "" {
		return target{}, invalid("org takes no id")
	}
	if _, ok := assetTypes[r.Type]; !ok && r.Type != "org" {
		return target{}, invalid("resource type %q is not one of monitor, dashboard, slo, notebook, org", r.Type)
	}
	t := target{typ: r.Type}
	if r.Type != "org" {
		if !idRe.MatchString(r.ID) {
			return target{}, invalid("%s: id must be the asset's id", r.Type)
		}
		t.id = r.ID
	}
	if strings.HasPrefix(actionName, "raw:") {
		p, err := parseRaw(actionName)
		if err != nil {
			return target{}, err
		}
		t.action = action{name: actionName, desc: "hold " + p, resource: r.Type, permission: p}
		t.permission = p
		if r.Type != "org" {
			// On an asset a raw permission is checked against the asset's
			// restrictions as a write when it is the type's write
			// permission, as a read otherwise.
			t.relation = "viewer"
			if p == assetTypes[r.Type].writePermission {
				t.relation = "editor"
			}
		}
		return t, nil
	}
	a, ok := actions[actionName]
	if !ok {
		return target{}, invalid("unknown action %q", actionName)
	}
	if a.resource != r.Type {
		return target{}, invalid("action %s takes a %s: resource, not %s:", a.name, a.resource, r.Type)
	}
	t.action, t.permission, t.relation = a, a.permission, a.relation
	return t, nil
}

// String names the target for decision texts.
func (t target) String() string {
	if t.typ == "org" {
		return "the org"
	}
	return t.typ + " " + t.id
}
