package vault

import (
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// action is one named question, in terms of the capabilities Vault needs.
type action struct {
	name, desc string
	// need are the capabilities the request needs on the resolved path.
	need []string
	// kv2 names the KV v2 sub-path the request goes to (data, metadata,
	// destroy); "" keeps the logical path (KV v1 and path: resources).
	kv2 string
	// list matches the path as a prefix, the way Vault sanitizes LIST
	// requests.
	list bool
}

var actionList = []action{
	{"secret.read", "read the secret", []string{"read"}, "data", false},
	{"secret.write", "create or update the secret", []string{"create", "update"}, "data", false},
	{"secret.delete", "delete the secret (KV v2: soft-delete the latest version)", []string{"delete"}, "data", false},
	{"secret.list", "list the keys under the path", []string{"list"}, "metadata", true},
	{"secret.metadata", "read the secret's metadata (KV v2)", []string{"read"}, "metadata", false},
	{"secret.destroy", "permanently destroy the secret's versions (KV v2)", []string{"update"}, "destroy", false},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

const rawPattern = "raw:<capability>"

// Actions of the vault integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList)+1)
	for _, a := range actionList {
		out = append(out, catalog.Action{Name: a.name, Description: a.desc + " (" + strings.Join(a.need, "+") + ")"})
	}
	out = append(out, catalog.Action{Name: rawPattern, Pattern: true,
		Description: "any capability on a path: resource, e.g. raw:read, raw:update, raw:sudo, raw:list"})
	return out
}

// parseRaw parses raw:<capability>.
func parseRaw(name string) (action, bool) {
	c, ok := strings.CutPrefix(name, "raw:")
	if !ok || !capabilities[c] || c == "deny" {
		return action{}, false
	}
	return action{name: name, desc: "perform a request needing " + c, need: []string{c}, list: c == "list"}, true
}

// MatchAction accepts raw:<capability>.
func (Integration) MatchAction(name string) (catalog.Action, bool) {
	a, ok := parseRaw(name)
	if !ok {
		return catalog.Action{}, false
	}
	return catalog.Action{Name: rawPattern, Pattern: true, Description: a.desc}, true
}

// pathRe is a Vault API path: segments of ordinary characters, no
// wildcards (a requested path is literal), no dot-only segments.
var pathRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@:~=-]*(/[A-Za-z0-9_.@:~=-]+)*$`)

func invalid(format string, args ...any) error {
	return integration.Errorf(integration.CodeInvalidRequest, format, args...)
}

// target is a parsed question.
type target struct {
	action action
	// kind is kv or path.
	kind string
	// mount is the KV mount (kv:), key the path under it; for path:, path
	// is the whole API path.
	mount, key, path string
}

// parseTarget validates the action and resource.
func parseTarget(actionName string, r catalog.Resource) (target, error) {
	a, ok := actions[actionName]
	if !ok {
		if a, ok = parseRaw(actionName); !ok {
			return target{}, invalid("unknown action %q", actionName)
		}
	}
	if len(r.Query) > 0 {
		return target{}, invalid("resource %q must not carry a query", r.Raw)
	}
	p := strings.Trim(strings.TrimSpace(r.ID), "/")
	if p == "" || len(p) > 512 || !pathRe.MatchString(p) || badSegments(p) {
		return target{}, invalid("%s: takes a Vault path of plain segments (letters, digits, _ . - @ : ~ =), no wildcards", r.Type)
	}
	t := target{action: a, kind: r.Type, path: p}
	switch r.Type {
	case "kv":
		mount, key, ok := strings.Cut(p, "/")
		if !ok || key == "" {
			return target{}, invalid("kv: takes <mount>/<key path>")
		}
		if strings.HasPrefix(actionName, "raw:") {
			return target{}, invalid("raw: capabilities take a path: resource; kv: resolves the path from the action")
		}
		t.mount, t.key = mount, key
	case "path":
		if a.name == "secret.destroy" || a.name == "secret.metadata" {
			return target{}, invalid("%s is a KV v2 question; use kv:<mount>/<key>", a.name)
		}
	default:
		return target{}, invalid("resource type %q is not kv: or path:", r.Type)
	}
	return t, nil
}

func badSegments(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if strings.Trim(seg, ".") == "" {
			return true
		}
	}
	return false
}

// String names the target for decision texts.
func (t target) String() string {
	return t.kind + ":" + t.path
}
