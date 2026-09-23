package linear

import (
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// action is one named question.
type action struct {
	name, desc string
	// resource is the type the action takes: team, issue, project or
	// workspace.
	resource string
}

var actionList = []action{
	{"team.view", "see the team and its issues", "team"},
	{"team.member", "is a member of the team", "team"},
	{"team.admin", "manage the team's settings and members", "team"},
	{"issue.view", "see the issue", "issue"},
	{"issue.edit", "edit and comment on the issue", "issue"},
	{"project.view", "see the project", "project"},
	{"workspace.member", "is a full member of the workspace (not a guest or an app)", "workspace"},
	{"workspace.admin", "is a workspace administrator or owner", "workspace"},
	{"workspace.owner", "is a workspace owner", "workspace"},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

// Actions of the linear integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList))
	for _, a := range actionList {
		out = append(out, catalog.Action{Name: a.name, Description: a.desc + " (" + a.resource + ")"})
	}
	return out
}

var (
	// uuidRe is Linear's internal id.
	uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// teamKeyRe is a team key such as ENG.
	teamKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9]{0,9}$`)
	// issueKeyRe is a human issue identifier such as ENG-123.
	issueKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9]{0,9}-[1-9][0-9]{0,8}$`)
	// slugRe is a project slug id.
	slugRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,79}$`)
)

func invalid(format string, args ...any) error {
	return integration.Errorf(integration.CodeInvalidRequest, format, args...)
}

// target is a parsed question.
type target struct {
	action action
	// id is the resource's id, key or identifier, exactly as it will be
	// sent in a GraphQL variable.
	id string
	// byID is set when id is a Linear uuid rather than a key.
	byID bool
}

// parseTarget validates the resource for the action.
func parseTarget(actionName string, r catalog.Resource) (target, error) {
	a, ok := actions[actionName]
	if !ok {
		return target{}, invalid("unknown action %q", actionName)
	}
	if len(r.Query) > 0 {
		return target{}, invalid("resource %q must not carry a query", r.Raw)
	}
	if r.Type != a.resource {
		return target{}, invalid("action %s takes a %s: resource, not %s:", a.name, a.resource, r.Type)
	}
	if r.Type == "workspace" {
		if r.ID != "" {
			return target{}, invalid("workspace takes no id")
		}
		return target{action: a}, nil
	}
	id := strings.TrimSpace(r.ID)
	if uuidRe.MatchString(strings.ToLower(id)) {
		return target{action: a, id: strings.ToLower(id), byID: true}, nil
	}
	switch r.Type {
	case "team":
		id = strings.ToUpper(id)
		if !teamKeyRe.MatchString(id) {
			return target{}, invalid("team: takes a team key such as ENG or a Linear id")
		}
	case "issue":
		id = strings.ToUpper(id)
		if !issueKeyRe.MatchString(id) {
			return target{}, invalid("issue: takes an identifier such as ENG-123 or a Linear id")
		}
	case "project":
		if !slugRe.MatchString(id) {
			return target{}, invalid("project: takes a slug id or a Linear id")
		}
	}
	return target{action: a, id: id}, nil
}

// String names the target for decision texts.
func (t target) String() string {
	if t.action.resource == "workspace" {
		return "the workspace"
	}
	return t.action.resource + " " + t.id
}
