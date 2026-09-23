package zendesk

import (
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// action is one named question.
type action struct {
	name, desc string
	// resource is the type the action takes: ticket, organization, user or
	// account.
	resource string
}

var actionList = []action{
	{"ticket.view", "see the ticket", "ticket"},
	{"ticket.edit", "change the ticket's properties: status, assignee, fields", "ticket"},
	{"ticket.comment_public", "add a public comment to the ticket", "ticket"},
	{"ticket.merge", "merge the ticket into another", "ticket"},
	{"ticket.delete", "delete the ticket", "ticket"},
	{"organization.edit", "add or change organizations", "organization"},
	{"user.edit", "edit the end user's profile", "user"},
	{"macro.manage", "create and change shared macros", "account"},
	{"view.manage", "create and change shared views", "account"},
	{"business_rules.manage", "change triggers, automations and other business rules", "account"},
	{"account.admin", "is an administrator", "account"},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

// Actions of the zendesk integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList))
	for _, a := range actionList {
		out = append(out, catalog.Action{Name: a.name, Description: a.desc + " (" + a.resource + ")"})
	}
	return out
}

// idRe is a Zendesk numeric id.
var idRe = regexp.MustCompile(`^[0-9]{1,20}$`)

func invalid(format string, args ...any) error {
	return integration.Errorf(integration.CodeInvalidRequest, format, args...)
}

// target is a parsed question.
type target struct {
	action action
	id     string
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
	if r.Type == "account" {
		if r.ID != "" {
			return target{}, invalid("account takes no id")
		}
		return target{action: a}, nil
	}
	id := strings.TrimSpace(r.ID)
	if !idRe.MatchString(id) {
		return target{}, invalid("%s: id must be a numeric Zendesk id", r.Type)
	}
	return target{action: a, id: id}, nil
}

// String names the target for decision texts.
func (t target) String() string {
	if t.action.resource == "account" {
		return "the account"
	}
	return t.action.resource + " " + t.id
}
