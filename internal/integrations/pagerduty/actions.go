package pagerduty

import (
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// Base roles, as the API spells them. The web UI calls user "Manager",
// limited_user "Responder", read_only_user "Full Stakeholder" and
// read_only_limited_user "Limited Stakeholder".
const (
	roleOwner         = "owner"
	roleAdmin         = "admin"
	roleUser          = "user"
	roleLimitedUser   = "limited_user"
	roleObserver      = "observer"
	roleRestricted    = "restricted_access"
	roleReadOnly      = "read_only_user"
	roleReadOnlyLtd   = "read_only_limited_user"
	teamRoleManager   = "manager"
	teamRoleResponder = "responder"
	teamRoleObserver  = "observer"
)

// need is what an action requires.
type need int

const (
	// needRespond: act on incidents and create overrides. Base user and
	// limited_user hold it everywhere; observer and restricted_access hold
	// it through a responder or manager team role on the object's team.
	needRespond need = iota
	// needManage: create, change and delete configuration. Base user holds
	// it everywhere; every flexible role below holds it through a manager
	// team role on the object's team.
	needManage
	// needMaintenance: set a maintenance window on a service. Base user
	// holds it everywhere; team responders and managers hold it for their
	// team's services; whether base limited_user holds it account-wide is
	// not documented, so that case is unknown.
	needMaintenance
	// needAccountAdmin: owner or admin base role.
	needAccountAdmin
	// needTeamMember: a member of the team.
	needTeamMember
)

// action is one named question.
type action struct {
	name, desc string
	// resource is the type the action takes.
	resource string
	need     need
}

var actionList = []action{
	{"incident.acknowledge", "acknowledge the incident", "incident", needRespond},
	{"incident.resolve", "resolve the incident", "incident", needRespond},
	{"incident.reassign", "reassign or escalate the incident", "incident", needRespond},
	{"service.edit", "change or delete the service and its integrations", "service", needManage},
	{"service.maintenance", "create a maintenance window for the service", "service", needMaintenance},
	{"escalation_policy.edit", "change or delete the escalation policy", "escalation_policy", needManage},
	{"schedule.edit", "change or delete the schedule", "schedule", needManage},
	{"schedule.override", "create an override on the schedule", "schedule", needRespond},
	{"team.manage", "change the team, its members and their team roles", "team", needManage},
	{"team.member", "is a member of the team", "team", needTeamMember},
	{"account.admin", "is an account owner or global admin", "account", needAccountAdmin},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

// Actions of the pagerduty integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList))
	for _, a := range actionList {
		out = append(out, catalog.Action{Name: a.name, Description: a.desc + " (" + a.resource + ")"})
	}
	return out
}

// idRe is a PagerDuty object id (P + upper-case alphanumerics) or, for
// incidents, an incident number.
var idRe = regexp.MustCompile(`^[A-Z0-9]{1,32}$`)

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
		return target{}, invalid("action %s takes an %s: resource, not %s:", a.name, a.resource, r.Type)
	}
	if r.Type == "account" {
		if r.ID != "" {
			return target{}, invalid("account takes no id")
		}
		return target{action: a}, nil
	}
	id := strings.ToUpper(strings.TrimSpace(r.ID))
	if !idRe.MatchString(id) {
		return target{}, invalid("%s: id must be a PagerDuty id such as PABC123", r.Type)
	}
	return target{action: a, id: id}, nil
}

// String names the target for decision texts.
func (t target) String() string {
	if t.action.resource == "account" {
		return "the account"
	}
	return strings.ReplaceAll(t.action.resource, "_", " ") + " " + t.id
}
