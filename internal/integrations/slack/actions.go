package slack

import (
	"fmt"
	"regexp"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// Resource types the slack integration accepts.
const (
	resChannel   = "channel"
	resWorkspace = "workspace"
	resUsergroup = "usergroup"
)

// action is one named question and the resource type it takes.
type action struct {
	name, desc string
	resource   string
}

var actionList = []action{
	{name: "user.active", desc: "the user has an active, joined, non-bot account", resource: resWorkspace},
	{name: "workspace.admin", desc: "the user is a workspace admin or owner", resource: resWorkspace},
	{name: "org.admin", desc: "the user is an Enterprise Grid org admin or owner", resource: resWorkspace},
	{name: "channel.read", desc: "read the channel's history", resource: resChannel},
	{name: "channel.join", desc: "join the channel", resource: resChannel},
	{name: "message.post", desc: "post a top-level message in the channel", resource: resChannel},
	{name: "message.post_thread", desc: "reply in a thread in the channel", resource: resChannel},
	{name: "file.upload", desc: "upload a file to the channel", resource: resChannel},
	{name: "usergroup.member", desc: "the user is a member of the user group", resource: resUsergroup},
	{name: "channel.invite", desc: "invite someone to the channel", resource: resChannel},
	{name: "channel.create", desc: "create a channel in the workspace", resource: resWorkspace},
	{name: "channel.archive", desc: "archive the channel", resource: resChannel},
	{name: "channel.rename", desc: "rename the channel", resource: resChannel},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

// Actions of the slack integration.
func (Integration) Actions() []catalog.Action {
	acts := make([]catalog.Action, 0, len(actionList))
	for _, a := range actionList {
		acts = append(acts, catalog.Action{Name: a.name, Description: a.desc + " (" + a.resource + ")"})
	}
	return acts
}

var (
	channelIDRe   = regexp.MustCompile(`^[CG][A-Z0-9]{8,}$`)
	usergroupIDRe = regexp.MustCompile(`^S[A-Z0-9]{8,}$`)
	userIDRe      = regexp.MustCompile(`^[UW][A-Z0-9]{8,}$`)
)

// validateResource checks that the resource matches the action's type and
// that the id is safe to put into a query string.
func validateResource(actionName string, res catalog.Resource) (action, error) {
	a, ok := actions[actionName]
	if !ok {
		return a, fmt.Errorf("unknown action %q", actionName)
	}
	if res.Type != a.resource {
		return a, fmt.Errorf("action %s takes a %s resource, not %s", actionName, describeResource(a.resource), res.Type)
	}
	if len(res.Query) > 0 {
		return a, fmt.Errorf("slack resources take no query parameters")
	}
	switch a.resource {
	case resWorkspace:
		if res.ID != "" {
			return a, fmt.Errorf("the workspace resource takes no id: use workspace")
		}
	case resChannel:
		if !channelIDRe.MatchString(res.ID) {
			return a, fmt.Errorf("channel id %q must be a Slack channel id such as C0123456789", res.ID)
		}
	case resUsergroup:
		if !usergroupIDRe.MatchString(res.ID) {
			return a, fmt.Errorf("usergroup id %q must be a Slack user group id such as S0123456789", res.ID)
		}
	}
	return a, nil
}

func describeResource(typ string) string {
	switch typ {
	case resWorkspace:
		return "workspace"
	case resChannel:
		return "channel:<id>"
	case resUsergroup:
		return "usergroup:<id>"
	}
	return typ
}
