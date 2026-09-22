package jira

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// action is one Jira permission key. global ones are checked with
// globalPermissions on the resource "global"; the rest are project
// permissions checked on project:<KEY> or issue:<KEY-N>.
type action struct {
	name, desc string
	global     bool
}

var actionList = []action{
	{name: "BROWSE_PROJECTS", desc: "view the project and its issues"},
	{name: "CREATE_ISSUES", desc: "create issues in the project"},
	{name: "EDIT_ISSUES", desc: "edit issues"},
	{name: "DELETE_ISSUES", desc: "delete issues"},
	{name: "ASSIGN_ISSUES", desc: "assign issues to users"},
	{name: "ASSIGNABLE_USER", desc: "be assigned issues"},
	{name: "TRANSITION_ISSUES", desc: "transition issues through the workflow"},
	{name: "RESOLVE_ISSUES", desc: "resolve and reopen issues, set fix versions"},
	{name: "CLOSE_ISSUES", desc: "close issues"},
	{name: "MOVE_ISSUES", desc: "move issues between projects or issue types"},
	{name: "LINK_ISSUES", desc: "link issues"},
	{name: "ADD_COMMENTS", desc: "add comments"},
	{name: "EDIT_ALL_COMMENTS", desc: "edit any comment"},
	{name: "DELETE_ALL_COMMENTS", desc: "delete any comment"},
	{name: "CREATE_ATTACHMENTS", desc: "attach files"},
	{name: "WORK_ON_ISSUES", desc: "log work on issues"},
	{name: "MANAGE_WATCHERS", desc: "manage the watcher list"},
	{name: "VIEW_VOTERS_AND_WATCHERS", desc: "view voters and watchers"},
	{name: "SCHEDULE_ISSUES", desc: "schedule issues (due date, rank)"},
	{name: "SET_ISSUE_SECURITY", desc: "set the security level of issues"},
	{name: "MANAGE_SPRINTS_PERMISSION", desc: "manage sprints"},
	{name: "ADMINISTER_PROJECTS", desc: "administer the project"},
	{name: "ADMINISTER", desc: "administer Jira (global)", global: true},
	{name: "SYSTEM_ADMIN", desc: "administer Jira system settings (global)", global: true},
	{name: "USER_PICKER", desc: "browse users and groups (global)", global: true},
	{name: "CREATE_SHARED_OBJECTS", desc: "share filters and dashboards (global)", global: true},
	{name: "MANAGE_GROUP_FILTER_SUBSCRIPTIONS", desc: "manage group filter subscriptions (global)", global: true},
	{name: "BULK_CHANGE", desc: "make bulk changes (global)", global: true},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

var (
	projectKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,9}$`)
	issueKeyRe   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,9}-[1-9][0-9]*$`)
)

type resourceKind int

const (
	resGlobal resourceKind = iota
	resProject
	resIssue
)

// resource is a parsed project:<KEY>, issue:<KEY-N> or global.
type resource struct {
	kind resourceKind
	key  string
}

func (r resource) describe() string {
	switch r.kind {
	case resProject:
		return "project " + r.key
	case resIssue:
		return "issue " + r.key
	}
	return "this site"
}

func parseResource(res catalog.Resource) (resource, error) {
	switch res.Type {
	case "global":
		if res.ID != "" {
			return resource{}, errors.New("global takes no id")
		}
		return resource{kind: resGlobal}, nil
	case "project":
		if !projectKeyRe.MatchString(res.ID) {
			return resource{}, fmt.Errorf("project key %q must match %s", res.ID, projectKeyRe)
		}
		return resource{kind: resProject, key: res.ID}, nil
	case "issue":
		if !issueKeyRe.MatchString(res.ID) {
			return resource{}, fmt.Errorf("issue key %q must match %s", res.ID, issueKeyRe)
		}
		return resource{kind: resIssue, key: res.ID}, nil
	default:
		return resource{}, fmt.Errorf("resource type %q; use project:<KEY>, issue:<KEY-N> or global", res.Type)
	}
}
