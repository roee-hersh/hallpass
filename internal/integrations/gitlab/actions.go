package gitlab

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// GitLab access levels. Planner (15) and Security Manager (25) are not
// cumulative with the levels around them, so every action lists the exact
// set of levels that grants it; nothing compares with >=.
const (
	levelNone            = 0
	levelMinimal         = 5
	levelGuest           = 10
	levelPlanner         = 15
	levelReporter        = 20
	levelSecurityManager = 25
	levelDeveloper       = 30
	levelMaintainer      = 40
	levelOwner           = 50
	// levelAdmin appears only in protected-branch access entries ("Admins").
	levelAdmin = 60
)

func levelName(l int) string {
	switch l {
	case levelNone:
		return "no access"
	case levelMinimal:
		return "Minimal Access"
	case levelGuest:
		return "Guest"
	case levelPlanner:
		return "Planner"
	case levelReporter:
		return "Reporter"
	case levelSecurityManager:
		return "Security Manager"
	case levelDeveloper:
		return "Developer"
	case levelMaintainer:
		return "Maintainer"
	case levelOwner:
		return "Owner"
	case levelAdmin:
		return "Admin"
	}
	return fmt.Sprintf("level %d", l)
}

func levelNames(ls []int) string {
	names := make([]string, len(ls))
	for i, l := range ls {
		names[i] = levelName(l)
	}
	return strings.Join(names, ", ")
}

// Level sets shared by several actions.
var (
	guestUp      = []int{levelGuest, levelPlanner, levelReporter, levelSecurityManager, levelDeveloper, levelMaintainer, levelOwner}
	plannerUp    = []int{levelPlanner, levelReporter, levelSecurityManager, levelDeveloper, levelMaintainer, levelOwner}
	developerUp  = []int{levelDeveloper, levelMaintainer, levelOwner}
	maintainerUp = []int{levelMaintainer, levelOwner}
	ownerOnly    = []int{levelOwner}
)

// Resource scopes.
const (
	scopeProject = "project"
	scopeGroup   = "group"
)

// Protected-branch rule kinds.
const (
	branchPush  = "push"
	branchMerge = "merge"
)

// actionSpec is one row of the action table.
type actionSpec struct {
	name, desc string
	// scope is the resource type the action applies to.
	scope string
	// levels is the exact set of access levels that grants the action.
	levels []int
	// conditional lists levels at which GitLab grants the action only under
	// conditions hallpass does not evaluate; the answer is unknown.
	conditional []int
	// nonMember lists project visibilities that grant the action to
	// authenticated non-members.
	nonMember []string
	// branch is the protected-branch rule consulted when the resource has an
	// @branch suffix: branchPush, branchMerge or "".
	branch string
}

var actionList = []actionSpec{
	{name: "project.read", desc: "view the project, its code and issues", scope: scopeProject, levels: guestUp, nonMember: []string{"public", "internal"}},
	{name: "issue.create", desc: "create an issue", scope: scopeProject, levels: guestUp, nonMember: []string{"internal"}},
	// UNVERIFIED: Security Manager (25) is assumed to edit issues like Reporter.
	{name: "issue.edit", desc: "edit any issue (assign, label, close)", scope: scopeProject, levels: plannerUp},
	{name: "mr.create", desc: "create a merge request", scope: scopeProject, levels: developerUp},
	{name: "mr.approve", desc: "approve a merge request", scope: scopeProject, levels: developerUp, conditional: []int{levelPlanner, levelReporter}},
	{name: "repo.push", desc: "push to a branch (add @branch to the resource for protected-branch rules)", scope: scopeProject, levels: developerUp, branch: branchPush},
	{name: "mr.merge", desc: "merge into a branch (add @branch to the resource for protected-branch rules)", scope: scopeProject, levels: developerUp, branch: branchMerge},
	{name: "branch.protect", desc: "protect or unprotect branches", scope: scopeProject, levels: maintainerUp},
	{name: "project.admin", desc: "change project settings", scope: scopeProject, levels: maintainerUp},
	{name: "member.manage", desc: "add, change or remove project members", scope: scopeProject, levels: maintainerUp},
	{name: "project.delete", desc: "delete the project", scope: scopeProject, levels: ownerOnly},
	{name: "pipeline.run", desc: "run a pipeline", scope: scopeProject, levels: developerUp},
	{name: "variable.manage", desc: "manage CI/CD variables", scope: scopeProject, levels: maintainerUp},
	{name: "runner.manage", desc: "manage project runners", scope: scopeProject, levels: maintainerUp},
	{name: "group.member", desc: "be a member of the group at any level", scope: scopeGroup, levels: guestUp},
	{name: "group.admin", desc: "change group settings and members (Owner)", scope: scopeGroup, levels: ownerOnly},
	// UNVERIFIED: the group's "allowed to create projects" setting defaults to Developer.
	{name: "group.project.create", desc: "create a project in the group", scope: scopeGroup, levels: developerUp},
}

var actions = func() map[string]actionSpec {
	m := map[string]actionSpec{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

// Actions of the gitlab integration.
func (Integration) Actions() []catalog.Action {
	acts := make([]catalog.Action, 0, len(actionList))
	for _, a := range actionList {
		acts = append(acts, catalog.Action{Name: a.name, Description: a.desc})
	}
	return acts
}

func (a actionSpec) grants(level int) bool {
	for _, l := range a.levels {
		if l == level {
			return true
		}
	}
	return false
}

func (a actionSpec) isConditional(level int) bool {
	for _, l := range a.conditional {
		if l == level {
			return true
		}
	}
	return false
}

func (a actionSpec) grantsNonMember(visibility string) bool {
	for _, v := range a.nonMember {
		if v == visibility {
			return true
		}
	}
	return false
}

var (
	// pathRe is a namespace path: segments of [A-Za-z0-9_.-] that do not
	// start with "-", separated by "/".
	pathRe    = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_.-]*(/[A-Za-z0-9_.][A-Za-z0-9_.-]*)*$`)
	numericRe = regexp.MustCompile(`^[0-9]+$`)
	// branchRe rejects control characters, spaces and the characters git
	// forbids in ref names.
	branchRe = regexp.MustCompile(`^[^\x00-\x20\x7f~^:?*\[\\]+$`)
)

const maxPathLength = 512

// target is a parsed resource: the project or group and an optional branch.
type target struct {
	scope  string
	id     string // path or numeric id, as sent
	branch string
}

func (t target) String() string { return t.scope + " " + t.id }

// parseTarget validates the resource against the action's scope.
//
//	project:<path-or-id>[@branch]
//	group:<path-or-id>
func parseTarget(spec actionSpec, res catalog.Resource) (target, error) {
	if res.Type != spec.scope {
		return target{}, fmt.Errorf("action %s takes a %s:<path-or-id> resource, not %s:", spec.name, spec.scope, res.Type)
	}
	if len(res.Query) > 0 {
		return target{}, errors.New("gitlab resources take no query parameters")
	}
	id, branch := res.ID, ""
	if spec.scope == scopeProject {
		id, branch = catalog.SplitBranch(res.ID)
	}
	if err := validatePath(id); err != nil {
		return target{}, fmt.Errorf("%s %q: %w", spec.scope, id, err)
	}
	if branch != "" {
		if err := validateBranch(branch); err != nil {
			return target{}, fmt.Errorf("branch %q: %w", branch, err)
		}
	} else if strings.HasSuffix(res.ID, "@") {
		return target{}, errors.New("branch after @ is empty")
	}
	return target{scope: spec.scope, id: id, branch: branch}, nil
}

func validatePath(id string) error {
	switch {
	case id == "":
		return errors.New("id is empty")
	case len(id) > maxPathLength:
		return fmt.Errorf("id is longer than %d bytes", maxPathLength)
	case numericRe.MatchString(id):
		return nil
	case !pathRe.MatchString(id):
		return errors.New("must be a numeric id or a path such as acme/webapp")
	}
	for _, seg := range strings.Split(id, "/") {
		if seg == "." || seg == ".." {
			return errors.New("path segments . and .. are not allowed")
		}
	}
	return nil
}

func validateBranch(b string) error {
	switch {
	case len(b) > 255:
		return errors.New("longer than 255 bytes")
	case !branchRe.MatchString(b):
		return errors.New("contains a space, control character or one of ~ ^ : ? * [ \\")
	case strings.HasPrefix(b, "-"):
		return errors.New("must not start with -")
	case strings.Contains(b, ".."), strings.Contains(b, "@{"):
		return errors.New("must not contain .. or @{")
	case strings.HasPrefix(b, "/"), strings.HasSuffix(b, "/"), strings.HasSuffix(b, "."), strings.HasSuffix(b, ".lock"):
		return errors.New("must not start with /, or end with /, . or .lock")
	}
	return nil
}

// matchWildcard reports whether name matches a GitLab protected-branch
// pattern, where "*" matches any sequence of characters (including "/")
// and every other character matches itself.
func matchWildcard(pattern, name string) bool {
	for len(pattern) > 0 {
		if pattern[0] != '*' {
			if len(name) == 0 || name[0] != pattern[0] {
				return false
			}
			pattern, name = pattern[1:], name[1:]
			continue
		}
		// Collapse runs of "*"; a trailing "*" matches the rest.
		pattern = strings.TrimLeft(pattern, "*")
		if pattern == "" {
			return true
		}
		for i := 0; i <= len(name); i++ {
			if matchWildcard(pattern, name[i:]) {
				return true
			}
		}
		return false
	}
	return name == ""
}
