package bitbucket

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// level is an effective permission on a repository or project, ordered.
type level int

const (
	levelNone level = iota
	levelRead
	levelWrite
	levelAdmin
)

func (l level) String() string {
	switch l {
	case levelRead:
		return "read"
	case levelWrite:
		return "write"
	case levelAdmin:
		return "admin"
	}
	return "none"
}

// action is one named question.
type action struct {
	name, desc string
	// resource is the type the action takes: repo, project or workspace.
	resource string
	// level is the repository or project permission needed.
	level level
	// branch is the branch-restriction kind consulted when the repo
	// resource names a branch: "push" or "merge".
	branch string
	// createRepo marks project-level repository creation, which Cloud
	// grants separately from write.
	createRepo bool
	// role is the workspace role needed: "member" or "admin".
	role string
}

var actionList = []action{
	{name: "repo.read", desc: "read and clone the repository; needs read", resource: "repo", level: levelRead},
	{name: "repo.push", desc: "push to the repository (or to @branch, checked against its branch restrictions); needs write", resource: "repo", level: levelWrite, branch: "push"},
	{name: "pr.merge", desc: "merge a pull request (into @branch, checked against its branch restrictions); needs write", resource: "repo", level: levelWrite, branch: "merge"},
	{name: "repo.admin", desc: "administer the repository: settings, permissions, deletion; needs admin", resource: "repo", level: levelAdmin},
	{name: "project.read", desc: "see the project and read its repositories; needs read", resource: "project", level: levelRead},
	{name: "project.write", desc: "push to the project's repositories; needs write", resource: "project", level: levelWrite},
	{name: "repo.create", desc: "create a repository in the project; needs create-repo (Cloud) or project admin (Data Center, see the doc)", resource: "project", level: levelWrite, createRepo: true},
	{name: "project.admin", desc: "administer the project; needs admin", resource: "project", level: levelAdmin},
	{name: "workspace.member", desc: "is a member of the workspace (Cloud) or a licensed user (Data Center)", resource: "workspace", role: "member"},
	{name: "workspace.admin", desc: "is a workspace owner (Cloud) or a global administrator (Data Center)", resource: "workspace", role: "admin"},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

// Actions of the bitbucket integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList))
	for _, a := range actionList {
		out = append(out, catalog.Action{Name: a.name, Description: a.desc + " (" + a.resource + ")"})
	}
	return out
}

var (
	// slugRe is a workspace slug, repository slug or project key. Cloud
	// slugs are lowercase with dots, hyphens and underscores; Data Center
	// project keys are upper case and personal projects start with "~".
	slugRe = regexp.MustCompile(`^~?[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	// uuidRe is a Cloud UUID in braces, also accepted where a slug is.
	uuidRe   = regexp.MustCompile(`^\{[0-9a-fA-F-]{36}\}$`)
	branchRe = regexp.MustCompile(`^[^\x00-\x20\x7f~^:?*\[\\]{1,255}$`)
)

func validSlug(s string) bool { return slugRe.MatchString(s) || uuidRe.MatchString(s) }

func validBranch(s string) bool {
	return branchRe.MatchString(s) && !strings.HasPrefix(s, "-") && !strings.HasPrefix(s, "/") &&
		!strings.HasSuffix(s, "/") && !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, ".lock") &&
		!strings.Contains(s, "..") && !strings.Contains(s, "//") && !strings.Contains(s, "@{")
}

// target is a parsed resource.
type target struct {
	action action
	// project is the project key (Data Center, and Cloud projects).
	project string
	// repo is the repository slug; empty for project and workspace targets.
	repo string
	// branch is the branch named with @, if any.
	branch string
}

func invalid(format string, args ...any) error {
	return integration.Errorf(integration.CodeInvalidRequest, format, args...)
}

// parseTarget validates the resource for the action.
//
//	repo:<slug>[@branch]                Cloud, the workspace is the connection's
//	repo:<PROJECT>/<slug>[@branch]      Data Center
//	project:<key>
//	workspace                           the connection's workspace or instance
func parseTarget(actionName string, r catalog.Resource, dataCenter bool) (target, error) {
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
	t := target{action: a}
	switch r.Type {
	case "workspace":
		if r.ID != "" {
			return target{}, invalid("workspace takes no id: the connection names the workspace")
		}
	case "project":
		if !validSlug(r.ID) {
			return target{}, invalid("project: id must be a project key")
		}
		t.project = r.ID
	case "repo":
		id, branch := catalog.SplitBranch(r.ID)
		if strings.Contains(r.ID, "@") && branch == "" {
			return target{}, invalid("repo: a branch after @ must not be empty")
		}
		if branch != "" && !validBranch(branch) {
			return target{}, invalid("branch %q is not a valid branch name", branch)
		}
		if branch != "" && a.branch == "" {
			return target{}, invalid("action %s does not take a branch", a.name)
		}
		t.branch = branch
		if dataCenter {
			project, repo, ok := strings.Cut(id, "/")
			if !ok || !validSlug(project) || !validSlug(repo) {
				return target{}, invalid("repo: id must be <PROJECT>/<slug>[@branch] on Data Center")
			}
			t.project, t.repo = project, repo
		} else {
			if strings.Contains(id, "/") || !validSlug(id) {
				return target{}, invalid("repo: id must be <slug>[@branch]; the workspace is the connection's")
			}
			t.repo = id
		}
	}
	return t, nil
}

// String names the target for decision texts.
func (t target) String() string {
	switch t.action.resource {
	case "workspace":
		return "the workspace"
	case "project":
		return "project " + t.project
	}
	s := "repository " + t.repo
	if t.project != "" {
		s = "repository " + t.project + "/" + t.repo
	}
	if t.branch != "" {
		s += "@" + t.branch
	}
	return s
}

// globMatch matches a Bitbucket branch pattern against a branch name. "*"
// and "**" match any run of characters, including "/"; "?" one character.
// Anything else is literal. Patterns with character classes or
// alternations are reported unsupported.
func globMatch(pattern, name string) (matched, supported bool) {
	if strings.ContainsAny(pattern, "[]{}") {
		return false, false
	}
	return glob(pattern, name), true
}

func glob(p, s string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			p = strings.TrimLeft(p, "*")
			if p == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if glob(p, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
			p, s = p[1:], s[1:]
		default:
			if s == "" || p[0] != s[0] {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return s == ""
}

// refMatch matches a pattern that may carry a refs/heads/ prefix against a
// branch name, as Bitbucket does.
func refMatch(pattern, branch string) (bool, bool) {
	pattern = strings.TrimPrefix(pattern, "refs/heads/")
	return globMatch(pattern, branch)
}

func describeLevel(l level, needed level) string {
	if l >= needed {
		return fmt.Sprintf("has %s (needs %s)", l, needed)
	}
	return fmt.Sprintf("has %s, needs %s", l, needed)
}
