package github

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// level is one rung of GitHub's repository permission ladder, lowest first.
type level string

const (
	levelPull     level = "pull"
	levelTriage   level = "triage"
	levelPush     level = "push"
	levelMaintain level = "maintain"
	levelAdmin    level = "admin"
)

// action is one entry of the fixed action table.
type action struct {
	name, desc string
	// resource is the resource type the action applies to: repo, org or team.
	resource string
	// level is the repository permission the action needs (repo actions only).
	level level
}

var actionList = []action{
	{name: "repo.read", desc: "read the repository (clone, view code and issues); needs pull", resource: "repo", level: levelPull},
	{name: "repo.triage", desc: "manage issues and pull requests without write access; needs triage", resource: "repo", level: levelTriage},
	{name: "repo.push", desc: "push to the repository (or to @branch, checked against its rules); needs push", resource: "repo", level: levelPush},
	{name: "repo.maintain", desc: "manage the repository without destructive actions; needs maintain", resource: "repo", level: levelMaintain},
	{name: "repo.admin", desc: "administer the repository; needs admin", resource: "repo", level: levelAdmin},
	{name: "issue.create", desc: "open an issue; needs pull and the repository must have issues enabled", resource: "repo", level: levelPull},
	{name: "pr.create", desc: "open a pull request (via a fork with pull; a branch in the repository itself needs push)", resource: "repo", level: levelPull},
	{name: "pr.merge", desc: "merge a pull request (into @branch, checked against its rules); needs push", resource: "repo", level: levelPush},
	{name: "org.member", desc: "be an active member of the organization", resource: "org"},
	{name: "org.admin", desc: "be an owner (admin) of the organization", resource: "org"},
	{name: "org.repo.create", desc: "create a repository in the organization: owner, or member when members may create repositories", resource: "org"},
	{name: "team.member", desc: "be an active member of the team", resource: "team"},
	{name: "team.maintainer", desc: "be a maintainer of the team", resource: "team"},
}

var actions = func() map[string]action {
	m := map[string]action{}
	for _, a := range actionList {
		m[a.name] = a
	}
	return m
}()

var (
	// ownerRe and repoRe are GitHub's name rules; a repository name may
	// contain dots, an owner (login) may not.
	repoRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	loginRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	slugRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
)

// validLogin reports whether s is a GitHub login: alphanumerics and single
// hyphens, at most 39 characters.
func validLogin(s string) bool {
	return loginRe.MatchString(s) && !strings.Contains(s, "--")
}

// validRepoName reports whether s is a repository name.
func validRepoName(s string) bool {
	return repoRe.MatchString(s) && s != "." && s != ".."
}

// validBranch rejects branch names that could not be git refs or that
// would change the meaning of a URL.
func validBranch(s string) bool {
	if s == "" || len(s) > 255 || strings.HasPrefix(s, "-") || strings.Contains(s, "..") {
		return false
	}
	for _, c := range s {
		if c < 0x21 || c == 0x7f || strings.ContainsRune(`\~^:?*[@`, c) {
			return false
		}
	}
	return true
}

// target is a parsed and validated resource.
type target struct {
	kind   string // repo, org or team
	owner  string // organization login, as configured
	repo   string
	branch string
	team   string
}

func (t target) String() string {
	switch t.kind {
	case "repo":
		s := t.owner + "/" + t.repo
		if t.branch != "" {
			s += "@" + t.branch
		}
		return s
	case "team":
		return t.owner + "/" + t.team
	default:
		return t.owner
	}
}

// parseTarget validates the resource against the action's resource type and
// the configured organization. Every part goes into a URL path later, so
// the rules are strict.
func parseTarget(a action, org string, r catalog.Resource) (target, error) {
	if r.Type != a.resource {
		return target{}, fmt.Errorf("action %s needs a %s: resource, not %s:", a.name, a.resource, r.Type)
	}
	if len(r.Query) > 0 {
		return target{}, errors.New("github resources take no query parameters")
	}
	switch r.Type {
	case "repo":
		id, branch := catalog.SplitBranch(r.ID)
		owner, name, ok := strings.Cut(id, "/")
		if !ok || !validLogin(owner) || !validRepoName(name) {
			return target{}, fmt.Errorf("repo resource must be repo:<owner>/<name>[@branch], got %q", r.ID)
		}
		if !strings.EqualFold(owner, org) {
			return target{}, fmt.Errorf("repository owner %q must be the configured organization %q: the app installation is per organization", owner, org)
		}
		if strings.Contains(r.ID, "@") && !validBranch(branch) {
			return target{}, fmt.Errorf("branch %q is not a valid branch name", branch)
		}
		return target{kind: "repo", owner: org, repo: name, branch: branch}, nil
	case "org":
		if !validLogin(r.ID) {
			return target{}, fmt.Errorf("org resource must be org:<login>, got %q", r.ID)
		}
		if !strings.EqualFold(r.ID, org) {
			return target{}, fmt.Errorf("organization %q must be the configured organization %q: the app installation is per organization", r.ID, org)
		}
		return target{kind: "org", owner: org}, nil
	case "team":
		owner, slug, ok := strings.Cut(r.ID, "/")
		if !ok || !validLogin(owner) || !slugRe.MatchString(slug) || len(slug) > 255 {
			return target{}, fmt.Errorf("team resource must be team:<org>/<slug>, got %q", r.ID)
		}
		if !strings.EqualFold(owner, org) {
			return target{}, fmt.Errorf("team organization %q must be the configured organization %q: the app installation is per organization", owner, org)
		}
		return target{kind: "team", owner: org, team: slug}, nil
	}
	return target{}, fmt.Errorf("unknown resource type %q", r.Type)
}

// permissions are the booleans GitHub reports for a collaborator.
type permissions struct {
	Pull     bool `json:"pull"`
	Triage   bool `json:"triage"`
	Push     bool `json:"push"`
	Maintain bool `json:"maintain"`
	Admin    bool `json:"admin"`
}

// has reports whether the permissions include the level.
func (p permissions) has(l level) bool {
	switch l {
	case levelPull:
		return p.Pull
	case levelTriage:
		return p.Triage
	case levelPush:
		return p.Push
	case levelMaintain:
		return p.Maintain
	case levelAdmin:
		return p.Admin
	}
	return false
}

// fromString expands the lossy top-level permission string, for responses
// that carry no user.permissions object.
func fromString(s string) permissions {
	switch s {
	case "admin":
		return permissions{Pull: true, Triage: true, Push: true, Maintain: true, Admin: true}
	case "maintain":
		return permissions{Pull: true, Triage: true, Push: true, Maintain: true}
	case "write", "push":
		return permissions{Pull: true, Triage: true, Push: true}
	case "triage":
		return permissions{Pull: true, Triage: true}
	case "read", "pull":
		return permissions{Pull: true}
	}
	return permissions{}
}
