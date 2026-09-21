// Package rbac evaluates Argo CD RBAC policy the way Argo CD's API server
// does, without Casbin. It is a port of argo-cd/util/rbac and
// argo-cd/server/rbacpolicy (v3):
//
//	request  r = sub, res, act, obj
//	policy   p = sub, res, act, obj, eft
//	roles    g = _, _
//	effect   some allow && !some deny
//	matcher  g(r.sub, p.sub) && m(r.res, p.res) && m(r.act, p.act) && m(r.obj, p.obj)
//
// where m is a gobwas glob with no separators (default) or an unanchored Go
// regexp when policy.matchMode is "regex".
package rbac

import (
	"encoding/csv"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Config map keys, as in argo-cd/util/rbac.
const (
	PolicyCSVKey     = "policy.csv"
	PolicyDefaultKey = "policy.default"
	ScopesKey        = "scopes"
	MatchModeKey     = "policy.matchMode"
	GlobMatchMode    = "glob"
	RegexMatchMode   = "regex"
)

// Resources and actions Argo CD knows.
const (
	ResourceClusters          = "clusters"
	ResourceProjects          = "projects"
	ResourceApplications      = "applications"
	ResourceApplicationSets   = "applicationsets"
	ResourceRepositories      = "repositories"
	ResourceWriteRepositories = "write-repositories"
	ResourceCertificates      = "certificates"
	ResourceAccounts          = "accounts"
	ResourceGPGKeys           = "gpgkeys"
	ResourceLogs              = "logs"
	ResourceExec              = "exec"
	ResourceExtensions        = "extensions"

	ActionGet      = "get"
	ActionCreate   = "create"
	ActionUpdate   = "update"
	ActionDelete   = "delete"
	ActionSync     = "sync"
	ActionOverride = "override"
	ActionAction   = "action"
	ActionInvoke   = "invoke"
	ActionRollback = "rollback"
)

// DefaultScopes is the claim Argo CD reads groups from when "scopes" is unset.
var DefaultScopes = []string{"groups"}

// MaxRoleDepth is Casbin's default role hierarchy limit.
const MaxRoleDepth = 10

// Rule is one p line.
type Rule struct {
	Sub, Res, Act, Obj string
	Deny               bool
}

// Link is one g line: Sub has role Role.
type Link struct {
	Sub, Role string
}

// Policy is a parsed set of p and g lines.
type Policy struct {
	Rules []Rule
	Links []Link
}

// ParsePolicy parses CSV policy text exactly as Argo CD's loadPolicyLine
// does: blank lines and # comments are skipped, fields are CSV with leading
// space trimmed, p lines have 6 fields and g lines 3, anything else is an
// error.
func ParsePolicy(text string) (*Policy, error) {
	p := &Policy{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r := csv.NewReader(strings.NewReader(line))
		r.TrimLeadingSpace = true
		tokens, err := r.Read()
		if err != nil {
			return nil, fmt.Errorf("error parsing policy line %q: %w", line, err)
		}
		switch {
		case len(tokens) == 6 && tokens[0] == "p":
			eft := tokens[5]
			if eft != "allow" && eft != "deny" {
				// Casbin treats any other effect as neither allow nor deny;
				// such a line can never match. Keep it out.
				continue
			}
			p.Rules = append(p.Rules, Rule{Sub: tokens[1], Res: tokens[2], Act: tokens[3], Obj: tokens[4], Deny: eft == "deny"})
		case len(tokens) == 3 && tokens[0] == "g":
			p.Links = append(p.Links, Link{Sub: tokens[1], Role: tokens[2]})
		default:
			return nil, fmt.Errorf("invalid RBAC policy: %s", line)
		}
	}
	return p, nil
}

// PolicyCSV assembles the user policy from an argocd-rbac-cm data map:
// policy.csv first, then every policy.*.csv key in sorted order.
func PolicyCSV(data map[string]string) string {
	var b strings.Builder
	if p, ok := data[PolicyCSVKey]; ok {
		b.WriteString(p)
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.HasPrefix(k, "policy.") && strings.HasSuffix(k, ".csv") && k != PolicyCSVKey {
			b.WriteString("\n")
			b.WriteString(data[k])
		}
	}
	return b.String()
}

// Project is the part of an AppProject that affects RBAC.
type Project struct {
	Name  string
	Roles []ProjectRole
}

// ProjectRole is one spec.roles entry.
type ProjectRole struct {
	Name     string
	Policies []string
	Groups   []string
}

// PoliciesString renders the project's runtime policy exactly as
// AppProject.ProjectPoliciesString does.
func (p *Project) PoliciesString() string {
	var lines []string
	for _, role := range p.Roles {
		lines = append(lines, fmt.Sprintf("p, proj:%s:%s, projects, get, %s, allow", p.Name, role.Name, p.Name))
		lines = append(lines, role.Policies...)
		for _, g := range role.Groups {
			lines = append(lines, fmt.Sprintf("g, %s, proj:%s:%s", g, p.Name, role.Name))
		}
	}
	return strings.Join(lines, "\n")
}

// Enforcer evaluates requests against builtin + user (+ runtime) policy.
type Enforcer struct {
	rules       []Rule
	links       map[string][]string // sub -> roles
	linkSubs    map[string]bool     // first element of every g line
	matchMode   string
	defaultRole string
	regexes     sync.Map
}

// Options for NewEnforcer.
type Options struct {
	// Builtin is Argo CD's built-in policy (BuiltinPolicyCSV).
	Builtin string
	// User is the policy from argocd-rbac-cm (PolicyCSV).
	User string
	// Runtime is a project's PoliciesString, or "".
	Runtime string
	// MatchMode is "glob" (default) or "regex".
	MatchMode string
	// DefaultRole is policy.default, or "".
	DefaultRole string
}

// NewEnforcer parses the three policies. A parse error in any of them is
// returned; Argo CD would refuse to load the policy too.
func NewEnforcer(o Options) (*Enforcer, error) {
	e := &Enforcer{links: map[string][]string{}, linkSubs: map[string]bool{}, matchMode: GlobMatchMode, defaultRole: o.DefaultRole}
	if o.MatchMode == RegexMatchMode {
		e.matchMode = RegexMatchMode
	}
	for _, text := range []string{o.Builtin, o.User, o.Runtime} {
		p, err := ParsePolicy(text)
		if err != nil {
			return nil, err
		}
		e.rules = append(e.rules, p.Rules...)
		for _, l := range p.Links {
			e.links[l.Sub] = append(e.links[l.Sub], l.Role)
			e.linkSubs[l.Sub] = true
		}
	}
	return e, nil
}

// HasGroupingSubject reports whether a g line starts with sub. Argo CD only
// considers a user's group when the policy names it in a g line.
func (e *Enforcer) HasGroupingSubject(sub string) bool { return e.linkSubs[sub] }

// hasLink is Casbin's role manager: sub == role, or sub reaches role through
// g links within MaxRoleDepth steps.
func (e *Enforcer) hasLink(sub, role string) bool {
	if sub == role {
		return true
	}
	seen := map[string]bool{sub: true}
	frontier := []string{sub}
	for depth := 0; depth < MaxRoleDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, s := range frontier {
			for _, r := range e.links[s] {
				if r == role {
					return true
				}
				if !seen[r] {
					seen[r] = true
					next = append(next, r)
				}
			}
		}
		frontier = next
	}
	return false
}

func (e *Enforcer) match(val, pattern string) bool {
	if e.matchMode == RegexMatchMode {
		return e.regexMatch(val, pattern)
	}
	return globMatch(pattern, val)
}

// regexMatch is Casbin's RegexMatch: regexp.MatchString(pattern, val),
// unanchored. An invalid pattern never matches (Casbin panics, and Argo CD's
// enforce treats the resulting error as false).
func (e *Enforcer) regexMatch(val, pattern string) bool {
	if v, ok := e.regexes.Load(pattern); ok {
		if re, ok := v.(*regexp.Regexp); ok {
			return re.MatchString(val)
		}
		return false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		e.regexes.Store(pattern, err)
		return false
	}
	e.regexes.Store(pattern, re)
	return re.MatchString(val)
}

// enforceRaw is Casbin's Enforce: some allow and no deny among matching rules.
func (e *Enforcer) enforceRaw(sub, res, act, obj string) bool {
	allow := false
	for i := range e.rules {
		r := &e.rules[i]
		if !e.hasLink(sub, r.Sub) || !e.match(res, r.Res) || !e.match(act, r.Act) || !e.match(obj, r.Obj) {
			continue
		}
		if r.Deny {
			return false
		}
		allow = true
	}
	return allow
}

// Enforce is Argo CD's enforce for a string subject: the default role is
// checked first, then the subject.
func (e *Enforcer) Enforce(sub, res, act, obj string) bool {
	if e.defaultRole != "" && e.enforceRaw(e.defaultRole, res, act, obj) {
		return true
	}
	return e.enforceRaw(sub, res, act, obj)
}

// EnforceClaims is RBACPolicyEnforcer.EnforceClaims for a resolved subject
// and its group values: default role, then the subject, then each group
// that appears as the first element of a g line. The Enforcer must already
// include the project's runtime policy when the request is project scoped.
func (e *Enforcer) EnforceClaims(subject string, groups []string, res, act, obj string) bool {
	if e.Enforce(subject, res, act, obj) {
		return true
	}
	for _, g := range groups {
		if !e.linkSubs[g] {
			continue
		}
		if e.Enforce(g, res, act, obj) {
			return true
		}
	}
	return false
}

// ProjectScoped lists the resources whose object is "<project>/<name>".
var ProjectScoped = map[string]bool{
	ResourceApplications:    true,
	ResourceApplicationSets: true,
	ResourceLogs:            true,
	ResourceExec:            true,
	ResourceClusters:        true,
	ResourceRepositories:    true,
}

// ProjectFromRequest returns the project name a request refers to, as
// getProjectFromRequest does: the first path segment of the object for
// project-scoped resources (when there is a "/"), the object itself for
// projects, "" otherwise.
func ProjectFromRequest(res, obj string) string {
	switch {
	case ProjectScoped[res]:
		if parts := strings.Split(obj, "/"); len(parts) >= 2 {
			return parts[0]
		}
	case res == ResourceProjects:
		return obj
	}
	return ""
}

// ParseScopes parses the "scopes" config map value, a YAML/JSON flow list
// such as "[groups, email]". Argo CD uses a YAML parser; the flow form is
// the only one documented and the only one accepted here.
func ParseScopes(v string) ([]string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	if !strings.HasPrefix(v, "[") || !strings.HasSuffix(v, "]") {
		return nil, errors.New("scopes must be a list such as [groups, email]")
	}
	var out []string
	for _, s := range strings.Split(v[1:len(v)-1], ",") {
		s = strings.TrimSpace(s)
		s = strings.Trim(s, `"'`)
		if s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}
