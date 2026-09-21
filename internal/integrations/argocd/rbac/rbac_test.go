package rbac

// These tests are ported from argo-cd/util/rbac/rbac_test.go and
// argo-cd/server/rbacpolicy/rbacpolicy_test.go. Names are kept so a reader
// can compare them with upstream.

import (
	"strconv"
	"strings"
	"testing"
)

func mustEnforcer(t *testing.T, o Options) *Enforcer {
	t.Helper()
	e, err := NewEnforcer(o)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestPolicyCSV(t *testing.T) {
	if PolicyCSV(map[string]string{}) != "" {
		t.Error("empty")
	}
	data := map[string]string{PolicyCSVKey: "policy1\npolicy2", "UnrelatedKey": "unrelated value"}
	if PolicyCSV(data) != "policy1\npolicy2" {
		t.Error("default key only")
	}
	data = map[string]string{PolicyCSVKey: "policy1", "UnrelatedKey": "x", "policy.overlay1.csv": "policy2", "policy.overlay2.csv": "policy3"}
	p := PolicyCSV(data)
	if !strings.HasPrefix(p, "policy1") || !strings.Contains(p, "policy2") || !strings.Contains(p, "policy3") {
		t.Error(p)
	}
	data = map[string]string{"UnrelatedKey": "x", "policy.B.csv": "policyb", "policy.A.csv": "policya", "policy.C.csv": "policyc", PolicyCSVKey: "policy1"}
	got := strings.Split(PolicyCSV(data), "\n")
	if len(got) != 4 || got[0] != "policy1" || got[1] != "policya" || got[2] != "policyb" || got[3] != "policyc" {
		t.Error(got)
	}
}

func TestBuiltinPolicyEnforcer(t *testing.T) {
	// Without the builtin policy nothing is allowed.
	e := mustEnforcer(t, Options{})
	if e.Enforce("admin", "applications", "get", "foo/bar") {
		t.Error("no policy should deny")
	}
	e = mustEnforcer(t, Options{Builtin: BuiltinPolicyCSV})
	allowed := [][4]string{
		{"admin", "applications", "get", "foo/bar"},
		{"admin", "applications", "delete", "foo/bar"},
		{"role:readonly", "applications", "get", "foo/bar"},
		{"role:admin", "applications", "get", "foo/bar"},
		{"role:admin", "applications", "delete", "foo/bar"},
		{"role:admin", "applications", "sync", "foo/bar"},
	}
	for _, a := range allowed {
		if !e.Enforce(a[0], a[1], a[2], a[3]) {
			t.Errorf("%v: expected true", a)
		}
	}
	disallowed := [][4]string{
		{"role:readonly", "applications", "create", "foo/bar"},
		{"role:readonly", "applications", "delete", "foo/bar"},
		{"role:readonly", "applications", "rollback", "foo/bar"},
		// v3.5.3's builtin policy has no rollback line; unreleased master adds one.
		{"role:admin", "applications", "rollback", "foo/bar"},
	}
	for _, a := range disallowed {
		if e.Enforce(a[0], a[1], a[2], a[3]) {
			t.Errorf("%v: expected false", a)
		}
	}
}

func TestProjectIsolationEnforcement(t *testing.T) {
	e := mustEnforcer(t, Options{Builtin: `
p, role:foo-admin, *, *, foo/*, allow
p, role:bar-admin, *, *, bar/*, allow
g, alice, role:foo-admin
g, bob, role:bar-admin
`})
	if !e.Enforce("bob", "applications", "delete", "bar/obj") || e.Enforce("bob", "applications", "delete", "foo/obj") {
		t.Error("bob")
	}
	if !e.Enforce("alice", "applications", "delete", "foo/obj") || e.Enforce("alice", "applications", "delete", "bar/obj") {
		t.Error("alice")
	}
}

func TestProjectReadOnly(t *testing.T) {
	e := mustEnforcer(t, Options{Builtin: "p, role:foo-readonly, *, get, foo/*, allow\ng, alice, role:foo-readonly\n"})
	if !e.Enforce("alice", "applications", "get", "foo/obj") {
		t.Error("alice get")
	}
	if e.Enforce("alice", "applications", "delete", "bar/obj") || e.Enforce("alice", "applications", "get", "bar/obj") || e.Enforce("bob", "applications", "get", "foo/obj") {
		t.Error("denies")
	}
}

func TestDefaultRole(t *testing.T) {
	e := mustEnforcer(t, Options{Builtin: BuiltinPolicyCSV})
	if e.Enforce("bob", "applications", "get", "foo/bar") {
		t.Error("bob without default role")
	}
	e = mustEnforcer(t, Options{Builtin: BuiltinPolicyCSV, DefaultRole: "role:readonly"})
	if !e.Enforce("bob", "applications", "get", "foo/bar") {
		t.Error("bob with default role")
	}
	// A user-level deny cannot block the default role: it is checked first.
	e = mustEnforcer(t, Options{Builtin: BuiltinPolicyCSV, User: "p, bob, applications, get, foo/bar, deny", DefaultRole: "role:readonly"})
	if !e.Enforce("bob", "applications", "get", "foo/bar") {
		t.Error("default role is checked before the subject")
	}
}

func TestURLAsObjectName(t *testing.T) {
	e := mustEnforcer(t, Options{User: `
p, alice, repositories, *, foo/*, allow
p, bob, repositories, *, foo/https://github.com/argoproj/argo-cd.git, allow
p, cathy, repositories, *, foo/*, allow
`})
	if !e.Enforce("alice", "repositories", "delete", "foo/https://github.com/argoproj/argo-cd.git") || !e.Enforce("alice", "repositories", "delete", "foo/https://github.com/golang/go.git") {
		t.Error("alice")
	}
	if !e.Enforce("bob", "repositories", "delete", "foo/https://github.com/argoproj/argo-cd.git") || e.Enforce("bob", "repositories", "delete", "foo/https://github.com/golang/go.git") {
		t.Error("bob")
	}
}

func TestDenyOverridesAllow(t *testing.T) {
	e := mustEnforcer(t, Options{User: "p, alice, *, get, foo/obj, allow\np, mike, *, get, foo/obj, deny\n"})
	if !e.Enforce("alice", "applications", "get", "foo/obj") || e.Enforce("alice", "applications/resources", "delete", "foo/obj") {
		t.Error("alice")
	}
	if e.Enforce("mike", "applications", "get", "foo/obj") {
		t.Error("mike deny")
	}
	if e.Enforce("", "applications/resources", "delete", "foo/obj") {
		t.Error("empty subject")
	}
	e = mustEnforcer(t, Options{Builtin: BuiltinPolicyCSV, User: "p, admin, applications, delete, prod/*, deny"})
	if e.Enforce("admin", "applications", "delete", "prod/db") || !e.Enforce("admin", "applications", "delete", "dev/db") {
		t.Error("explicit deny on builtin admin")
	}
}

func TestValidatePolicy(t *testing.T) {
	good := []string{
		"p, role:admin, projects, delete, *, allow",
		"",
		"#",
		`p, "role,admin", projects, delete, *, allow`,
		` p, role:admin, projects, delete, *, allow `,
		"g, your-github-org:your-team, role:org-admin",
		"# Some comment",
	}
	for _, g := range good {
		if _, err := ParsePolicy(g); err != nil {
			t.Errorf("%q: %v", g, err)
		}
	}
	bad := []string{
		"this, is, not, a, good, policy",
		"this\ttoo",
		"p",
		"Some comment",
		"agh, foo, bar",
		"p, role:Myrole, applications, *, myproj/* allow",
		", role:Myrole, applications, *, myproj/*, allow",
		"g, only-two",
	}
	for _, b := range bad {
		if _, err := ParsePolicy(b); err == nil {
			t.Errorf("%q accepted", b)
		}
	}
	p, err := ParsePolicy(`p, "role,admin", projects, delete, *, allow`)
	if err != nil || p.Rules[0].Sub != "role,admin" {
		t.Errorf("quoted field: %+v %v", p, err)
	}
	p, _ = ParsePolicy("p, a, b, c, d, maybe")
	if len(p.Rules) != 0 {
		t.Error("unknown effect must not become a rule")
	}
}

func TestGlobMatchModeAndRegexMatchMode(t *testing.T) {
	e := mustEnforcer(t, Options{User: `p, alice, clusters, get, "https://github.com/*/*.git", allow`})
	if !e.Enforce("alice", "clusters", "get", "https://github.com/argoproj/argo-cd.git") {
		t.Error("glob match")
	}
	if e.Enforce("alice", "repositories", "get", "https://github.com/argoproj/argo-cd.git") {
		t.Error("wrong resource")
	}
	if e.Enforce("alice", "clusters", "get", "https://github.com/argo-cd.git") {
		t.Error("glob needs two segments")
	}
	e = mustEnforcer(t, Options{MatchMode: RegexMatchMode, User: `p, alice, clusters, get, "https://github.com/argo[a-z]{4}/argo-[a-z]+.git", allow`})
	if !e.Enforce("alice", "clusters", "get", "https://github.com/argoproj/argo-cd.git") {
		t.Error("regex match")
	}
	if e.Enforce("alice", "clusters", "get", "https://github.com/argoproj/1argo-cd.git") {
		t.Error("regex mismatch")
	}
	// Regex is unanchored, and an invalid regex never matches.
	e = mustEnforcer(t, Options{MatchMode: RegexMatchMode, User: "p, alice, clusters, get, proj, allow\np, bob, clusters, get, (, allow"})
	if !e.Enforce("alice", "clusters", "get", "my-proj-1") {
		t.Error("unanchored")
	}
	if e.Enforce("bob", "clusters", "get", "(") {
		t.Error("invalid regex matched")
	}
}

func TestRoleDepth(t *testing.T) {
	var b strings.Builder
	b.WriteString("p, role:leaf, applications, get, */*, allow\n")
	for i := 0; i < 12; i++ {
		b.WriteString("g, role:l" + itoa(i) + ", role:l" + itoa(i+1) + "\n")
	}
	b.WriteString("g, role:l12, role:leaf\n")
	b.WriteString("g, deep, role:l0\ng, shallow, role:l5\n")
	e := mustEnforcer(t, Options{User: b.String()})
	if e.Enforce("deep", "applications", "get", "a/b") {
		t.Error("13 hops should exceed the Casbin depth of 10")
	}
	if !e.Enforce("shallow", "applications", "get", "a/b") {
		t.Error("8 hops should work")
	}
	// Cycles must not loop forever.
	e = mustEnforcer(t, Options{User: "g, a, b\ng, b, a\np, c, x, y, z, allow"})
	if e.Enforce("a", "x", "y", "z") {
		t.Error("cycle")
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func newFakeProj() *Project {
	return &Project{Name: "my-proj", Roles: []ProjectRole{{
		Name: "my-role",
		Policies: []string{
			"p, proj:my-proj:my-role, applications, create, my-proj/*, allow",
			"p, proj:my-proj:my-role, logs, get, my-proj/*, allow",
			"p, proj:my-proj:my-role, exec, create, my-proj/*, allow",
		},
		Groups: []string{"my-org:my-team"},
	}}}
}

func TestProjectPoliciesString(t *testing.T) {
	got := newFakeProj().PoliciesString()
	want := "p, proj:my-proj:my-role, projects, get, my-proj, allow\n" +
		"p, proj:my-proj:my-role, applications, create, my-proj/*, allow\n" +
		"p, proj:my-proj:my-role, logs, get, my-proj/*, allow\n" +
		"p, proj:my-proj:my-role, exec, create, my-proj/*, allow\n" +
		"g, my-org:my-team, proj:my-proj:my-role"
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

// claims mirrors the upstream test: enforce with a subject and group claims
// against builtin + user + the project's runtime policy.
func claims(t *testing.T, e *Enforcer, sub string, groups []string, res, act, obj string) bool {
	t.Helper()
	return e.EnforceClaims(sub, groups, res, act, obj)
}

func TestEnforceAllPolicies(t *testing.T) {
	proj := newFakeProj()
	e := mustEnforcer(t, Options{
		Builtin: "p, alice, applications, create, my-proj/*, allow\np, alice, logs, get, my-proj/*, allow\np, alice, exec, create, my-proj/*, allow",
		User:    "p, bob, applications, create, my-proj/*, allow\np, bob, logs, get, my-proj/*, allow\np, bob, exec, create, my-proj/*, allow",
		Runtime: proj.PoliciesString(),
	})
	for _, sub := range []string{"alice", "bob", "proj:my-proj:my-role"} {
		if !claims(t, e, sub, nil, "applications", "create", "my-proj/my-app") || !claims(t, e, sub, nil, "logs", "get", "my-proj/my-app") || !claims(t, e, sub, nil, "exec", "create", "my-proj/my-app") {
			t.Errorf("%s should be allowed", sub)
		}
	}
	if !claims(t, e, "", []string{"my-org:my-team"}, "applications", "create", "my-proj/my-app") {
		t.Error("group via project role")
	}
	if !claims(t, e, "", []string{"my-org:my-team"}, "projects", "get", "my-proj") {
		t.Error("project roles get the project")
	}
	if claims(t, e, "cathy", nil, "applications", "create", "my-proj/my-app") {
		t.Error("cathy")
	}
	// A group not named in any g line is ignored even if a p line names it.
	e2 := mustEnforcer(t, Options{User: "p, some-group, applications, get, */*, allow"})
	if claims(t, e2, "", []string{"some-group"}, "applications", "get", "a/b") {
		t.Error("groups without a g line must be ignored (upstream prefilter)")
	}
	if !e2.Enforce("some-group", "applications", "get", "a/b") {
		t.Error("but as a plain subject it matches")
	}
}

func TestEnforceActionActions(t *testing.T) {
	e := mustEnforcer(t, Options{Builtin: `p, alice, applications, action/*, my-proj/*, allow
p, bob, applications, action/argoproj.io/Rollout/*, my-proj/*, allow
p, cam, applications, action/argoproj.io/Rollout/resume, my-proj/*, allow
`})
	if !e.Enforce("alice", "applications", "action/argoproj.io/Rollout/resume", "my-proj/my-app") || !e.Enforce("alice", "applications", "action/argoproj.io/NewCrd/abort", "my-proj/my-app") {
		t.Error("alice")
	}
	if !e.Enforce("bob", "applications", "action/argoproj.io/Rollout/resume", "my-proj/my-app") || e.Enforce("bob", "applications", "action/argoproj.io/NewCrd/abort", "my-proj/my-app") {
		t.Error("bob")
	}
	if !e.Enforce("cam", "applications", "action/argoproj.io/Rollout/resume", "my-proj/my-app") || e.Enforce("cam", "applications", "action/argoproj.io/Rollout/abort", "my-proj/my-app") {
		t.Error("cam")
	}
	if e.Enforce("eve", "applications", "action/argoproj.io/Rollout/resume", "my-proj/my-app") {
		t.Error("eve")
	}
}

func TestFineGrainedNotInherited(t *testing.T) {
	e := mustEnforcer(t, Options{User: "p, alice, applications, update, my-proj/*, allow"})
	if !e.Enforce("alice", "applications", "update", "my-proj/app") {
		t.Error("update")
	}
	if e.Enforce("alice", "applications", "update/apps/Deployment/ns/name", "my-proj/app") {
		t.Error("update must not match update/* on its own; the integration decides inheritance")
	}
}

func TestProjectFromRequest(t *testing.T) {
	cases := []struct{ res, obj, want string }{
		{"repositories", "my-proj/https://github.com/argoproj/argocd-example-apps", "my-proj"},
		{"applicationsets", "my-proj/x", "my-proj"},
		{"applications", "my-proj/ns/x", "my-proj"},
		{"applications", "noslash", ""},
		{"projects", "my-proj", "my-proj"},
		{"accounts", "a/b", ""},
	}
	for _, c := range cases {
		if got := ProjectFromRequest(c.res, c.obj); got != c.want {
			t.Errorf("%s %s = %q", c.res, c.obj, got)
		}
	}
}

func TestParseScopes(t *testing.T) {
	s, err := ParseScopes("[groups, email]")
	if err != nil || len(s) != 2 || s[0] != "groups" || s[1] != "email" {
		t.Error(s, err)
	}
	s, err = ParseScopes(`["cognito:groups"]`)
	if err != nil || len(s) != 1 || s[0] != "cognito:groups" {
		t.Error(s, err)
	}
	if s, err := ParseScopes(""); err != nil || s != nil {
		t.Error("empty")
	}
	if _, err := ParseScopes("groups"); err == nil {
		t.Error("not a list")
	}
}
