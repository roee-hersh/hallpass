package rbac

import "testing"

func TestGlob(t *testing.T) {
	cases := []struct {
		pattern, text string
		want          bool
	}{
		{"*", "", true},
		{"*", "anything/with/slashes", true},
		{"*/*", "foo/bar", true},
		{"*/*", "foo", false},
		{"*/*", "foo/bar/baz", true}, // no separators: * crosses /
		{"foo/*", "foo/bar", true},
		{"foo/*", "foo/", true},
		{"foo/*", "bar/foo", false},
		{"**", "a/b/c", true},
		{"a**b", "a/x/b", true},
		{"?", "a", true},
		{"?", "ab", false},
		{"?", "", false},
		{"a?c", "abc", true},
		{"a?c", "a/c", true},
		{"[abc]", "b", true},
		{"[abc]", "d", false},
		{"[!abc]", "d", true},
		{"[!abc]", "a", false},
		{"[a-z]x", "qx", true},
		{"[a-z]x", "Qx", false},
		{"{foo,bar}/*", "foo/x", true},
		{"{foo,bar}/*", "bar/x", true},
		{"{foo,bar}/*", "baz/x", false},
		{"{*.go,*.md}", "main.go", true},
		{"{*.go,*.md}", "README.md", true},
		{"{*.go,*.md}", "main.rs", false},
		{"{a,{b,c}}", "c", true},
		{"{a,{b,c}}", "d", false},
		{`\*`, "*", true},
		{`\*`, "x", false},
		{`a\,b`, "a,b", true},
		{"https://github.com/*/*.git", "https://github.com/argoproj/argo-cd.git", true},
		{"https://github.com/*/*.git", "https://github.com/argo-cd.git", false},
		{"action/*", "action/argoproj.io/Rollout/resume", true},
		{"action/argoproj.io/Rollout/*", "action/argoproj.io/Rollout/resume", true},
		{"action/argoproj.io/Rollout/*", "action/argoproj.io/NewCrd/abort", false},
		{"update", "update/apps/Deployment/ns/name", false},
		{"update/*", "update/apps/Deployment/ns/name", true},
		{"proj:*:admin", "proj:foo:admin", true},
		{"", "", true},
		{"", "a", false},
		{"a,b", "a,b", true},
		{"a}b", "a}b", true},
		{"日本*", "日本語", true},
		{"[日-語]", "本", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.text); got != c.want {
			t.Errorf("glob(%q, %q) = %v, want %v", c.pattern, c.text, got, c.want)
		}
	}
}

func TestGlobInvalid(t *testing.T) {
	for _, bad := range []string{"[abc", "{a,b", "a\\", "[]", "[z-a]"} {
		if _, err := parseGlob(bad); err == nil {
			t.Errorf("parseGlob(%q) accepted", bad)
		}
		if globMatch(bad, bad) {
			t.Errorf("invalid pattern %q matched", bad)
		}
	}
}

func TestGlobNoBlowup(t *testing.T) {
	pattern := "*a*a*a*a*a*a*a*a*a*a*a*a*b"
	text := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"
	if globMatch(pattern, text) {
		t.Fatal("should not match")
	}
}
