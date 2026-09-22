package github

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseTarget: every part of an accepted target is a validated login,
// repository name, team slug or branch, and always inside the configured
// organization.
func FuzzParseTarget(f *testing.F) {
	for _, s := range [][2]string{
		{"repo.read", "repo:acme/webapp"},
		{"repo.push", "repo:acme/webapp@main"},
		{"org.member", "org:acme"},
		{"team.member", "team:acme/platform"},
		{"repo.read", "repo:other/webapp"},
		{"repo.push", "repo:acme/webapp@../x"},
		{"repo.push", "repo:acme/..@main"},
		{"team.member", "team:acme/Platform Team"},
		{"repo.read", "repo:acme/webapp?x=1"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, action, resource string) {
		a, ok := actions[action]
		if !ok {
			return
		}
		res, err := catalog.ParseResource(resource)
		if err != nil {
			return
		}
		tg, err := parseTarget(a, "acme", res)
		if err != nil {
			return
		}
		if tg.owner != "acme" {
			t.Fatalf("owner %q escaped the organization", tg.owner)
		}
		switch tg.kind {
		case "repo":
			if !validRepoName(tg.repo) {
				t.Fatalf("unvalidated repo %q", tg.repo)
			}
			if tg.branch != "" && !validBranch(tg.branch) {
				t.Fatalf("unvalidated branch %q", tg.branch)
			}
			if strings.ContainsAny(tg.repo, "/?#%") || strings.Contains(tg.branch, "..") || strings.ContainsAny(tg.branch, "?@") {
				t.Fatalf("url-significant character in %+v", tg)
			}
		case "team":
			if !slugRe.MatchString(tg.team) || len(tg.team) > 255 {
				t.Fatalf("unvalidated team %q", tg.team)
			}
		case "org":
			if tg.repo != "" || tg.team != "" || tg.branch != "" {
				t.Fatalf("org target carries extra parts %+v", tg)
			}
		default:
			t.Fatalf("unknown kind %q", tg.kind)
		}
	})
}
