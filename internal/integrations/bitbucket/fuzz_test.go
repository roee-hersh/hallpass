package bitbucket

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseTarget: an accepted target is made of validated slugs and, if
// present, a validated branch name, so every piece is safe in a URL path.
func FuzzParseTarget(f *testing.F) {
	for _, s := range [][2]string{
		{"repo.read", "repo:api"},
		{"repo.push", "repo:api@release/1.2"},
		{"repo.push", "repo:APP/api@main"},
		{"project.read", "project:APP"},
		{"workspace.member", "workspace"},
		{"repo.read", "repo:api@main"},
		{"repo.push", "repo:api@a..b"},
		{"repo.read", "repo:a/b/c"},
		{"repo.read", "repo:api?x=1"},
		{"project.read", "project:~dana"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, action, resource string) {
		res, err := catalog.ParseResource(resource)
		if err != nil {
			return
		}
		for _, dc := range []bool{false, true} {
			tg, err := parseTarget(action, res, dc)
			if err != nil {
				continue
			}
			if len(res.Query) > 0 {
				t.Fatalf("query slipped through %+v", res)
			}
			if tg.action.name != action {
				t.Fatalf("action %q became %q", action, tg.action.name)
			}
			if tg.project != "" && !validSlug(tg.project) {
				t.Fatalf("unvalidated project %q from %q", tg.project, resource)
			}
			if tg.repo != "" && !validSlug(tg.repo) {
				t.Fatalf("unvalidated repo %q from %q", tg.repo, resource)
			}
			if tg.branch != "" && (!validBranch(tg.branch) || tg.action.branch == "") {
				t.Fatalf("unvalidated branch %q from %q", tg.branch, resource)
			}
			if strings.ContainsAny(tg.project+tg.repo, "/?#\\ ") {
				t.Fatalf("path characters in %+v", tg)
			}
			if dc && tg.repo != "" && tg.project == "" {
				t.Fatalf("data center repo without project from %q", resource)
			}
			if !dc && tg.repo != "" && tg.project != "" {
				t.Fatalf("cloud repo with project from %q", resource)
			}
		}
	})
}
