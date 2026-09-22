package gitlab

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseTarget: whatever the caller sends, an accepted target is a
// numeric id or a clean path, and a branch is a plausible git ref with
// nothing that changes the meaning of a URL.
func FuzzParseTarget(f *testing.F) {
	for _, s := range [][2]string{
		{"project.read", "project:acme/webapp"},
		{"repo.push", "project:acme/webapp@main"},
		{"repo.push", "project:42@release/1.0"},
		{"member.manage", "group:acme"},
		{"repo.push", "project:acme/../admin@x"},
		{"repo.push", "project:acme/webapp@"},
		{"repo.push", "project:acme/webapp@a b"},
		{"project.read", "project:acme/webapp?x=1"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, action, resource string) {
		spec, ok := actions[action]
		if !ok {
			return
		}
		res, err := catalog.ParseResource(resource)
		if err != nil {
			return
		}
		tg, err := parseTarget(spec, res)
		if err != nil {
			return
		}
		if tg.scope != spec.scope || tg.id == "" {
			t.Fatalf("scope/id %+v", tg)
		}
		if !numericRe.MatchString(tg.id) && !pathRe.MatchString(tg.id) {
			t.Fatalf("unvalidated id %q", tg.id)
		}
		for _, seg := range strings.Split(tg.id, "/") {
			if seg == "." || seg == ".." {
				t.Fatalf("dot segment in %q", tg.id)
			}
		}
		if tg.branch != "" && (!branchRe.MatchString(tg.branch) || strings.Contains(tg.branch, "..") || strings.HasPrefix(tg.branch, "-")) {
			t.Fatalf("unvalidated branch %q", tg.branch)
		}
		if spec.scope != scopeProject && tg.branch != "" {
			t.Fatalf("branch on a %s resource", spec.scope)
		}
	})
}
