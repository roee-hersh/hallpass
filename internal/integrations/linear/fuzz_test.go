package linear

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseTarget: an accepted id is a Linear uuid, an upper-case team key,
// an upper-case issue identifier or a project slug, with no query.
func FuzzParseTarget(f *testing.F) {
	for _, s := range [][2]string{
		{"team.view", "team:ENG"}, {"issue.view", "issue:ENG-123"}, {"project.view", "project:abc-def"},
		{"workspace.admin", "workspace"}, {"team.view", "team:00000000-0000-4000-8000-000000000001"},
		{"issue.view", "issue:eng-1"}, {"team.view", "team:ENG?x=y"}, {"team.view", "team:a b"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, action, resource string) {
		res, err := catalog.ParseResource(resource)
		if err != nil {
			return
		}
		tg, err := parseTarget(action, res)
		if err != nil {
			return
		}
		if len(res.Query) > 0 {
			t.Fatalf("query slipped through %+v", res)
		}
		if tg.action.resource != res.Type {
			t.Fatalf("type %q for action %q", res.Type, action)
		}
		if tg.action.resource == "workspace" {
			if tg.id != "" {
				t.Fatalf("workspace with id %+v", tg)
			}
			return
		}
		if tg.byID {
			if !uuidRe.MatchString(tg.id) || tg.id != strings.ToLower(tg.id) {
				t.Fatalf("byID with %q", tg.id)
			}
			return
		}
		var ok bool
		switch tg.action.resource {
		case "team":
			ok = teamKeyRe.MatchString(tg.id)
		case "issue":
			ok = issueKeyRe.MatchString(tg.id)
		case "project":
			ok = slugRe.MatchString(tg.id)
		}
		if !ok || strings.ContainsAny(tg.id, " /?#\"\\") {
			t.Fatalf("unvalidated id %q from %q", tg.id, resource)
		}
	})
}
