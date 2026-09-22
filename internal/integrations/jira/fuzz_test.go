package jira

import (
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseResource: an accepted key always matches the strict project or
// issue key shape, so it is safe in a URL path.
func FuzzParseResource(f *testing.F) {
	for _, s := range []string{"project:OPS", "issue:OPS-123", "global", "project:ops", "issue:OPS-0", "project:OPS/x", "global:x", "project:OPS?x=1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, resource string) {
		res, err := catalog.ParseResource(resource)
		if err != nil {
			return
		}
		r, err := parseResource(res)
		if err != nil {
			return
		}
		switch r.kind {
		case resGlobal:
			if r.key != "" {
				t.Fatalf("global with key %q", r.key)
			}
		case resProject:
			if !projectKeyRe.MatchString(r.key) {
				t.Fatalf("unvalidated project key %q", r.key)
			}
		case resIssue:
			if !issueKeyRe.MatchString(r.key) {
				t.Fatalf("unvalidated issue key %q", r.key)
			}
		default:
			t.Fatalf("unknown kind %v", r.kind)
		}
	})
}
