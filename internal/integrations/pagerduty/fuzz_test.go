package pagerduty

import (
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseTarget: an accepted id is upper-case alphanumeric, so it is safe
// as a path segment.
func FuzzParseTarget(f *testing.F) {
	for _, s := range [][2]string{
		{"incident.acknowledge", "incident:PINC1"},
		{"service.edit", "service:psvc1"},
		{"account.admin", "account"},
		{"team.member", "team:PTEAM1/x"},
		{"team.member", "team:P TEAM"},
		{"account.admin", "account:x"},
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
		if tg.action.name != action {
			t.Fatalf("action %q became %q", action, tg.action.name)
		}
		if tg.action.resource == "account" {
			if tg.id != "" {
				t.Fatalf("account with id %q", tg.id)
			}
			return
		}
		if !idRe.MatchString(tg.id) {
			t.Fatalf("unvalidated id %q from %q", tg.id, resource)
		}
	})
}
