package zendesk

import (
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseTarget: an accepted id is a plain decimal Zendesk id, and the
// resource type is the one the action takes.
func FuzzParseTarget(f *testing.F) {
	for _, s := range [][2]string{
		{"ticket.view", "ticket:123"}, {"organization.edit", "organization:5"}, {"user.edit", "user:1"},
		{"account.admin", "account"}, {"ticket.view", "ticket:1/2"}, {"ticket.view", "ticket:1?x=y"},
		{"ticket.view", "ticket:-1"}, {"account.admin", "account:1"},
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
		if tg.action.resource == "account" {
			if tg.id != "" {
				t.Fatalf("account with id %+v", tg)
			}
			return
		}
		if !idRe.MatchString(tg.id) {
			t.Fatalf("unvalidated id %q from %q", tg.id, resource)
		}
		for _, r := range tg.id {
			if r < '0' || r > '9' {
				t.Fatalf("non-digit in id %q", tg.id)
			}
		}
	})
}
