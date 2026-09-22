package slack

import (
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzValidateResource: an accepted id is a Slack channel or user group id
// and never anything else that could reach a query string.
func FuzzValidateResource(f *testing.F) {
	for _, s := range [][2]string{
		{"channel.read", "channel:C0123456789"},
		{"usergroup.member", "usergroup:S0123456789"},
		{"user.active", "workspace"},
		{"channel.read", "channel:c0123456789"},
		{"channel.read", "channel:C0123456789&x=1"},
		{"user.active", "workspace:x"},
		{"channel.read", "channel:C0123456789?x=1"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, action, resource string) {
		res, err := catalog.ParseResource(resource)
		if err != nil {
			return
		}
		a, err := validateResource(action, res)
		if err != nil {
			return
		}
		if a.resource != res.Type || len(res.Query) > 0 {
			t.Fatalf("type/query slipped through %+v %+v", a, res)
		}
		switch a.resource {
		case resWorkspace:
			if res.ID != "" {
				t.Fatalf("workspace with id %q", res.ID)
			}
		case resChannel:
			if !channelIDRe.MatchString(res.ID) {
				t.Fatalf("unvalidated channel %q", res.ID)
			}
		case resUsergroup:
			if !usergroupIDRe.MatchString(res.ID) {
				t.Fatalf("unvalidated usergroup %q", res.ID)
			}
		default:
			t.Fatalf("unknown resource type %q", a.resource)
		}
	})
}
