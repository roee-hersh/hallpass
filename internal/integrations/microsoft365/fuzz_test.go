package microsoft365

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseRef: every part of an accepted ref matches the strict shape of
// its type (GUIDs where Graph needs GUIDs, no whitespace or control
// characters anywhere), so it is safe as a path segment.
func FuzzParseRef(f *testing.F) {
	for _, s := range [][2]string{
		{"group.member", "group:11111111-2222-3333-4444-555555555555"},
		{"team.member", "team:11111111-2222-3333-4444-555555555555"},
		{"channel.read", "team:11111111-2222-3333-4444-555555555555/channel/19:abc@thread.tacv2"},
		{"file.read", "drive:b!abc/item/01ABC"},
		{"user.active", "user:dana@example.com"},
		{"mail.send_as_self", "mailbox:dana@example.com"},
		{"channel.read", "team:11111111-2222-3333-4444-555555555555"},
		{"team.member", "team:11111111-2222-3333-4444-555555555555/channel/x"},
		{"file.read", "drive:b!abc/item/../x"},
		{"group.member", "group:not-a-guid"},
		{"user.active", "user:dana@example.com?x=1"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, action, resource string) {
		if _, ok := actionResources[action]; !ok {
			return
		}
		res, err := catalog.ParseResource(resource)
		if err != nil {
			return
		}
		ref, err := parseRef(action, res)
		if err != nil {
			return
		}
		if ref.typ != res.Type || len(res.Query) > 0 {
			t.Fatalf("type/query slipped through %+v", res)
		}
		for _, part := range []string{ref.id, ref.channel, ref.item} {
			for _, r := range part {
				if r <= 0x20 || r == 0x7f {
					t.Fatalf("whitespace or control character in %+v", ref)
				}
			}
		}
		switch ref.typ {
		case "user", "mailbox":
			if !emailRe.MatchString(ref.id) && !guidRe.MatchString(ref.id) {
				t.Fatalf("unvalidated id %q", ref.id)
			}
		case "group", "role":
			if !guidRe.MatchString(ref.id) {
				t.Fatalf("unvalidated guid %q", ref.id)
			}
		case "team":
			if !guidRe.MatchString(ref.id) || (ref.channel != "" && !channelIDRe.MatchString(ref.channel)) {
				t.Fatalf("unvalidated team ref %+v", ref)
			}
			if strings.HasPrefix(action, "channel.") && ref.channel == "" || strings.HasPrefix(action, "team.") && ref.channel != "" {
				t.Fatalf("channel presence does not match action %s: %+v", action, ref)
			}
		case "drive":
			if !driveIDRe.MatchString(ref.id) || !driveIDRe.MatchString(ref.item) || strings.Contains(ref.id+ref.item, "/") {
				t.Fatalf("unvalidated drive ref %+v", ref)
			}
		default:
			t.Fatalf("unknown type %q", ref.typ)
		}
	})
}

// FuzzODataString: an escaped literal never contains a lone quote, so it
// cannot end a $filter string early.
func FuzzODataString(f *testing.F) {
	for _, s := range []string{"o'neil", "''", "a' or 1 eq 1 or 'b", "plain@example.com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		lit := odataString(s)
		if len(lit) < 2 || lit[0] != '\'' || lit[len(lit)-1] != '\'' {
			t.Fatalf("literal %q is not quoted", lit)
		}
		inner := lit[1 : len(lit)-1]
		if strings.Contains(strings.ReplaceAll(inner, "''", ""), "'") {
			t.Fatalf("literal %q has a lone quote", lit)
		}
	})
}
