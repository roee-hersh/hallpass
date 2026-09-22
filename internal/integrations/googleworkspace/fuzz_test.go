package googleworkspace

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseRef: an accepted id matches the strict shape of its type, so it
// is safe as a path segment or a query value.
func FuzzParseRef(f *testing.F) {
	for _, s := range [][2]string{
		{"drive.file.read", "file:1AbCdEfGhIjKlMnOpQrStUvWxYz"},
		{"calendar.read", "calendar:primary"},
		{"calendar.read", "calendar:team@example.com"},
		{"group.member", "group:eng@example.com"},
		{"user.active", "user:Dana@Example.com"},
		{"mail.send_as", "mailbox:dana@example.com"},
		{"drive.file.read", "file:../x"},
		{"user.active", "user:dana@example.com/x"},
		{"calendar.read", "calendar:a?b"},
		{"group.member", "group:eng@example.com?x=1"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, action, resource string) {
		i, ok := actionIndex[action]
		if !ok {
			return
		}
		res, err := catalog.ParseResource(resource)
		if err != nil {
			return
		}
		id, err := parseRef(action, res)
		if err != nil {
			return
		}
		if res.Type != actionList[i].resource || len(res.Query) > 0 {
			t.Fatalf("type/query slipped through %+v", res)
		}
		// Ids are path-escaped before use; the regexes must still keep out
		// whitespace and control characters.
		for _, r := range id {
			if r <= 0x20 || r == 0x7f {
				t.Fatalf("whitespace or control character in %q", id)
			}
		}
		switch res.Type {
		case "user", "mailbox", "group":
			if !emailRe.MatchString(id) || id != strings.ToLower(id) {
				t.Fatalf("unvalidated email %q", id)
			}
		case "file":
			if !fileIDRe.MatchString(id) {
				t.Fatalf("unvalidated file id %q", id)
			}
		case "calendar":
			if !calendarIDRe.MatchString(id) {
				t.Fatalf("unvalidated calendar id %q", id)
			}
		default:
			t.Fatalf("unknown type %q", res.Type)
		}
	})
}
