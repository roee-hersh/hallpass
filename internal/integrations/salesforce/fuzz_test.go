package salesforce

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseTarget: every part of an accepted target matches the strict
// identifier shapes, so nothing that could break out of a SOQL statement
// is ever interpolated. Emails are the one free-text value; they must
// round-trip through net/mail and carry no control characters.
func FuzzParseTarget(f *testing.F) {
	for _, s := range [][2]string{
		{"record.read", "record:001000000000001AAA"},
		{"object.create", "object:Invoice__c"},
		{"field.edit", "field:Account.Rating"},
		{"system.permission", "permission:PermissionsApiEnabled"},
		{"permset.assigned", "permset:acme__Sales_Ops"},
		{"user.active", "user:dana@example.com"},
		{"user.active", "user:o'neil@example.com"},
		{"user.active", "user:Dana <dana@example.com>"},
		{"object.read", "object:Account' OR 1=1"},
		{"record.read", "record:001000000000001AAA?x=1"},
		{"permset.assigned", "permset:a__b__c"},
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
		tg, err := parseTarget(a, res)
		if err != nil {
			return
		}
		if tg.recordID != "" && !idRe.MatchString(tg.recordID) {
			t.Fatalf("unvalidated id %q", tg.recordID)
		}
		for _, n := range []string{tg.object, tg.field, tg.permSet, tg.permSetNS} {
			if n != "" && !apiNameRe.MatchString(n) {
				t.Fatalf("unvalidated api name %q", n)
			}
		}
		if tg.perm != "" && !permNameRe.MatchString(tg.perm) {
			t.Fatalf("unvalidated permission %q", tg.perm)
		}
		if strings.Contains(tg.permSet, "__") || strings.Contains(tg.permSetNS, "__") {
			t.Fatalf("namespace separator left in %+v", tg)
		}
		if tg.email != "" {
			if validateEmail(tg.email) != nil {
				t.Fatalf("unvalidated email %q", tg.email)
			}
			lit := soqlString(tg.email)
			// An escaped literal never holds a bare quote or a control byte.
			if strings.ContainsAny(lit, "\n\r\t") || strings.Contains(strings.ReplaceAll(lit, `\'`, ""), "'") {
				t.Fatalf("literal %q not inert", lit)
			}
		}
	})
}

// FuzzSOQLString: the escaped literal never contains an unescaped quote,
// and every backslash is part of an escape sequence.
func FuzzSOQLString(f *testing.F) {
	for _, s := range []string{`a'b`, `a\'b`, `\`, "a\nb", `"`, `\\'`, "plain@example.com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		lit := soqlString(s)
		for i := 0; i < len(lit); i++ {
			switch lit[i] {
			case '\\':
				if i+1 >= len(lit) || !strings.ContainsRune(`\'"nrt`, rune(lit[i+1])) {
					t.Fatalf("dangling backslash in %q", lit)
				}
				i++
			case '\'', '"', '\n', '\r', '\t':
				t.Fatalf("unescaped %q in %q", lit[i], lit)
			}
		}
	})
}
