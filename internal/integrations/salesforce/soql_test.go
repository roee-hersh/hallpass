package salesforce

import (
	"strings"
	"testing"
)

func TestSoqlString(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain@example.com", "plain@example.com"},
		{"o'neil@example.com", `o\'neil@example.com`},
		{"x' OR 1=1--", `x\' OR 1=1--`},
		{`\'`, `\\\'`},
		{`a\b`, `a\\b`},
		{"line1\nline2", `line1\nline2`},
		{"cr\rlf\n", `cr\rlf\n`},
		{"tab\there", `tab\there`},
		{`say "hi"`, `say \"hi\"`},
		{"' OR Username != '", `\' OR Username != \'`},
		{"", ""},
		{"ünïcödé", "ünïcödé"},
	}
	for _, c := range cases {
		if got := soqlString(c.in); got != c.want {
			t.Errorf("soqlString(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// An escaped literal never contains a bare quote or backslash: every
	// quote is preceded by an odd run of backslashes.
	for _, in := range []string{"'", "''", `\`, `\\'`, `'\`, "a'b\\c'd"} {
		out := soqlString(in)
		for i := 0; i < len(out); i++ {
			if out[i] != '\'' {
				continue
			}
			n := 0
			for j := i - 1; j >= 0 && out[j] == '\\'; j-- {
				n++
			}
			if n%2 == 0 {
				t.Errorf("soqlString(%q) = %q leaves an unescaped quote at %d", in, out, i)
			}
		}
	}
}

func TestValidators(t *testing.T) {
	for _, ok := range []string{"001000000000001", "001000000000001AAA", "0055g00000AbCdEfGH"} {
		if err := validateID(ok); err != nil {
			t.Errorf("id %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "001", "001000000000001'", "001000000000001AA", "0010000000000010000", "001-00000000001", "001000000000001AAAA"} {
		if err := validateID(bad); err == nil {
			t.Errorf("id %q accepted", bad)
		}
	}
	for _, ok := range []string{"Account", "Invoice__c", "Custom_Metadata__mdt", "Order_Event__e", "npsp__Household__c", "a"} {
		if err := validateAPIName(ok); err != nil {
			t.Errorf("api name %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "_x", "1abc", "Account'", "Account Name", "Parent.Name", "Account;", strings.Repeat("a", 81)} {
		if err := validateAPIName(bad); err == nil {
			t.Errorf("api name %q accepted", bad)
		}
	}
	for _, ok := range []string{"PermissionsApiEnabled", "PermissionsViewSetup", "PermissionsModifyAllData"} {
		if err := validatePermissionName(ok); err != nil {
			t.Errorf("perm %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Permissions", "ApiEnabled", "PermissionsApi_Enabled", "PermissionsApiEnabled = true OR Id != null", "permissionsApiEnabled", "PermissionsApiEnabled'"} {
		if err := validatePermissionName(bad); err == nil {
			t.Errorf("perm %q accepted", bad)
		}
	}
	for _, ok := range []string{"dana@example.com", "o'neil@example.com", "first.last+tag@sub.example.co"} {
		if err := validateEmail(ok); err != nil {
			t.Errorf("email %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "dana", "Dana <dana@example.com>", "<dana@example.com>", "dana@example.com\n", "dana@exa\x00mple.com", "a@b.c' OR 1=1--", "x' OR 1=1--@example.com", "(comment)dana@example.com", " dana@example.com"} {
		if err := validateEmail(bad); err == nil {
			t.Errorf("email %q accepted", bad)
		}
	}
	if got := soqlIDList([]string{"001000000000001", "001000000000002AAA"}); got != "'001000000000001','001000000000002AAA'" {
		t.Error(got)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("soqlIDList accepted an unvalidated id")
			}
		}()
		soqlIDList([]string{"x') OR (1=1"})
	}()
}
