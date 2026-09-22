package integration

import (
	"reflect"
	"strings"
	"testing"
)

func TestTemplateValidation(t *testing.T) {
	good := []string{"{email}", "{local}", "oidc:{email}", "{local}-acme", "{domain}/{local}", "{local}.{domain}", "x{email}y"}
	for _, tpl := range good {
		if _, err := ParseTemplate(tpl); err != nil {
			t.Errorf("ParseTemplate(%q): %v", tpl, err)
		}
	}
	bad := map[string]string{
		"":                 "empty",
		"  ":               "empty",
		"static":           "must contain",
		"{domain}":         "must contain",
		"{user}":           "unknown placeholder {user}",
		"{email}{name}":    "unknown placeholder {name}",
		"{email":           "unclosed",
		"{local}{":         "unclosed",
		"{local}{email":    "unclosed",
		"{local}}":         "unbalanced",
		"{local}{{email}}": "unclosed",
		"{Email}":          "unknown placeholder {Email}",
		"{ email }":        "unknown placeholder { email }",
	}
	for tpl, want := range bad {
		err := ValidateTemplate(tpl)
		if err == nil {
			t.Errorf("ValidateTemplate(%q) accepted", tpl)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateTemplate(%q) = %v, want %q", tpl, err, want)
		}
		if _, err := ParseTemplate(tpl); err == nil {
			t.Errorf("ParseTemplate(%q) accepted", tpl)
		}
	}
}

func TestTemplateRender(t *testing.T) {
	cases := []struct{ tpl, email, want string }{
		{"{email}", "dana@example.com", "dana@example.com"},
		{"{local}", "dana@example.com", "dana"},
		{"{domain}-{local}", "dana@example.com", "example.com-dana"},
		{"oidc:{email}", "Dana@Example.com", "oidc:Dana@Example.com"},
		{"{local}@corp", "dana@example.com", "dana@corp"},
		// No @: the whole value is the local part, the domain is empty.
		{"{local}/{domain}", "dana", "dana/"},
		// Only the first @ splits the address.
		{"{local}|{domain}", "a@b@c", "a|b@c"},
		// The rendered value is not re-scanned for placeholders.
		{"{local}", "{domain}@example.com", "{domain}"},
	}
	for _, c := range cases {
		tpl, err := ParseTemplate(c.tpl)
		if err != nil {
			t.Fatalf("%q: %v", c.tpl, err)
		}
		if got := tpl.Render(c.email); got != c.want {
			t.Errorf("%q.Render(%q) = %q, want %q", c.tpl, c.email, got, c.want)
		}
	}
}

func TestEmailDomain(t *testing.T) {
	for in, want := range map[string]string{"dana@Example.COM": "example.com", "dana": "", "dana@": "", "a@b@c": "b@c"} {
		if got := EmailDomain(in); got != want {
			t.Errorf("EmailDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseEmailDomains(t *testing.T) {
	good := map[string][]string{
		"acme.com":                   {"acme.com"},
		"acme.com,acme.io":           {"acme.com", "acme.io"},
		"acme.com, acme.io":          {"acme.com", "acme.io"},
		" acme.com ,\tacme.io ":      {"acme.com", "acme.io"},
		"Acme.com,ACME.IO":           {"acme.com", "acme.io"},
		"acme.com,acme.com,Acme.com": {"acme.com"},
		"corp.example":               {"corp.example"},
		"localhost":                  {"localhost"},
		"xn--bcher-kva.example":      {"xn--bcher-kva.example"},
		"a-b.c1.example, 1.2.3.4":    {"a-b.c1.example", "1.2.3.4"},
	}
	for in, want := range good {
		got, err := ParseEmailDomains(in)
		if err != nil {
			t.Errorf("ParseEmailDomains(%q): %v", in, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ParseEmailDomains(%q) = %v, want %v", in, got, want)
		}
		if err := ValidateEmailDomains(in); err != nil {
			t.Errorf("ValidateEmailDomains(%q): %v", in, err)
		}
	}
	bad := []string{
		"", " ", ",", "acme.com,", ",acme.com", "acme.com,,acme.io", "acme.com, ,acme.io",
		"acme.com;acme.io", "a b.com", "a/b", "exa_mple.com", "acme.com.", ".acme.com", "acme..com",
		"-acme.com", "acme-.com", "acme.com:443", "@acme.com", "*.acme.com", "acmé.com",
		strings.Repeat("a", 64) + ".com", strings.Repeat("ab.", 90) + "com",
	}
	for _, in := range bad {
		if _, err := ParseEmailDomains(in); err == nil {
			t.Errorf("ParseEmailDomains(%q) accepted", in)
		}
		if err := ValidateEmailDomains(in); err == nil {
			t.Errorf("ValidateEmailDomains(%q) accepted", in)
		}
	}
	// The error names the offending entry, not the whole list.
	if _, err := ParseEmailDomains("acme.com, bad_domain.io"); err == nil || !strings.Contains(err.Error(), `"bad_domain.io"`) {
		t.Errorf("error should name the bad entry: %v", err)
	}
}
