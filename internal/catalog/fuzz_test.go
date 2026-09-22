package catalog

import (
	"strings"
	"testing"
	"unicode"
)

// FuzzParseResource checks the parser's invariants: it never panics, an
// accepted resource has a well-formed type, no control characters survive,
// and the parts re-assemble to the input.
func FuzzParseResource(f *testing.F) {
	for _, s := range []string{"repo:acme/api", "global", "namespace:payments?resource=deployments.apps&name=api", "cluster?resource=nodes", "nonresource:/metrics", "arn:aws:s3:::b/k", "", "x:", ":x", "a?b=c&b=d", "a?%zz", "type:id?k=v#frag", "日本:語"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		r, err := ParseResource(raw)
		if err != nil {
			return
		}
		if !typeRe.MatchString(r.Type) {
			t.Fatalf("accepted type %q", r.Type)
		}
		for _, c := range raw {
			if c < 0x20 || c == 0x7f {
				t.Fatalf("control character accepted in %q", raw)
			}
		}
		head := r.Type
		if strings.Contains(raw, ":") && (r.ID != "" || strings.HasPrefix(strings.TrimPrefix(raw, r.Type), ":")) {
			head += ":" + r.ID
		}
		if !strings.HasPrefix(raw, head) {
			t.Fatalf("parts %q do not prefix %q", head, raw)
		}
		for k, vs := range r.Query {
			if len(vs) != 1 || !typeRe.MatchString(k) {
				t.Fatalf("bad query %v", r.Query)
			}
			for _, c := range vs[0] {
				if unicode.IsControl(c) {
					t.Fatalf("control character in query value")
				}
			}
		}
		if len(raw) > MaxResourceLength {
			t.Fatalf("over-long resource accepted")
		}
	})
}

func FuzzValidateActionName(f *testing.F) {
	for _, s := range []string{"repo.push", "raw:get:pods/log", "", " ", "a\n", "BROWSE_PROJECTS"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if err := ValidateActionName(name); err != nil {
			return
		}
		for _, c := range name {
			if c > 0x7e || c < 0x21 {
				t.Fatalf("non-printable or non-ASCII accepted in %q", name)
			}
		}
		if len(name) > MaxActionLength {
			t.Fatal("over-long action accepted")
		}
	})
}
