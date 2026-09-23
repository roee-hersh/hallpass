package vault

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseTarget: an accepted path is plain segments without wildcards,
// dot-only segments or empty segments, and kv: always carries a key.
func FuzzParseTarget(f *testing.F) {
	for _, s := range [][2]string{
		{"secret.read", "kv:secret/dev/app"}, {"raw:sudo", "path:sys/seal"}, {"secret.list", "kv:secret/dev"},
		{"secret.read", "kv:secret/*"}, {"secret.read", "kv:secret/../x"}, {"secret.read", "path:a//b"},
		{"raw:read", "path:secret/data/x?v=1"}, {"secret.write", "kv:secret/a+b/c"},
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
		p := tg.path
		if p == "" || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") || strings.ContainsAny(p, "*+?# \\%") || len(p) > 512 {
			t.Fatalf("bad path %q from %q", p, resource)
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == "" || strings.Trim(seg, ".") == "" {
				t.Fatalf("bad segment %q in %q", seg, p)
			}
		}
		if tg.kind == "kv" && !strings.Contains(p, "/") {
			t.Fatalf("kv target without a key %+v", tg)
		}
		for _, c := range tg.action.need {
			if !capabilities[c] || c == "deny" {
				t.Fatalf("capability %q from %q", c, action)
			}
		}
	})
}

// FuzzPolicy: the policy parser never panics, and every rule it returns has
// a non-empty pattern and known capabilities.
func FuzzPolicy(f *testing.F) {
	for _, s := range []string{
		devPolicy, teamPolicy, opsPolicy, defaultPolicy, "",
		`path "a" { policy = "write" }`, `path = { "a/*" = { capabilities = ["read"] } }`,
		`{"path": [{"a": {"capabilities": ["read"]}}]}`, `path "a" { capabilities = ["read"] } # trailing`,
		`path "{{identity.entity.name}}/*" { capabilities = ["read"] }`,
	} {
		f.Add(s)
	}
	tc := &templateContext{entityID: "e1", entityName: "dana", metadata: map[string]string{"team": "x"}}
	f.Fuzz(func(t *testing.T, src string) {
		rules, err := parsePolicy("fuzz", src, tc)
		if err != nil {
			return
		}
		for _, r := range rules {
			if r.pattern == "" || r.policy != "fuzz" {
				t.Fatalf("rule %+v", r)
			}
			for c := range r.caps {
				if !capabilities[c] {
					t.Fatalf("capability %q", c)
				}
			}
			if strings.Contains(r.pattern, "{{") && !r.unresolved {
				t.Fatalf("template left in %q", r.pattern)
			}
		}
		// Evaluation never panics either.
		evaluate(rules, "secret/data/x", []string{"read"})
		evaluate(rules, "secret/metadata/x/", []string{"list"})
	})
}
