package snowflake

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseTarget: an accepted name has exactly the parts its kind takes,
// every part is a resolved identifier that quotes back to a safe literal
// (no unescaped quote, no control character), and raw privileges are
// upper-case words.
func FuzzParseTarget(f *testing.F) {
	for _, s := range [][2]string{
		{"table.select", "table:prod.sales.orders"}, {"table.select", `table:prod.sales."Mixed Case"`},
		{"schema.usage", "schema:prod.sales"}, {"database.usage", "database:prod"}, {"role.use", "role:analyst"},
		{"account.create_database", "account"}, {"raw:CREATE_STAGE", "schema:prod.sales"},
		{"table.select", `table:prod.sales."a""b"`}, {"table.select", "table:prod.sales.o;drop"}, {"table.select", `table:p."x"."y`},
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
		k := kinds[tg.kind]
		if len(tg.name) != k.parts {
			t.Fatalf("%d parts for %s", len(tg.name), tg.kind)
		}
		for _, p := range tg.name {
			if p == "" || len(p) > 255 {
				t.Fatalf("part %q", p)
			}
			for _, r := range p {
				if r < 0x20 || r == 0x7f {
					t.Fatalf("control character in %q", p)
				}
			}
			q := quote(p)
			if strings.Count(q, `"`)%2 != 0 || !strings.HasPrefix(q, `"`) || !strings.HasSuffix(q, `"`) {
				t.Fatalf("quote(%q) = %q", p, q)
			}
			// Round trip: the quoted form parses back to the same part.
			back, err := parseIdentifier(q)
			if err != nil || back != p {
				t.Fatalf("round trip %q -> %q -> %q (%v)", p, q, back, err)
			}
		}
		for _, priv := range tg.action.privileges {
			if priv == "" || priv == "OWNERSHIP" || strings.ToUpper(priv) != priv || strings.ContainsAny(priv, "_;'\"") {
				t.Fatalf("privilege %q from %q", priv, action)
			}
		}
	})
}

// FuzzIdentifier: parseIdentifier never panics and every accepted
// identifier survives quote/parse round trips.
func FuzzIdentifier(f *testing.F) {
	for _, s := range []string{"a", `"a"`, `"a""b"`, "_$", `"`, `""`, "x.y", `"x.y"`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, err := parseIdentifier(s)
		if err != nil {
			return
		}
		back, err := parseIdentifier(quote(id))
		if err != nil || back != id {
			t.Fatalf("round trip %q -> %q", id, back)
		}
		parts, err := splitName(quote(id))
		if err != nil || len(parts) != 1 {
			t.Fatalf("splitName(%q) = %v, %v", quote(id), parts, err)
		}
	})
}
