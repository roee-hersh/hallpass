package databricks

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseRef: an accepted question carries a Unity Catalog name made only
// of identifier parts, or a workspace object id of the strict shape, and a
// privilege or level in upper case.
func FuzzParseRef(f *testing.F) {
	for _, s := range [][2]string{
		{"table.read", "table:main.sales.orders"},
		{"catalog.use", "catalog:main"},
		{"uc.manage", "volume:main.sales.files"},
		{"cluster.attach", "cluster:0123-456789-abcde1f2"},
		{"raw:CAN_RESTART", "cluster:0123-456789-abcde1f2"},
		{"raw:SELECT", "table:main.sales.orders"},
		{"table.read", "table:main.sales.`orders`"},
		{"table.read", "table:main.sales.orders?x=1"},
		{"cluster.attach", "cluster:a/b"},
		{"raw:select", "table:main.sales.orders"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, action, resource string) {
		res, err := catalog.ParseResource(resource)
		if err != nil {
			return
		}
		q, err := parseRef(action, res)
		if err != nil {
			return
		}
		if len(res.Query) > 0 {
			t.Fatalf("query slipped through %+v", res)
		}
		if q.uc {
			if _, ok := ucTypes[res.Type]; !ok || q.fullName != res.ID {
				t.Fatalf("uc question %+v from %q", q, resource)
			}
			for _, part := range strings.Split(q.fullName, ".") {
				if !ucNameRe.MatchString(part) {
					t.Fatalf("unvalidated name part %q from %q", part, resource)
				}
			}
			if len(q.privileges) == 0 {
				t.Fatalf("uc question without privileges from %q", action)
			}
			for _, p := range q.privileges {
				if !rawRe.MatchString(p) {
					t.Fatalf("unvalidated privilege %q", p)
				}
			}
		} else {
			ws, ok := wsTypes[res.Type]
			if !ok || q.object != ws.object || q.id != res.ID || !wsIDRe.MatchString(q.id) {
				t.Fatalf("workspace question %+v from %q", q, resource)
			}
			if !rawRe.MatchString(q.level) {
				t.Fatalf("unvalidated level %q", q.level)
			}
		}
		if strings.HasPrefix(action, "raw:") {
			want := strings.TrimPrefix(action, "raw:")
			got := q.level
			if q.uc {
				got = q.privileges[0]
			}
			if got != want {
				t.Fatalf("raw action %q became %q", action, got)
			}
			if !q.uc && !knownLevel(q.chains, got) {
				t.Fatalf("unknown level %q accepted for %q", got, resource)
			}
		} else if _, ok := actionIndex[action]; !ok {
			t.Fatalf("unknown action %q accepted", action)
		}
	})
}
