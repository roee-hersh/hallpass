package datadog

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseTarget: an accepted asset id is alphanumeric with hyphens and
// underscores, and an accepted permission is a lower-case identifier.
func FuzzParseTarget(f *testing.F) {
	for _, s := range [][2]string{
		{"monitor.edit", "monitor:123"},
		{"dashboard.edit", "dashboard:abc-def-ghi"},
		{"logs.read", "org"},
		{"raw:monitors_write", "monitor:1"},
		{"raw:api_keys_read", "org"},
		{"monitor.edit", "monitor:1/2"},
		{"logs.read", "org:1"},
		{"raw:Monitors", "org"},
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
		if !permissionRe.MatchString(tg.permission) {
			t.Fatalf("unvalidated permission %q from %q", tg.permission, action)
		}
		if strings.HasPrefix(action, "raw:") && tg.permission != strings.TrimPrefix(action, "raw:") {
			t.Fatalf("raw action %q became %q", action, tg.permission)
		}
		if tg.typ == "org" {
			if tg.id != "" || tg.relation != "" {
				t.Fatalf("org target with id or relation: %+v", tg)
			}
			return
		}
		if _, ok := assetTypes[tg.typ]; !ok || !idRe.MatchString(tg.id) || tg.id != res.ID {
			t.Fatalf("unvalidated asset %+v from %q", tg, resource)
		}
		if tg.relation != "editor" && tg.relation != "viewer" {
			t.Fatalf("asset target without a relation: %+v", tg)
		}
	})
}
