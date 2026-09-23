package azure

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseTarget: an accepted scope is a well-formed ARM scope built from
// validated, escaped segments, and an accepted operation carries no
// wildcard or path metacharacter.
func FuzzParseTarget(f *testing.F) {
	for _, s := range [][2]string{
		{"vm.read", "subscription:33333333-3333-3333-3333-333333333333"},
		{"vm.read", "resourcegroup:33333333-3333-3333-3333-333333333333/prod"},
		{"raw:Microsoft.Compute/virtualMachines/read", "resource:/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/web-1"},
		{"data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", "managementgroup:corp"},
		{"vm.read", "resource:/subscriptions/x/../y"}, {"raw:Microsoft.Compute/*", "subscription:x"},
		{"vm.read", "resource:/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/prod/providers/Microsoft.Compute/../.."},
		{"vm.read", "managementgroup:.."}, {"vm.read", "resourcegroup:33333333-3333-3333-3333-333333333333/rg(1)"},
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
		op := tg.action.operation
		if strings.ContainsAny(op, "*?#% \\/") == strings.ContainsAny(op, "*?#% \\") || strings.Contains(op, "//") {
			t.Fatalf("unvalidated operation %q from %q", op, action)
		}
		for _, seg := range strings.Split(op, "/") {
			if seg == "" || strings.Trim(seg, ".") == "" {
				t.Fatalf("bad segment %q in operation %q", seg, op)
			}
		}
		if strings.HasPrefix(action, "raw:") && (tg.action.data || op != strings.TrimPrefix(action, "raw:")) {
			t.Fatalf("raw action %q became %+v", action, tg.action)
		}
		if strings.HasPrefix(action, "data:") && (!tg.action.data || op != strings.TrimPrefix(action, "data:")) {
			t.Fatalf("data action %q became %+v", action, tg.action)
		}
		sc := tg.scope
		if !strings.HasPrefix(sc, "/") || strings.HasSuffix(sc, "/") || strings.Contains(sc, "//") || strings.Contains(sc, "?") || strings.Contains(sc, "#") {
			t.Fatalf("malformed scope %q from %q", sc, resource)
		}
		for _, seg := range strings.Split(sc[1:], "/") {
			if seg == "" || strings.Trim(seg, ".") == "" || strings.ContainsAny(seg, " \\%?#") {
				t.Fatalf("bad segment %q in %q", seg, sc)
			}
		}
		switch tg.kind {
		case "subscription":
			if !strings.HasPrefix(sc, "/subscriptions/") || strings.Count(sc, "/") != 2 {
				t.Fatalf("subscription scope %q", sc)
			}
		case "resourcegroup":
			if !strings.HasPrefix(sc, "/subscriptions/") || strings.Count(sc, "/") != 4 || !strings.Contains(sc, "/resourceGroups/") {
				t.Fatalf("resource group scope %q", sc)
			}
		case "resource":
			if !strings.Contains(sc, "/providers/") || strings.Count(sc, "/") < 8 || strings.Count(sc, "/")%2 != 0 {
				t.Fatalf("resource scope %q", sc)
			}
		case "managementgroup":
			if !strings.HasPrefix(sc, "/providers/Microsoft.Management/managementGroups/") || strings.Count(sc, "/") != 4 {
				t.Fatalf("management group scope %q", sc)
			}
		default:
			t.Fatalf("kind %q", tg.kind)
		}
	})
}
