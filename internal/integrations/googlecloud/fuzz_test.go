package googlecloud

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseRef: an accepted question is a permission in the v1 or v2 format
// and a full resource name on a googleapis.com host, both built only from
// validated pieces.
func FuzzParseRef(f *testing.F) {
	for _, s := range [][2]string{
		{"project.view", "project:acme-prod"},
		{"iam.set", "bucket:acme-data"},
		{"storage.read", "object:acme-data/reports/2026/q1.csv"},
		{"raw:storage.objects.delete", "name://storage.googleapis.com/projects/_/buckets/x"},
		{"raw:iam.googleapis.com/roles.create", "organization:1"},
		{"serviceaccount.actas", "serviceaccount:deployer@acme-prod.iam.gserviceaccount.com"},
		{"gke.access", "cluster:acme-prod/europe-west1/main"},
		{"storage.read", "name://storage.googleapis.com/projects/../x"},
		{"storage.read", "object:acme-data/../x"},
		{"storage.read", "object:acme-data/a/../x"},
		{"storage.read", "object:acme-data/a/.."},
		{"storage.read", "object:acme-data/Q1 2026 (final).pdf"},
		{"secret.read", "secret:123456789012/db-password"},
		{"project.view", "project:acme-prod?x=1"},
		{"raw:storage.objects.get x", "project:acme-prod"},
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
		if !permissionRe.MatchString(q.permission) && !permissionV2Re.MatchString(q.permission) {
			t.Fatalf("unvalidated permission %q from %q", q.permission, action)
		}
		if strings.HasPrefix(action, "raw:") {
			if q.permission != strings.TrimPrefix(action, "raw:") {
				t.Fatalf("raw action %q became %q", action, q.permission)
			}
		} else if _, ok := actionIndex[action]; !ok {
			t.Fatalf("unknown action %q accepted", action)
		}
		if !wellFormed(q.resource) {
			t.Fatalf("unvalidated resource %q from %q", q.resource, resource)
		}
		if res.Type != "object" && strings.ContainsAny(q.resource, " \t?#\"\\") {
			t.Fatalf("unexpected characters in %q from %q", q.resource, resource)
		}
		if res.Type != "name" {
			for _, piece := range strings.Split(res.ID, "/") {
				if !strings.Contains(strings.ToLower(q.resource), strings.ToLower(piece)) {
					t.Fatalf("resource %q lost %q in %q", resource, piece, q.resource)
				}
			}
		}
		if res.Type == "name" && q.resource != res.ID {
			t.Fatalf("name resource %q changed to %q", res.ID, q.resource)
		}
	})
}
