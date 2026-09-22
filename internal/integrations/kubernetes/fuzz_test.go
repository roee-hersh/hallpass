package kubernetes

import (
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzBuildAttributes: whatever the caller sends, the attributes that reach
// the SubjectAccessReview are made only of validated pieces.
func FuzzBuildAttributes(f *testing.F) {
	seeds := [][2]string{
		{"raw:get:pods", "namespace:payments?name=api-0"},
		{"raw:get", "nonresource:/version"},
		{"scale", "namespace:payments?resource=deployments.apps&name=api"},
		{"impersonate", "cluster?name=admin"},
		{"raw:create:deployments.apps/scale", "namespace:x"},
		{"pods.exec", "namespace:payments?name=a b"},
		{"raw:get:pods", "namespace:payments?namespace=other"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, action, resource string) {
		res, err := catalog.ParseResource(resource)
		if err != nil {
			return
		}
		if !strings.HasPrefix(action, "raw:") {
			if _, ok := aliases[action]; !ok {
				return
			}
		}
		a, err := buildAttributes(action, res)
		if err != nil {
			return
		}
		if a.nonResourcePath != "" {
			if !pathRe.MatchString(a.nonResourcePath) || a.resource != "" {
				t.Fatalf("bad nonresource %+v", a)
			}
			return
		}
		if !verbRe.MatchString(a.verb) || !resourceRe.MatchString(a.resource) {
			t.Fatalf("unvalidated verb/resource %+v", a)
		}
		if a.group != "" && !groupRe.MatchString(a.group) {
			t.Fatalf("unvalidated group %+v", a)
		}
		if a.subresource != "" && !resourceRe.MatchString(a.subresource) {
			t.Fatalf("unvalidated subresource %+v", a)
		}
		if a.name != "" && !nameRe.MatchString(a.name) {
			t.Fatalf("unvalidated name %+v", a)
		}
		if a.namespace != "" && !namespaceRe.MatchString(a.namespace) {
			t.Fatalf("unvalidated namespace %+v", a)
		}
	})
}
