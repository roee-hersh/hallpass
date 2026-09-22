package argocd

import (
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzBuildRequest: the object handed to the policy evaluator is always the
// validated resource id, and actions are always known shapes.
func FuzzBuildRequest(f *testing.F) {
	for _, s := range [][2]string{{"app.get", "applications:dev/web"}, {"app.action/apps/Deployment/restart", "applications:dev/web"}, {"app.update/apps/Deployment/ns/x", "applications:p/a"}, {"project.get", "projects:dev"}, {"cluster.get", "clusters:https://k"}, {"app.get", "applications:x y"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, action, resource string) {
		res, err := catalog.ParseResource(resource)
		if err != nil {
			return
		}
		req, err := buildRequest(action, res)
		if err != nil {
			return
		}
		if req.obj != res.ID || !objRe.MatchString(req.obj) {
			t.Fatalf("obj %q not the validated id %q", req.obj, res.ID)
		}
		if req.res == "" || req.act == "" {
			t.Fatalf("empty res/act for %q", action)
		}
	})
}

// FuzzGlob: the matcher never panics and an invalid pattern never matches.
func FuzzGlob(f *testing.F) {
	for _, s := range [][2]string{{"*/*", "a/b"}, {"{a,b}", "a"}, {"[!a-c]x", "dx"}, {`\*`, "*"}, {"[", "["}, {"{", "{"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, text string) {
		if _, err := parseGlobForFuzz(pattern); err != nil {
			if globMatchForFuzz(pattern, text) {
				t.Fatalf("invalid pattern %q matched", pattern)
			}
			return
		}
		_ = globMatchForFuzz(pattern, text)
	})
}
