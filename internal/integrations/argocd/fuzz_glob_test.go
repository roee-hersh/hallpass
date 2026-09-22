package argocd

import "github.com/roee-hersh/hallpass/internal/integrations/argocd/rbac"

// The glob lives in the rbac subpackage; expose it to the fuzz test here
// through the exported test hooks.
func parseGlobForFuzz(p string) (any, error) { return rbac.CompileGlobForTest(p) }
func globMatchForFuzz(p, s string) bool      { return rbac.GlobMatchForTest(p, s) }
