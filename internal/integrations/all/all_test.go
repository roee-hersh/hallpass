package all

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestEveryActionHasAllowAndDenyTests is the coverage gate: every non-pattern
// action of every integration needs TestAction_<name>_allow and
// TestAction_<name>_deny in the integration's own package, where <name> has
// every character outside [A-Za-z0-9] replaced by "_".
func TestEveryActionHasAllowAndDenyTests(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(file))
	reg := Registry()
	for _, name := range reg.Names() {
		integ, _ := reg.Lookup(name)
		dir := filepath.Join(root, name)
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("integration %s: package directory %s missing (package dir must equal the integration name)", name, dir)
			continue
		}
		tests := testFuncs(t, dir)
		for _, a := range integ.Actions() {
			if a.Pattern {
				continue
			}
			base := "TestAction_" + sanitize(a.Name)
			for _, suffix := range []string{"_allow", "_deny"} {
				if !tests[base+suffix] {
					t.Errorf("integration %s: action %q has no %s test", name, a.Name, base+suffix)
				}
			}
		}
	}
}

var nonIdent = regexp.MustCompile(`[^A-Za-z0-9]`)

func sanitize(s string) string { return nonIdent.ReplaceAllString(s, "_") }

func testFuncs(t *testing.T, dir string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { return strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatalf("%s: %v", dir, err)
	}
	out := map[string]bool{}
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
					out[fd.Name.Name] = true
				}
			}
		}
	}
	return out
}

func TestRegistryHasFake(t *testing.T) {
	if _, ok := Registry().Lookup("fake"); !ok {
		t.Fatal("fake not registered")
	}
}
