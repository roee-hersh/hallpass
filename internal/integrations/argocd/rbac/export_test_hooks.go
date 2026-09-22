package rbac

// CompileGlobForTest and GlobMatchForTest expose the glob matcher to fuzz
// tests in the parent package. They are not used by production code.
func CompileGlobForTest(pattern string) (any, error) { return parseGlob(pattern) }

// GlobMatchForTest is globMatch.
func GlobMatchForTest(pattern, text string) bool { return globMatch(pattern, text) }
