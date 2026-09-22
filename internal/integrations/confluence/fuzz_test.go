package confluence

import (
	"testing"

	"github.com/roee-hersh/hallpass/internal/catalog"
)

// FuzzParseResource: an accepted id is a numeric content id or a strict
// space key, safe in a URL path or query.
func FuzzParseResource(f *testing.F) {
	for _, s := range []string{"page:123", "blogpost:9", "space:OPS", "page:0", "page:12a", "space:O S", "space:OPS/x", "page:1?x=1", "attachment:1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, resource string) {
		res, err := catalog.ParseResource(resource)
		if err != nil {
			return
		}
		r, err := parseResource(res)
		if err != nil {
			return
		}
		switch r.kind {
		case resPage, resBlogpost:
			if !contentIDRe.MatchString(r.id) {
				t.Fatalf("unvalidated content id %q", r.id)
			}
		case resSpace:
			if !spaceKeyRe.MatchString(r.id) {
				t.Fatalf("unvalidated space key %q", r.id)
			}
		default:
			t.Fatalf("unknown kind %q", r.kind)
		}
	})
}
