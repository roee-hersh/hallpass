package authx

import (
	"net/url"
	"strings"
)

// parseTarget turns a raw request-target such as "/%20/foo" or
// "/example/..//./" into a URL whose EscapedPath and RawQuery keep the
// original bytes, so the signer's normalisation is what gets tested.
func parseTarget(target string) (*url.URL, error) {
	path, query, _ := strings.Cut(target, "?")
	u := &url.URL{Scheme: "https", Host: "example.amazonaws.com", RawQuery: query}
	// url.URL uses RawPath when it is a valid encoding of Path.
	unesc, err := url.PathUnescape(path)
	if err != nil {
		unesc = path
	}
	u.Path = unesc
	u.RawPath = path
	return u, nil
}
