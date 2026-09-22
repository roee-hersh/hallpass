package rbac

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"
)

// This file is a matcher compatible with github.com/gobwas/glob compiled
// with no separators, which is how Argo CD calls it. With no separators
// `*` and `**` both match any sequence of characters, including "/".
//
// Syntax: `*` and `**` any sequence; `?` one character; `[abc]`, `[a-z]`,
// `[!abc]` character classes; `{a,b}` alternatives, which may nest; `\x`
// escapes x.

type nodeKind int

const (
	nText  nodeKind = iota
	nAny            // ?
	nSuper          // * or **
	nClass          // [...]
)

type node struct {
	kind nodeKind
	text string
	// class
	not    bool
	ranges [][2]rune
}

// globPattern is a compiled pattern: a set of alternative flat sequences.
type globPattern struct {
	alts [][]node
}

var (
	globMu    sync.Mutex
	globCache = map[string]*globPattern{}
	globErrs  = map[string]error{}
)

// globMatch reports whether text matches pattern. An invalid pattern never
// matches, as in Argo CD (which logs the compile error and returns false).
func globMatch(pattern, text string) bool {
	p, err := compileGlob(pattern)
	if err != nil {
		return false
	}
	return p.match(text)
}

func compileGlob(pattern string) (*globPattern, error) {
	globMu.Lock()
	defer globMu.Unlock()
	if p, ok := globCache[pattern]; ok {
		return p, nil
	}
	if err, ok := globErrs[pattern]; ok {
		return nil, err
	}
	if len(globCache)+len(globErrs) > 10000 {
		globCache = map[string]*globPattern{}
		globErrs = map[string]error{}
	}
	p, err := parseGlob(pattern)
	if err != nil {
		globErrs[pattern] = err
		return nil, err
	}
	globCache[pattern] = p
	return p, nil
}

// parseGlob parses the whole pattern.
func parseGlob(pattern string) (*globPattern, error) {
	alts, rest, err := parseSeq(pattern, false)
	if err != nil {
		return nil, err
	}
	if rest != "" {
		return nil, fmt.Errorf("glob %q: unexpected %q", pattern, rest)
	}
	return &globPattern{alts: alts}, nil
}

// parseSeq parses until end of input or, inside braces, until "," or "}".
// It returns every alternative expansion of the parsed sequence.
func parseSeq(s string, inBrace bool) (alts [][]node, rest string, err error) {
	alts = [][]node{{}}
	appendNode := func(n node) {
		for i := range alts {
			alts[i] = append(alts[i], n)
		}
	}
	appendAlts := func(sub [][]node) {
		var out [][]node
		for _, a := range alts {
			for _, b := range sub {
				seq := make([]node, 0, len(a)+len(b))
				seq = append(seq, a...)
				seq = append(seq, b...)
				out = append(out, seq)
			}
		}
		alts = out
	}
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch r {
		case '\\':
			if len(s) < 2 {
				return nil, "", errors.New("glob: trailing backslash")
			}
			r2, size2 := utf8.DecodeRuneInString(s[1:])
			appendNode(node{kind: nText, text: string(r2)})
			s = s[1+size2:]
		case '*':
			s = s[1:]
			for strings.HasPrefix(s, "*") {
				s = s[1:]
			}
			appendNode(node{kind: nSuper})
		case '?':
			appendNode(node{kind: nAny})
			s = s[1:]
		case '[':
			n, rest, err := parseClass(s[1:])
			if err != nil {
				return nil, "", err
			}
			appendNode(n)
			s = rest
		case '{':
			s = s[1:]
			var sub [][]node
			for {
				a, rest, err := parseSeq(s, true)
				if err != nil {
					return nil, "", err
				}
				sub = append(sub, a...)
				if strings.HasPrefix(rest, ",") {
					s = rest[1:]
					continue
				}
				if strings.HasPrefix(rest, "}") {
					s = rest[1:]
					break
				}
				return nil, "", errors.New("glob: unclosed {")
			}
			appendAlts(sub)
		case ',', '}':
			if inBrace {
				return mergeText(alts), s, nil
			}
			appendNode(node{kind: nText, text: string(r)})
			s = s[size:]
		default:
			appendNode(node{kind: nText, text: string(r)})
			s = s[size:]
		}
	}
	if inBrace {
		return nil, "", errors.New("glob: unclosed {")
	}
	return mergeText(alts), "", nil
}

// mergeText joins adjacent text nodes.
func mergeText(alts [][]node) [][]node {
	for i, seq := range alts {
		var out []node
		for _, n := range seq {
			if n.kind == nText && len(out) > 0 && out[len(out)-1].kind == nText {
				out[len(out)-1].text += n.text
				continue
			}
			out = append(out, n)
		}
		alts[i] = out
	}
	return alts
}

// parseClass parses the body of [...] after the opening bracket.
func parseClass(s string) (node, string, error) {
	n := node{kind: nClass}
	if strings.HasPrefix(s, "!") {
		n.not = true
		s = s[1:]
	}
	first := true
	for {
		if s == "" {
			return node{}, "", errors.New("glob: unclosed [")
		}
		r, size := utf8.DecodeRuneInString(s)
		if r == ']' && !first {
			return n, s[size:], nil
		}
		first = false
		if r == '\\' && len(s) > size {
			r, size = utf8.DecodeRuneInString(s[size:])
			size++
		}
		s = s[size:]
		lo, hi := r, r
		if strings.HasPrefix(s, "-") && len(s) > 1 && s[1] != ']' {
			r2, size2 := utf8.DecodeRuneInString(s[1:])
			if r2 == '\\' && len(s) > 1+size2 {
				r2, size2 = utf8.DecodeRuneInString(s[1+size2:])
				size2++
			}
			hi = r2
			s = s[1+size2:]
		}
		if hi < lo {
			return node{}, "", fmt.Errorf("glob: bad range %c-%c", lo, hi)
		}
		n.ranges = append(n.ranges, [2]rune{lo, hi})
	}
}

func (n *node) classMatch(r rune) bool {
	in := false
	for _, rg := range n.ranges {
		if r >= rg[0] && r <= rg[1] {
			in = true
			break
		}
	}
	return in != n.not
}

func (p *globPattern) match(text string) bool {
	for _, seq := range p.alts {
		if matchSeq(seq, text) {
			return true
		}
	}
	return false
}

// matchSeq matches one flat sequence with memoised backtracking.
func matchSeq(seq []node, text string) bool {
	type key struct{ i, pos int }
	memo := map[key]bool{}
	var m func(i, pos int) bool
	m = func(i, pos int) bool {
		k := key{i, pos}
		if v, ok := memo[k]; ok {
			return v
		}
		var res bool
		switch {
		case i == len(seq):
			res = pos == len(text)
		default:
			n := seq[i]
			switch n.kind {
			case nText:
				res = strings.HasPrefix(text[pos:], n.text) && m(i+1, pos+len(n.text))
			case nAny:
				if pos < len(text) {
					_, size := utf8.DecodeRuneInString(text[pos:])
					res = m(i+1, pos+size)
				}
			case nClass:
				if pos < len(text) {
					r, size := utf8.DecodeRuneInString(text[pos:])
					res = n.classMatch(r) && m(i+1, pos+size)
				}
			case nSuper:
				for p := pos; p <= len(text); {
					if m(i+1, p) {
						res = true
						break
					}
					if p == len(text) {
						break
					}
					_, size := utf8.DecodeRuneInString(text[p:])
					p += size
				}
			}
		}
		memo[k] = res
		return res
	}
	return m(0, 0)
}
