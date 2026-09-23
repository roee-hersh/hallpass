package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// rule is one path stanza of an ACL policy.
type rule struct {
	// pattern is the path as written, templates resolved; templates that
	// could not be resolved are replaced by "+" and unresolved is set.
	pattern    string
	caps       map[string]bool
	unresolved bool
	// params is set when allowed_parameters, denied_parameters or
	// required_parameters restrict the stanza; wrapping when a wrapping
	// TTL is required. Both make the answer unknown: hallpass does not see
	// the request's parameters, and reads carry them too (KV's version).
	params, wrapping bool
	policy           string
}

// capabilities Vault knows.
var capabilities = map[string]bool{
	"create": true, "read": true, "update": true, "patch": true, "delete": true,
	"list": true, "sudo": true, "deny": true, "subscribe": true, "recover": true,
}

// legacyPolicy maps the deprecated `policy = "..."` stanza attribute.
// UNVERIFIED: taken from Vault's policy package (write = create, read,
// update, delete, list; read = read, list; sudo = all of them plus sudo).
var legacyPolicy = map[string][]string{
	"deny":  {"deny"},
	"read":  {"read", "list"},
	"write": {"create", "read", "update", "delete", "list"},
	"sudo":  {"create", "read", "update", "delete", "list", "sudo"},
}

// templateContext resolves {{identity...}} placeholders for one entity.
type templateContext struct {
	entityID, entityName string
	metadata             map[string]string
	// aliases by mount accessor: id, name and metadata.
	aliases map[string]alias
	// groups by id and by name.
	groupNames map[string]string // id -> name
	groupIDs   map[string]string // name -> id
}

type alias struct {
	id, name string
	metadata map[string]string
}

// parsePolicy parses an ACL policy in HCL or JSON.
func parsePolicy(name, src string, tc *templateContext) ([]rule, error) {
	trimmed := strings.TrimSpace(src)
	var rules []rule
	var err error
	if strings.HasPrefix(trimmed, "{") {
		rules, err = parseJSONPolicy(trimmed)
	} else {
		rules, err = parseHCLPolicy(trimmed)
	}
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", name, err)
	}
	for i := range rules {
		rules[i].policy = name
		// Vault drops one leading slash: paths start after the / of the API.
		pattern := strings.TrimPrefix(rules[i].pattern, "/")
		if pattern == "" {
			return nil, fmt.Errorf("policy %s: a path stanza has an empty path", name)
		}
		rules[i].pattern, rules[i].unresolved = resolveTemplates(pattern, tc)
	}
	return rules, nil
}

// --- JSON -------------------------------------------------------------------

func parseJSONPolicy(src string) ([]rule, error) {
	var doc struct {
		Path json.RawMessage `json:"path"`
	}
	if err := json.Unmarshal([]byte(src), &doc); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	if len(doc.Path) == 0 {
		return nil, nil
	}
	var stanzas map[string]json.RawMessage
	if err := json.Unmarshal(doc.Path, &stanzas); err != nil {
		// The list form: [{"secret/foo": {...}}, ...].
		var list []map[string]json.RawMessage
		if err := json.Unmarshal(doc.Path, &list); err != nil {
			return nil, errors.New("path is neither an object nor a list")
		}
		stanzas = map[string]json.RawMessage{}
		for _, m := range list {
			for k, v := range m {
				stanzas[k] = v
			}
		}
	}
	var rules []rule
	for pattern, raw := range stanzas {
		var body struct {
			Capabilities       []string        `json:"capabilities"`
			Policy             string          `json:"policy"`
			AllowedParameters  json.RawMessage `json:"allowed_parameters"`
			DeniedParameters   json.RawMessage `json:"denied_parameters"`
			RequiredParameters json.RawMessage `json:"required_parameters"`
			MinWrappingTTL     json.RawMessage `json:"min_wrapping_ttl"`
			MaxWrappingTTL     json.RawMessage `json:"max_wrapping_ttl"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, fmt.Errorf("stanza %q: %w", pattern, err)
		}
		r, err := newRule(pattern, body.Capabilities, body.Policy)
		if err != nil {
			return nil, err
		}
		r.params = nonEmptyJSON(body.AllowedParameters) || nonEmptyJSON(body.DeniedParameters) || nonEmptyJSON(body.RequiredParameters)
		r.wrapping = nonEmptyJSON(body.MinWrappingTTL) || nonEmptyJSON(body.MaxWrappingTTL)
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].pattern < rules[j].pattern })
	return rules, nil
}

func nonEmptyJSON(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null" && s != "{}" && s != "[]" && s != `""` && s != "0"
}

func newRule(pattern string, caps []string, legacy string) (rule, error) {
	r := rule{pattern: pattern, caps: map[string]bool{}}
	if pattern == "" {
		return r, errors.New("a path stanza has an empty path")
	}
	for _, c := range caps {
		c = strings.ToLower(strings.TrimSpace(c))
		if !capabilities[c] {
			return r, fmt.Errorf("stanza %q has unknown capability %q", pattern, c)
		}
		r.caps[c] = true
	}
	if legacy != "" {
		mapped, ok := legacyPolicy[strings.ToLower(legacy)]
		if !ok {
			return r, fmt.Errorf("stanza %q has unknown policy %q", pattern, legacy)
		}
		for _, c := range mapped {
			r.caps[c] = true
		}
	}
	return r, nil
}

// --- HCL --------------------------------------------------------------------

type hclTok struct {
	kind byte // 'n' name, 's' string, 'p' punctuation, 'd' number, 'e' end
	val  string
	pos  int
}

func hclLex(src string) ([]hclTok, error) {
	var toks []hclTok
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == ',':
			i++
		case c == '\n':
			toks = append(toks, hclTok{'e', "\n", i})
			i++
		case c == '#' || (c == '/' && i+1 < len(src) && src[i+1] == '/'):
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("unterminated comment at %d", i)
			}
			i += 2 + end + 2
		case c == '"':
			start := i
			i++
			var b strings.Builder
			for i < len(src) && src[i] != '"' {
				if src[i] == '\\' && i+1 < len(src) {
					i++
					switch src[i] {
					case 'n':
						b.WriteByte('\n')
					case 't':
						b.WriteByte('\t')
					default:
						b.WriteByte(src[i])
					}
					i++
					continue
				}
				if src[i] == '\n' {
					return nil, fmt.Errorf("newline in string at %d", start)
				}
				b.WriteByte(src[i])
				i++
			}
			if i >= len(src) {
				return nil, fmt.Errorf("unterminated string at %d", start)
			}
			i++
			toks = append(toks, hclTok{'s', b.String(), start})
		case c == '<' && strings.HasPrefix(src[i:], "<<"):
			return nil, fmt.Errorf("heredoc at %d is not supported", i)
		case strings.IndexByte("{}[]=:", c) >= 0:
			toks = append(toks, hclTok{'p', string(c), i})
			i++
		case c == '-' || (c >= '0' && c <= '9'):
			j := i + 1
			for j < len(src) && (src[j] >= '0' && src[j] <= '9' || src[j] == '.' || src[j] == 'h' || src[j] == 'm' || src[j] == 's') {
				j++
			}
			toks = append(toks, hclTok{'d', src[i:j], i})
			i = j
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			j := i
			for j < len(src) && (src[j] == '_' || src[j] == '-' || src[j] == '.' || src[j] >= 'a' && src[j] <= 'z' || src[j] >= 'A' && src[j] <= 'Z' || src[j] >= '0' && src[j] <= '9') {
				j++
			}
			toks = append(toks, hclTok{'n', src[i:j], i})
			i = j
		default:
			return nil, fmt.Errorf("unexpected byte %q at %d", c, i)
		}
	}
	return toks, nil
}

type hclParser struct {
	toks []hclTok
	i    int
}

func (p *hclParser) skipNewlines() {
	for p.i < len(p.toks) && p.toks[p.i].kind == 'e' {
		p.i++
	}
}

func (p *hclParser) peek() hclTok {
	p.skipNewlines()
	if p.i < len(p.toks) {
		return p.toks[p.i]
	}
	return hclTok{}
}

func (p *hclParser) more() bool { p.skipNewlines(); return p.i < len(p.toks) }

func (p *hclParser) next() hclTok {
	t := p.peek()
	p.i++
	return t
}

func (p *hclParser) is(kind byte, val string) bool {
	t := p.peek()
	return p.more() && t.kind == kind && (val == "" || t.val == val)
}

// value skips one value (string, number, name, list or object) and reports
// whether it was non-empty.
func (p *hclParser) value() (nonEmpty bool, err error) {
	t := p.peek()
	switch {
	case t.kind == 's':
		p.next()
		return t.val != "", nil
	case t.kind == 'd':
		p.next()
		return t.val != "0", nil
	case t.kind == 'n':
		p.next()
		return t.val != "null" && t.val != "false", nil
	case t.kind == 'p' && t.val == "[":
		p.next()
		n := 0
		for !p.is('p', "]") {
			if !p.more() {
				return false, errors.New("unterminated list")
			}
			if _, err := p.value(); err != nil {
				return false, err
			}
			n++
		}
		p.next()
		return n > 0, nil
	case t.kind == 'p' && t.val == "{":
		p.next()
		n := 0
		for !p.is('p', "}") {
			if !p.more() {
				return false, errors.New("unterminated object")
			}
			k := p.next()
			if k.kind != 's' && k.kind != 'n' {
				return false, fmt.Errorf("expected a key at %d", k.pos)
			}
			// key = value, key : value, or a nested block with optional
			// labels: factor "ops" { ... } (control groups).
			for p.is('s', "") {
				p.next()
			}
			if p.is('p', "=") || p.is('p', ":") {
				p.next()
			} else if !p.is('p', "{") {
				return false, fmt.Errorf("expected = or a block after key %q", k.val)
			}
			if _, err := p.value(); err != nil {
				return false, err
			}
			n++
		}
		p.next()
		return n > 0, nil
	}
	return false, fmt.Errorf("expected a value at %d, found %q", t.pos, t.val)
}

// stringList parses ["a", "b"] or a single string.
func (p *hclParser) stringList() ([]string, error) {
	if p.is('s', "") {
		return []string{p.next().val}, nil
	}
	if !p.is('p', "[") {
		return nil, fmt.Errorf("expected a list at %d", p.peek().pos)
	}
	p.next()
	var out []string
	for !p.is('p', "]") {
		if !p.more() {
			return nil, errors.New("unterminated list")
		}
		t := p.next()
		if t.kind != 's' {
			return nil, fmt.Errorf("expected a string at %d", t.pos)
		}
		out = append(out, t.val)
	}
	p.next()
	return out, nil
}

// parseHCLPolicy parses the subset of HCL that Vault policies use: `path
// "<pattern>" { attr = value ... }` blocks, and top-level attributes such
// as `name` which are ignored.
func parseHCLPolicy(src string) ([]rule, error) {
	toks, err := hclLex(src)
	if err != nil {
		return nil, err
	}
	p := &hclParser{toks: toks}
	var rules []rule
	for p.more() {
		t := p.next()
		if t.kind != 'n' {
			return nil, fmt.Errorf("expected a block or attribute at %d, found %q", t.pos, t.val)
		}
		if t.val != "path" {
			// A top-level attribute (name = "...") or an unknown block.
			if p.is('p', "=") {
				p.next()
				if _, err := p.value(); err != nil {
					return nil, err
				}
				continue
			}
			return nil, fmt.Errorf("unknown block %q at %d", t.val, t.pos)
		}
		// path "pattern" { ... } or path = { "pattern" = { ... } }.
		if p.is('p', "=") {
			p.next()
			if !p.is('p', "{") {
				return nil, fmt.Errorf("expected { after path = at %d", p.peek().pos)
			}
			p.next()
			for !p.is('p', "}") {
				k := p.next()
				if k.kind != 's' && k.kind != 'n' {
					return nil, fmt.Errorf("expected a path at %d", k.pos)
				}
				if p.is('p', "=") || p.is('p', ":") {
					p.next()
				}
				r, err := p.stanza(k.val)
				if err != nil {
					return nil, err
				}
				rules = append(rules, r)
			}
			p.next()
			continue
		}
		name := p.next()
		if name.kind != 's' {
			return nil, fmt.Errorf("expected a quoted path at %d", name.pos)
		}
		r, err := p.stanza(name.val)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// stanza parses { capabilities = [...] ... } for pattern.
func (p *hclParser) stanza(pattern string) (rule, error) {
	if !p.is('p', "{") {
		return rule{}, fmt.Errorf("expected { for path %q", pattern)
	}
	p.next()
	var caps []string
	legacy := ""
	r := rule{}
	for !p.is('p', "}") {
		if !p.more() {
			return rule{}, fmt.Errorf("unterminated stanza for %q", pattern)
		}
		k := p.next()
		if k.kind != 'n' && k.kind != 's' {
			return rule{}, fmt.Errorf("expected an attribute in %q at %d", pattern, k.pos)
		}
		if !p.is('p', "=") && !p.is('p', ":") {
			return rule{}, fmt.Errorf("expected = after %q in %q", k.val, pattern)
		}
		p.next()
		switch k.val {
		case "capabilities":
			list, err := p.stringList()
			if err != nil {
				return rule{}, fmt.Errorf("%q capabilities: %w", pattern, err)
			}
			caps = append(caps, list...)
		case "policy":
			t := p.next()
			if t.kind != 's' {
				return rule{}, fmt.Errorf("%q policy: expected a string", pattern)
			}
			legacy = t.val
		case "allowed_parameters", "denied_parameters", "required_parameters":
			nonEmpty, err := p.value()
			if err != nil {
				return rule{}, err
			}
			r.params = r.params || nonEmpty
		case "min_wrapping_ttl", "max_wrapping_ttl":
			nonEmpty, err := p.value()
			if err != nil {
				return rule{}, err
			}
			r.wrapping = r.wrapping || nonEmpty
		default:
			// control_group, subscribe_event_types and future attributes.
			if _, err := p.value(); err != nil {
				return rule{}, err
			}
		}
	}
	p.next()
	nr, err := newRule(pattern, caps, legacy)
	if err != nil {
		return rule{}, err
	}
	nr.params, nr.wrapping = r.params, r.wrapping
	return nr, nil
}

// --- templates --------------------------------------------------------------

// resolveTemplates substitutes {{identity.*}} placeholders. From the first
// placeholder it cannot resolve (unknown selector, empty value, or a value
// with a slash or wildcard, whose rendering could take any shape) the
// pattern becomes a glob of its literal prefix, so that it matches
// everything Vault's rendering might, and unresolved is reported.
func resolveTemplates(pattern string, tc *templateContext) (string, bool) {
	if !strings.Contains(pattern, "{{") {
		return pattern, false
	}
	var b strings.Builder
	rest := pattern
	for {
		i := strings.Index(rest, "{{")
		if i < 0 {
			b.WriteString(rest)
			return b.String(), false
		}
		b.WriteString(rest[:i])
		j := strings.Index(rest[i:], "}}")
		if j < 0 {
			return b.String() + "*", true
		}
		key := strings.TrimSpace(rest[i+2 : i+j])
		rest = rest[i+j+2:]
		v, ok := tc.lookup(key)
		if !ok || v == "" || strings.ContainsAny(v, "/*+") {
			return b.String() + "*", true
		}
		b.WriteString(v)
	}
}

// lookup resolves one template key.
func (tc *templateContext) lookup(key string) (string, bool) {
	if tc == nil {
		return "", false
	}
	parts := strings.Split(key, ".")
	if len(parts) < 3 || parts[0] != "identity" {
		return "", false
	}
	switch parts[1] {
	case "entity":
		switch {
		case len(parts) == 3 && parts[2] == "id":
			return tc.entityID, true
		case len(parts) == 3 && parts[2] == "name":
			return tc.entityName, true
		case len(parts) == 4 && parts[2] == "metadata":
			v, ok := tc.metadata[parts[3]]
			return v, ok
		case len(parts) >= 5 && parts[2] == "aliases":
			a, ok := tc.aliases[parts[3]]
			if !ok {
				return "", false
			}
			switch {
			case len(parts) == 5 && parts[4] == "id":
				return a.id, true
			case len(parts) == 5 && parts[4] == "name":
				return a.name, true
			case len(parts) == 6 && parts[4] == "metadata":
				v, ok := a.metadata[parts[5]]
				return v, ok
			}
		}
	case "groups":
		if len(parts) == 5 && parts[2] == "ids" && parts[4] == "name" {
			v, ok := tc.groupNames[parts[3]]
			return v, ok
		}
		if len(parts) == 5 && parts[2] == "names" && parts[4] == "id" {
			v, ok := tc.groupIDs[parts[3]]
			return v, ok
		}
	}
	return "", false
}

// --- matching ---------------------------------------------------------------

// matchPattern reports whether a policy pattern covers path: a segment
// that is exactly "+" matches any one segment, a trailing "*" matches any
// suffix, everything else (a "+" inside a segment included) is literal.
func matchPattern(pattern, path string) bool {
	glob := strings.HasSuffix(pattern, "*")
	if glob {
		pattern = pattern[:len(pattern)-1]
	}
	psegs, segs := strings.Split(pattern, "/"), strings.Split(path, "/")
	for i, ps := range psegs {
		if i >= len(segs) {
			return false
		}
		if glob && i == len(psegs)-1 {
			// The partial last segment is a prefix of the rest of the path.
			return strings.HasPrefix(strings.Join(segs[i:], "/"), ps)
		}
		if ps != "+" && ps != segs[i] {
			return false
		}
	}
	return len(segs) == len(psegs)
}

// lessPriority reports whether pattern a has lower priority than b under
// Vault's rules: an earlier first wildcard, a trailing glob, more "+"
// segments, a shorter length, then lexicographic order.
func lessPriority(a, b string) bool {
	if fa, fb := firstWildcard(a), firstWildcard(b); fa != fb {
		return fa < fb
	}
	ga, gb := strings.HasSuffix(a, "*"), strings.HasSuffix(b, "*")
	if ga != gb {
		return ga
	}
	if pa, pb := plusSegments(a), plusSegments(b); pa != pb {
		return pa > pb
	}
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// plusSegments counts the segments that are exactly "+".
func plusSegments(pattern string) int {
	n := 0
	for _, seg := range strings.Split(strings.TrimSuffix(pattern, "*"), "/") {
		if seg == "+" {
			n++
		}
	}
	return n
}

// firstWildcard is the index of the first "+" segment or the trailing
// glob, or past the end when there is none.
func firstWildcard(pattern string) int {
	off := 0
	for _, seg := range strings.Split(pattern, "/") {
		if seg == "+" || seg == "*" {
			return off
		}
		off += len(seg) + 1
	}
	if strings.HasSuffix(pattern, "*") {
		return len(pattern) - 1
	}
	return len(pattern) + 1
}

// evaluation is the outcome of matching a path and capability against a
// rule set.
type evaluation struct {
	// outcome is "allow", "deny", "unknown".
	outcome string
	// pattern is the winning pattern; policies the policies carrying it.
	pattern  string
	policies []string
	// reason explains deny and unknown outcomes.
	reason string
}

// evaluate applies Vault's matching: the highest-priority matching pattern
// decides, with the union of capabilities the policies grant it; deny
// wins; parameter and wrapping constraints make write answers unknown.
func evaluate(rules []rule, path string, need []string) evaluation {
	if len(rules) == 0 {
		return evaluation{outcome: "deny", reason: "no policy path matches"}
	}
	// Group rules by pattern, taking the union of capabilities.
	byPattern := map[string][]rule{}
	var winner string
	var winnerUnresolved bool
	for _, r := range rules {
		if !matchPattern(r.pattern, path) {
			continue
		}
		byPattern[r.pattern] = append(byPattern[r.pattern], r)
		if winner == "" || lessPriority(winner, r.pattern) {
			winner = r.pattern
		}
	}
	if winner == "" {
		return evaluation{outcome: "deny", reason: "no policy path matches " + path}
	}
	caps := map[string]bool{}
	params, wrapping := false, false
	var policies []string
	for _, r := range byPattern[winner] {
		for c := range r.caps {
			caps[c] = true
		}
		params = params || r.params
		wrapping = wrapping || r.wrapping
		winnerUnresolved = winnerUnresolved || r.unresolved
		policies = append(policies, r.policy)
	}
	sort.Strings(policies)
	ev := evaluation{pattern: winner, policies: policies}
	if winnerUnresolved {
		ev.outcome, ev.reason = "unknown", fmt.Sprintf("policy path %q carries a template hallpass could not resolve", winner)
		return ev
	}
	// Another matching stanza with an unresolved template could, once
	// rendered by Vault, be the same pattern as the winner (and add a
	// deny) or outrank it; either way the answer is unknown.
	for pattern, rs := range byPattern {
		if pattern == winner {
			continue
		}
		for _, r := range rs {
			if r.unresolved {
				ev.outcome, ev.reason = "unknown", fmt.Sprintf("policy path %q carries a template hallpass could not resolve", pattern)
				return ev
			}
		}
	}
	if caps["deny"] {
		ev.outcome, ev.reason = "deny", fmt.Sprintf("policy path %q denies", winner)
		return ev
	}
	missing := []string{}
	for _, c := range need {
		if !caps[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		ev.outcome, ev.reason = "deny", fmt.Sprintf("policy path %q grants %s but not %s", winner, capList(caps), strings.Join(missing, ", "))
		return ev
	}
	if params {
		ev.outcome, ev.reason = "unknown", fmt.Sprintf("policy path %q restricts the request parameters (allowed, denied or required parameters), which hallpass does not evaluate", winner)
		return ev
	}
	if wrapping {
		ev.outcome, ev.reason = "unknown", fmt.Sprintf("policy path %q requires response wrapping, which hallpass does not evaluate", winner)
		return ev
	}
	ev.outcome = "allow"
	return ev
}

func capList(caps map[string]bool) string {
	var out []string
	for c := range caps {
		out = append(out, c)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return "nothing"
	}
	return strings.Join(out, ", ")
}
