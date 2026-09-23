package itest

// Spec-aware fakes: every request an integration sends to the fake upstream
// can be validated against the vendor's published API description, so a
// wrong path, method, missing required parameter or missing body field
// fails the test even though the fake would have answered anyway.
//
// Supported descriptions: OpenAPI 3 and Swagger 2 (JSON or YAML), Google
// API discovery documents, and botocore service models (AWS Query and
// JSON protocols). Descriptions are loaded from $HALLPASS_SPECS_DIR/<name>.spec;
// when the directory or file is absent validation is skipped and the test
// says so once.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

// Spec validates requests against an API description.
type Spec interface {
	// Validate returns nil when the request is one the API accepts.
	Validate(r *http.Request, body []byte) error
	// Name identifies the description in messages.
	Name() string
}

// optionalKey marks, in a request's context, parameters not to require.
type optionalKey struct{}

// WithOptional returns a request whose validation treats the named
// parameters as optional.
func WithOptional(r *http.Request, names []string) *http.Request {
	if len(names) == 0 {
		return r
	}
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return r.WithContext(contextWithOptional(r.Context(), set))
}

func isOptional(r *http.Request, name string) bool {
	set, _ := r.Context().Value(optionalKey{}).(map[string]bool)
	return set[name]
}

// SpecOptions tune how a spec is applied to a fake server.
type SpecOptions struct {
	// StripPrefix patterns are removed from the start of the request path
	// before matching (a gateway prefix such as /ex/jira/<cloudid>).
	StripPrefix []string
	// IgnorePaths are request paths (regexps) that are not part of the
	// description, such as a token endpoint the fake also serves.
	IgnorePaths []string
	// AllowQuery lists query parameters accepted on every operation even
	// when the description does not declare them.
	AllowQuery []string
	// OptionalParams names parameters the description marks required but
	// the API also accepts elsewhere (Slack's legacy "token" in the query
	// when the token travels in the Authorization header).
	OptionalParams []string
}

var (
	specMu    sync.Mutex
	specCache = map[string]Spec{}
	specNoted = map[string]bool{}
)

// SpecFromEnv loads $HALLPASS_SPECS_DIR/<name>.spec. It returns nil, and
// logs once per name, when validation is not possible.
func SpecFromEnv(t testing.TB, name string) Spec {
	t.Helper()
	dir := os.Getenv("HALLPASS_SPECS_DIR")
	if dir == "" {
		noteOnce(t, name, "HALLPASS_SPECS_DIR not set: requests are not validated against the "+name+" API description")
		return nil
	}
	path := filepath.Join(dir, name+".spec")
	specMu.Lock()
	s, ok := specCache[path]
	specMu.Unlock()
	if ok {
		return s
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		noteOnce(t, name, "no "+path+": requests are not validated against the "+name+" API description")
		return nil
	}
	s, err = LoadSpec(name, raw)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	specMu.Lock()
	specCache[path] = s
	specMu.Unlock()
	return s
}

func noteOnce(t testing.TB, name, msg string) {
	specMu.Lock()
	defer specMu.Unlock()
	if specNoted[name] {
		return
	}
	specNoted[name] = true
	t.Log(msg)
}

// LoadSpec parses a description, detecting its format.
func LoadSpec(name string, raw []byte) (Spec, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		doc = map[string]any{}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("%s: neither JSON nor YAML: %w", name, err)
		}
		doc = normaliseYAML(doc).(map[string]any)
	}
	switch {
	case doc["openapi"] != nil || doc["swagger"] != nil:
		return newOpenAPI(name, doc)
	case doc["discoveryVersion"] != nil:
		return newDiscovery(name, doc)
	case doc["metadata"] != nil && doc["operations"] != nil && doc["shapes"] != nil:
		return newBotocore(name, doc)
	}
	return nil, fmt.Errorf("%s: unknown description format", name)
}

// normaliseYAML converts map[any]any (yaml.v3 output for some documents)
// into map[string]any recursively.
func normaliseYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			x[k] = normaliseYAML(val)
		}
		return x
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[fmt.Sprint(k)] = normaliseYAML(val)
		}
		return m
	case []any:
		for i := range x {
			x[i] = normaliseYAML(x[i])
		}
		return x
	}
	return v
}

func contextWithOptional(ctx context.Context, set map[string]bool) context.Context {
	return context.WithValue(ctx, optionalKey{}, set)
}

// ---- shared helpers ----

type pathTemplate struct {
	raw      string
	segments []string // literal or "{}" for a variable
	literals int
}

func newTemplate(p string) pathTemplate {
	t := pathTemplate{raw: p}
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			t.segments = append(t.segments, "{}")
		} else if strings.Contains(seg, "{") {
			// mixed segment such as "{owner}.json" or "sobjects/{name}": treat as variable
			t.segments = append(t.segments, "{}")
		} else {
			t.segments = append(t.segments, seg)
			t.literals++
		}
	}
	return t
}

func (t pathTemplate) match(path string) bool {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(t.segments) > 1 && t.segments[0] == "{}" && t.literals > 0 {
		// A template that starts with a variable and continues with
		// literals (Azure's /{scope}/providers/...) takes a whole resource
		// path there: the variable spans one or more non-empty segments. A
		// bare /{id} template keeps matching one segment, or it would match
		// every path.
		n := len(segs) - len(t.segments) + 1
		if n < 1 {
			return false
		}
		for _, seg := range segs[:n] {
			if seg == "" {
				return false
			}
		}
		return matchSegments(t.segments[1:], segs[n:])
	}
	return matchSegments(t.segments, segs)
}

func matchSegments(tpl, segs []string) bool {
	if len(segs) != len(tpl) {
		return false
	}
	for i, s := range tpl {
		if s == "{}" {
			if segs[i] == "" {
				return false
			}
			continue
		}
		if s != segs[i] {
			return false
		}
	}
	return true
}

// bestTemplate returns the matching template with the most literal segments.
func bestTemplate(templates []pathTemplate, path string) (pathTemplate, bool) {
	best, found := pathTemplate{}, false
	for _, t := range templates {
		if t.match(path) && (!found || t.literals > best.literals) {
			best, found = t, true
		}
	}
	return best, found
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

// resolveRef follows a local JSON pointer such as #/components/parameters/x.
func resolveRef(doc map[string]any, ref string) map[string]any {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	var cur any = doc
	for _, part := range strings.Split(ref[2:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return asMap(cur)
}

func deref(doc map[string]any, v any) map[string]any {
	m := asMap(v)
	if ref := asString(m["$ref"]); ref != "" {
		if r := resolveRef(doc, ref); r != nil {
			return r
		}
	}
	return m
}

// requiredTopLevel returns the required property names of a JSON schema,
// following $ref and allOf one level.
func requiredTopLevel(doc map[string]any, schema map[string]any) []string {
	schema = deref(doc, schema)
	var req []string
	for _, r := range asSlice(schema["required"]) {
		req = append(req, asString(r))
	}
	for _, sub := range asSlice(schema["allOf"]) {
		for _, r := range asSlice(deref(doc, sub)["required"]) {
			req = append(req, asString(r))
		}
	}
	return req
}

func checkJSONBody(body []byte, required []string, what string) error {
	if len(required) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return fmt.Errorf("%s: body is not a JSON object: %v", what, err)
	}
	var missing []string
	for _, r := range required {
		if _, ok := m[r]; !ok {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("%s: body lacks required properties %v", what, missing)
	}
	return nil
}

// ---- OpenAPI 3 / Swagger 2 ----

type openAPI struct {
	name      string
	doc       map[string]any
	templates []pathTemplate
	prefixes  []string // server/base paths that may precede the path
	ops       map[string]map[string]map[string]any
	v2        bool
}

func newOpenAPI(name string, doc map[string]any) (*openAPI, error) {
	s := &openAPI{name: name, doc: doc, ops: map[string]map[string]map[string]any{}, v2: doc["swagger"] != nil}
	paths := asMap(doc["paths"])
	if len(paths) == 0 {
		return nil, fmt.Errorf("%s: no paths", name)
	}
	for p, item := range paths {
		tpl := newTemplate(p)
		s.templates = append(s.templates, tpl)
		s.ops[p] = map[string]map[string]any{}
		for method, op := range asMap(item) {
			switch method {
			case "get", "put", "post", "delete", "patch", "head", "options":
				m := asMap(op)
				// merge path-level parameters
				if pp := asSlice(asMap(item)["parameters"]); len(pp) > 0 {
					merged := append([]any{}, pp...)
					merged = append(merged, asSlice(m["parameters"])...)
					cp := map[string]any{}
					for k, v := range m {
						cp[k] = v
					}
					cp["parameters"] = merged
					m = cp
				}
				s.ops[p][strings.ToUpper(method)] = m
			}
		}
	}
	if s.v2 {
		if bp := asString(doc["basePath"]); bp != "" && bp != "/" {
			s.prefixes = append(s.prefixes, strings.TrimRight(bp, "/"))
		}
	} else {
		for _, srv := range asSlice(doc["servers"]) {
			if p := serverPath(asMap(srv)); p != "" {
				s.prefixes = append(s.prefixes, p)
			}
		}
	}
	return s, nil
}

func (s *openAPI) Name() string { return s.name }

func (s *openAPI) Validate(r *http.Request, body []byte) error {
	// The escaped path keeps %2F inside one segment (GitLab project paths).
	path := r.URL.EscapedPath()
	candidates := []string{path}
	for _, pre := range s.prefixes {
		if strings.HasPrefix(path, pre+"/") {
			candidates = append(candidates, strings.TrimPrefix(path, pre))
		}
	}
	var tpl pathTemplate
	found := false
	for _, c := range candidates {
		if t, ok := bestTemplate(s.templates, c); ok {
			tpl, found = t, true
			break
		}
	}
	if !found {
		return fmt.Errorf("%s: no operation for path %s", s.name, path)
	}
	op, ok := s.ops[tpl.raw][r.Method]
	if !ok {
		var methods []string
		for m := range s.ops[tpl.raw] {
			methods = append(methods, m)
		}
		sort.Strings(methods)
		return fmt.Errorf("%s: %s not allowed on %s (spec has %v)", s.name, r.Method, tpl.raw, methods)
	}
	declared := map[string]bool{}
	var missingQ, missingH []string
	var bodyParam map[string]any
	for _, p := range asSlice(op["parameters"]) {
		pm := deref(s.doc, p)
		in, pname := asString(pm["in"]), asString(pm["name"])
		switch in {
		case "query":
			declared[pname] = true
			if asBool(pm["required"]) && !r.URL.Query().Has(pname) && !isOptional(r, pname) {
				missingQ = append(missingQ, pname)
			}
		case "header":
			if asBool(pm["required"]) && r.Header.Get(pname) == "" && !strings.EqualFold(pname, "authorization") && !isOptional(r, pname) {
				missingH = append(missingH, pname)
			}
		case "body":
			bodyParam = pm
		}
	}
	if len(missingQ) > 0 {
		return fmt.Errorf("%s: %s %s lacks required query parameters %v", s.name, r.Method, tpl.raw, missingQ)
	}
	if len(missingH) > 0 {
		return fmt.Errorf("%s: %s %s lacks required headers %v", s.name, r.Method, tpl.raw, missingH)
	}
	for q := range r.URL.Query() {
		if !declared[q] {
			return fmt.Errorf("%s: %s %s sends undeclared query parameter %q", s.name, r.Method, tpl.raw, q)
		}
	}
	what := fmt.Sprintf("%s: %s %s", s.name, r.Method, tpl.raw)
	if s.v2 {
		if bodyParam != nil {
			if asBool(bodyParam["required"]) && len(body) == 0 {
				return errors.New(what + ": body required")
			}
			if len(body) > 0 && strings.Contains(r.Header.Get("Content-Type"), "json") {
				return checkJSONBody(body, requiredTopLevel(s.doc, asMap(bodyParam["schema"])), what)
			}
		}
		return nil
	}
	if rb := deref(s.doc, op["requestBody"]); rb != nil {
		if asBool(rb["required"]) && len(body) == 0 {
			return errors.New(what + ": body required")
		}
		content := asMap(rb["content"])
		if len(body) > 0 && len(content) > 0 {
			ct := r.Header.Get("Content-Type")
			matched := false
			for mt, media := range content {
				if strings.HasPrefix(ct, strings.Split(mt, ";")[0]) || (mt == "*/*") {
					matched = true
					if strings.Contains(mt, "json") {
						return checkJSONBody(body, requiredTopLevel(s.doc, asMap(asMap(media)["schema"])), what)
					}
				}
			}
			if !matched {
				var mts []string
				for mt := range content {
					mts = append(mts, mt)
				}
				sort.Strings(mts)
				return fmt.Errorf("%s: content type %q not among %v", what, ct, mts)
			}
		}
	}
	return nil
}

// ---- Google API discovery ----

type discovery struct {
	name      string
	base      string // servicePath, e.g. /drive/v3/
	templates []pathTemplate
	methods   map[string]map[string]map[string]any // template raw -> METHOD -> method doc
	global    map[string]bool                      // global query params
}

func newDiscovery(name string, doc map[string]any) (*discovery, error) {
	d := &discovery{name: name, methods: map[string]map[string]map[string]any{}, global: map[string]bool{}}
	d.base = "/" + strings.Trim(asString(doc["servicePath"]), "/")
	if d.base == "/" {
		if u, err := url.Parse(asString(doc["baseUrl"])); err == nil {
			d.base = "/" + strings.Trim(u.Path, "/")
		}
	}
	for p := range asMap(doc["parameters"]) {
		d.global[p] = true
	}
	var walk func(res map[string]any)
	walk = func(res map[string]any) {
		for _, m := range asMap(res["methods"]) {
			md := asMap(m)
			p := asString(md["path"])
			if strings.HasPrefix(p, "/") {
				// absolute path (some methods): use as is
			} else {
				p = strings.TrimRight(d.base, "/") + "/" + p
			}
			p = discoveryTemplate(p)
			if _, ok := d.methods[p]; !ok {
				d.templates = append(d.templates, newTemplate(p))
				d.methods[p] = map[string]map[string]any{}
			}
			d.methods[p][strings.ToUpper(asString(md["httpMethod"]))] = md
		}
		for _, sub := range asMap(res["resources"]) {
			walk(asMap(sub))
		}
	}
	walk(doc)
	if len(d.templates) == 0 {
		return nil, fmt.Errorf("%s: no methods", name)
	}
	return d, nil
}

var reservedExpansion = regexp.MustCompile(`\{\+?([A-Za-z0-9_]+)\}`)

func discoveryTemplate(p string) string {
	return reservedExpansion.ReplaceAllString(p, "{$1}")
}

func (d *discovery) Name() string { return d.name }

func (d *discovery) Validate(r *http.Request, body []byte) error {
	// {+param} reserved expansion may contain "/"; retry with segments joined
	// when the direct match fails is not needed for the ids hallpass sends.
	tpl, ok := bestTemplate(d.templates, r.URL.EscapedPath())
	if !ok {
		return fmt.Errorf("%s: no method for path %s", d.name, r.URL.EscapedPath())
	}
	md, ok := d.methods[tpl.raw][r.Method]
	if !ok {
		return fmt.Errorf("%s: %s not allowed on %s", d.name, r.Method, tpl.raw)
	}
	params := asMap(md["parameters"])
	var missing []string
	for name, p := range params {
		pm := asMap(p)
		if asString(pm["location"]) == "query" && asBool(pm["required"]) && !r.URL.Query().Has(name) && !isOptional(r, name) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("%s: %s %s lacks required query parameters %v", d.name, r.Method, tpl.raw, missing)
	}
	for q := range r.URL.Query() {
		if d.global[q] {
			continue
		}
		if pm := asMap(params[q]); pm == nil || asString(pm["location"]) != "query" {
			return fmt.Errorf("%s: %s %s sends undeclared query parameter %q", d.name, r.Method, tpl.raw, q)
		}
	}
	if req := asMap(md["request"]); req != nil && len(body) == 0 && r.Method != http.MethodGet {
		return fmt.Errorf("%s: %s %s expects a request body", d.name, r.Method, tpl.raw)
	}
	return nil
}

// ---- botocore service model ----

type botocore struct {
	name         string
	protocol     string // "query" or "json"
	targetPrefix string
	ops          map[string]map[string]any
	shapes       map[string]any
}

func newBotocore(name string, doc map[string]any) (*botocore, error) {
	meta := asMap(doc["metadata"])
	b := &botocore{name: name, protocol: asString(meta["protocol"]), targetPrefix: asString(meta["targetPrefix"]), ops: map[string]map[string]any{}, shapes: asMap(doc["shapes"])}
	for n, op := range asMap(doc["operations"]) {
		b.ops[n] = asMap(op)
	}
	if b.protocol != "query" && b.protocol != "json" {
		return nil, fmt.Errorf("%s: unsupported protocol %q", name, b.protocol)
	}
	return b, nil
}

func (b *botocore) Name() string { return b.name }

func (b *botocore) requiredMembers(opName string) []string {
	op := b.ops[opName]
	in := asMap(op["input"])
	if in == nil {
		return nil
	}
	shape := asMap(b.shapes[asString(in["shape"])])
	var req []string
	for _, r := range asSlice(shape["required"]) {
		req = append(req, asString(r))
	}
	return req
}

func (b *botocore) Validate(r *http.Request, body []byte) error {
	if r.Method != http.MethodPost {
		return fmt.Errorf("%s: AWS calls are POST, got %s", b.name, r.Method)
	}
	switch b.protocol {
	case "query":
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return fmt.Errorf("%s: body is not form encoded: %v", b.name, err)
		}
		action := form.Get("Action")
		if _, ok := b.ops[action]; !ok {
			return fmt.Errorf("%s: unknown Action %q", b.name, action)
		}
		var missing []string
		for _, m := range b.requiredMembers(action) {
			if form.Get(m) == "" && form.Get(m+".member.1") == "" {
				missing = append(missing, m)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("%s: %s lacks required members %v", b.name, action, missing)
		}
		// Every sent key must be a member (or a member list/struct path).
		in := asMap(asMap(b.ops[action])["input"])
		members := asMap(asMap(b.shapes[asString(in["shape"])])["members"])
		for k := range form {
			if k == "Action" || k == "Version" {
				continue
			}
			top := strings.SplitN(k, ".", 2)[0]
			if _, ok := members[top]; !ok {
				return fmt.Errorf("%s: %s sends unknown parameter %q", b.name, action, k)
			}
		}
	case "json":
		target := r.Header.Get("X-Amz-Target")
		prefix, op, ok := strings.Cut(target, ".")
		if !ok || prefix != b.targetPrefix {
			return fmt.Errorf("%s: X-Amz-Target %q does not start with %s.", b.name, target, b.targetPrefix)
		}
		if _, ok := b.ops[op]; !ok {
			return fmt.Errorf("%s: unknown operation %q", b.name, op)
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-amz-json-1.") {
			return fmt.Errorf("%s: content type %q", b.name, r.Header.Get("Content-Type"))
		}
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			return fmt.Errorf("%s: %s body is not JSON: %v", b.name, op, err)
		}
		var missing []string
		for _, req := range b.requiredMembers(op) {
			if _, ok := m[req]; !ok {
				missing = append(missing, req)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("%s: %s lacks required members %v", b.name, op, missing)
		}
		in := asMap(asMap(b.ops[op])["input"])
		members := asMap(asMap(b.shapes[asString(in["shape"])])["members"])
		for k := range m {
			if _, ok := members[k]; !ok {
				return fmt.Errorf("%s: %s sends unknown member %q", b.name, op, k)
			}
		}
	}
	return nil
}

// AnySpec accepts a request when one of several descriptions does: for a
// fake that serves several APIs (Confluence v1 and v2, the AWS services).
// A request whose path no description knows is rejected with every error.
// When any description is missing (nil) the result is nil and nothing is
// validated: a partial set would reject the requests meant for the absent
// one.
func AnySpec(specs ...Spec) Spec {
	for _, s := range specs {
		if s == nil {
			return nil
		}
	}
	return anySpec(specs)
}

type anySpec []Spec

func (a anySpec) Name() string {
	names := make([]string, len(a))
	for i, s := range a {
		names[i] = s.Name()
	}
	return strings.Join(names, "|")
}

func (a anySpec) Validate(r *http.Request, body []byte) error {
	var errs []string
	for _, s := range a {
		err := s.Validate(r, body)
		if err == nil {
			return nil
		}
		errs = append(errs, err.Error())
	}
	return errors.New(strings.Join(errs, "; "))
}

// serverPath returns the path part of an OpenAPI server URL, or "" when it
// has none. Server variables ({your-domain}) are replaced by their defaults
// first, since a brace in the host does not parse; a URL that still does
// not parse is split on the first slash after the scheme.
func serverPath(srv map[string]any) string {
	raw := asString(srv["url"])
	for name, v := range asMap(srv["variables"]) {
		raw = strings.ReplaceAll(raw, "{"+name+"}", asString(asMap(v)["default"]))
	}
	var path string
	if u, err := url.Parse(raw); err == nil {
		path = u.Path
	} else {
		rest := raw
		if i := strings.Index(rest, "://"); i >= 0 {
			rest = rest[i+3:]
		}
		if i := strings.Index(rest, "/"); i >= 0 {
			path = rest[i:]
		}
	}
	path = strings.TrimRight(path, "/")
	if path == "" || path == "/" {
		return ""
	}
	return path
}
