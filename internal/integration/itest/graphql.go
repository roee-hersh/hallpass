package itest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// graphQL validates GraphQL requests against a schema in SDL form: the
// POST body's query must parse, every selected field must exist on its
// type with the arguments the schema declares, required arguments must be
// given, selection sets must sit on composite types only, and the
// variables must match their declared input types.
type graphQL struct {
	name  string
	types map[string]*gqlType
	roots map[string]string
}

type gqlType struct {
	kind    string // OBJECT, INTERFACE, INPUT, ENUM, SCALAR, UNION
	fields  map[string]*gqlField
	enum    map[string]bool
	members []string
}

type gqlField struct {
	typ  gqlRef
	args map[string]*gqlArg
}

type gqlArg struct {
	typ        gqlRef
	hasDefault bool
}

// gqlRef is a type reference: a name, wrapped in lists, each level
// possibly non-null.
type gqlRef struct {
	name    string
	nonNull bool
	list    *gqlRef
}

func (r gqlRef) base() string {
	if r.list != nil {
		return r.list.base()
	}
	return r.name
}

func (r gqlRef) String() string {
	s := r.name
	if r.list != nil {
		s = "[" + r.list.String() + "]"
	}
	if r.nonNull {
		s += "!"
	}
	return s
}

// sdlRe is a type definition at the start of a line: `type Query {`,
// `schema {`, `directive @x`, `scalar DateTime`, `union U = A | B`. A YAML
// description that happens to start a line with "type of ..." does not
// match, since the name must be followed by a brace, "implements", "=", "@"
// or the end of the line.
var sdlRe = regexp.MustCompile(`(?m)^\s*(?:(?:extend\s+)?(?:type|interface|input|enum|scalar|union)\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\{|implements\b|=|@|$)|(?:extend\s+)?schema\s*(?:\{|@)|directive\s+@)`)

// looksLikeSDL reports whether raw is a GraphQL schema rather than JSON or
// YAML. It is consulted only when the text is not a JSON or YAML document
// of a known description format.
func looksLikeSDL(raw []byte) bool {
	trim := strings.TrimSpace(string(raw))
	return trim != "" && trim[0] != '{' && sdlRe.MatchString(trim)
}

// --- lexer ------------------------------------------------------------------

type gqlTok struct {
	kind byte // 'n' name, 's' string, 'p' punctuation, 'd' number, 'v' variable
	val  string
	pos  int
}

func gqlLex(src string) ([]gqlTok, error) {
	var toks []gqlTok
	src = strings.TrimPrefix(src, "\xEF\xBB\xBF")
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '"':
			start := i
			if strings.HasPrefix(src[i:], `"""`) {
				end := strings.Index(src[i+3:], `"""`)
				for end >= 0 && src[i+3+end-1] == '\\' {
					next := strings.Index(src[i+3+end+3:], `"""`)
					if next < 0 {
						end = -1
						break
					}
					end += 3 + next
				}
				if end < 0 {
					return nil, fmt.Errorf("unterminated block string at %d", start)
				}
				toks = append(toks, gqlTok{'s', src[i+3 : i+3+end], start})
				i += 3 + end + 3
				continue
			}
			i++
			var b strings.Builder
			for i < len(src) && src[i] != '"' {
				if src[i] == '\\' && i+1 < len(src) {
					i++
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
			toks = append(toks, gqlTok{'s', b.String(), start})
		case c == '$':
			start := i
			i++
			j := i
			for j < len(src) && isNameByte(src[j]) {
				j++
			}
			if j == i {
				return nil, fmt.Errorf("bare $ at %d", start)
			}
			toks = append(toks, gqlTok{'v', src[i:j], start})
			i = j
		case c == '.':
			if !strings.HasPrefix(src[i:], "...") {
				return nil, fmt.Errorf("stray . at %d", i)
			}
			toks = append(toks, gqlTok{'p', "...", i})
			i += 3
		case strings.IndexByte("{}()[]:!=@|&", c) >= 0:
			toks = append(toks, gqlTok{'p', string(c), i})
			i++
		case c == '-' || (c >= '0' && c <= '9'):
			j := i + 1
			for j < len(src) && (src[j] >= '0' && src[j] <= '9' || src[j] == '.' || src[j] == 'e' || src[j] == 'E' || src[j] == '+' || src[j] == '-') {
				j++
			}
			toks = append(toks, gqlTok{'d', src[i:j], i})
			i = j
		case isNameByte(c):
			j := i
			for j < len(src) && isNameByte(src[j]) {
				j++
			}
			toks = append(toks, gqlTok{'n', src[i:j], i})
			i = j
		default:
			return nil, fmt.Errorf("unexpected byte %q at %d", c, i)
		}
	}
	return toks, nil
}

func isNameByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// --- parser -----------------------------------------------------------------

type gqlParser struct {
	toks []gqlTok
	i    int
}

func (p *gqlParser) more() bool { return p.i < len(p.toks) }

func (p *gqlParser) peek() gqlTok {
	if p.i < len(p.toks) {
		return p.toks[p.i]
	}
	return gqlTok{}
}

func (p *gqlParser) is(kind byte, val string) bool {
	t := p.peek()
	return p.more() && t.kind == kind && (val == "" || t.val == val)
}

func (p *gqlParser) next() gqlTok {
	t := p.peek()
	p.i++
	return t
}

func (p *gqlParser) expect(kind byte, val string) (gqlTok, error) {
	if !p.is(kind, val) {
		return gqlTok{}, fmt.Errorf("expected %q at %d, found %q", val, p.peek().pos, p.peek().val)
	}
	return p.next(), nil
}

func (p *gqlParser) name() (string, error) {
	t, err := p.expect('n', "")
	return t.val, err
}

// typeRef parses Name, [Type] and the ! suffixes.
func (p *gqlParser) typeRef() (gqlRef, error) {
	var r gqlRef
	if p.is('p', "[") {
		p.next()
		inner, err := p.typeRef()
		if err != nil {
			return r, err
		}
		if _, err := p.expect('p', "]"); err != nil {
			return r, err
		}
		r.list = &inner
	} else {
		n, err := p.name()
		if err != nil {
			return r, err
		}
		r.name = n
	}
	if p.is('p', "!") {
		p.next()
		r.nonNull = true
	}
	return r, nil
}

// skipValue consumes one value literal.
func (p *gqlParser) skipValue() error {
	_, err := p.value()
	return err
}

// skipDirectives consumes @name(args) sequences.
func (p *gqlParser) skipDirectives() error {
	for p.is('p', "@") {
		p.next()
		if _, err := p.name(); err != nil {
			return err
		}
		if p.is('p', "(") {
			if _, err := p.arguments(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *gqlParser) skipDescription() {
	if p.is('s', "") {
		p.next()
	}
}

// argDefs parses ( name: Type = default ... ).
func (p *gqlParser) argDefs() (map[string]*gqlArg, error) {
	args := map[string]*gqlArg{}
	if _, err := p.expect('p', "("); err != nil {
		return nil, err
	}
	for !p.is('p', ")") {
		if !p.more() {
			return nil, fmt.Errorf("unterminated argument list")
		}
		p.skipDescription()
		n, err := p.name()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect('p', ":"); err != nil {
			return nil, err
		}
		ref, err := p.typeRef()
		if err != nil {
			return nil, err
		}
		a := &gqlArg{typ: ref}
		if p.is('p', "=") {
			p.next()
			if err := p.skipValue(); err != nil {
				return nil, err
			}
			a.hasDefault = true
		}
		if err := p.skipDirectives(); err != nil {
			return nil, err
		}
		args[n] = a
	}
	p.next()
	return args, nil
}

// fieldDefs parses { name(args): Type ... } for object, interface and
// input types (input fields take no arguments).
func (p *gqlParser) fieldDefs(input bool) (map[string]*gqlField, error) {
	fields := map[string]*gqlField{}
	if _, err := p.expect('p', "{"); err != nil {
		return nil, err
	}
	for !p.is('p', "}") {
		if !p.more() {
			return nil, fmt.Errorf("unterminated field list")
		}
		p.skipDescription()
		n, err := p.name()
		if err != nil {
			return nil, err
		}
		f := &gqlField{args: map[string]*gqlArg{}}
		if !input && p.is('p', "(") {
			if f.args, err = p.argDefs(); err != nil {
				return nil, err
			}
		}
		if _, err := p.expect('p', ":"); err != nil {
			return nil, err
		}
		if f.typ, err = p.typeRef(); err != nil {
			return nil, err
		}
		if input && p.is('p', "=") {
			p.next()
			if err := p.skipValue(); err != nil {
				return nil, err
			}
			// A defaulted input field is optional; record it as such.
			f.args["="] = &gqlArg{hasDefault: true}
		}
		if err := p.skipDirectives(); err != nil {
			return nil, err
		}
		fields[n] = f
	}
	p.next()
	return fields, nil
}

// newGraphQL parses an SDL schema.
func newGraphQL(name string, raw []byte) (*graphQL, error) {
	toks, err := gqlLex(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	g := &graphQL{name: name, types: map[string]*gqlType{}, roots: map[string]string{"query": "Query", "mutation": "Mutation", "subscription": "Subscription"}}
	for _, s := range []string{"Int", "Float", "String", "Boolean", "ID"} {
		g.types[s] = &gqlType{kind: "SCALAR"}
	}
	p := &gqlParser{toks: toks}
	define := func(n, kind string) *gqlType {
		t := g.types[n]
		if t == nil || t.kind == "SCALAR" && kind != "SCALAR" {
			t = &gqlType{kind: kind, fields: map[string]*gqlField{}, enum: map[string]bool{}}
			g.types[n] = t
		}
		return t
	}
	for p.more() {
		p.skipDescription()
		if p.is('n', "extend") {
			p.next()
		}
		kw, err := p.name()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		switch kw {
		case "schema":
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			if _, err := p.expect('p', "{"); err != nil {
				return nil, err
			}
			for !p.is('p', "}") {
				op, err := p.name()
				if err != nil {
					return nil, err
				}
				if _, err := p.expect('p', ":"); err != nil {
					return nil, err
				}
				tn, err := p.name()
				if err != nil {
					return nil, err
				}
				g.roots[op] = tn
			}
			p.next()
		case "scalar":
			n, err := p.name()
			if err != nil {
				return nil, err
			}
			define(n, "SCALAR")
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
		case "type", "interface":
			n, err := p.name()
			if err != nil {
				return nil, err
			}
			kind := "OBJECT"
			if kw == "interface" {
				kind = "INTERFACE"
			}
			t := define(n, kind)
			if p.is('n', "implements") {
				p.next()
				if p.is('p', "&") {
					p.next()
				}
				for {
					if _, err := p.name(); err != nil {
						return nil, err
					}
					if !p.is('p', "&") {
						break
					}
					p.next()
				}
			}
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			if p.is('p', "{") {
				fields, err := p.fieldDefs(false)
				if err != nil {
					return nil, fmt.Errorf("%s: type %s: %w", name, n, err)
				}
				for k, v := range fields {
					t.fields[k] = v
				}
			}
		case "input":
			n, err := p.name()
			if err != nil {
				return nil, err
			}
			t := define(n, "INPUT")
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			if p.is('p', "{") {
				fields, err := p.fieldDefs(true)
				if err != nil {
					return nil, fmt.Errorf("%s: input %s: %w", name, n, err)
				}
				for k, v := range fields {
					t.fields[k] = v
				}
			}
		case "enum":
			n, err := p.name()
			if err != nil {
				return nil, err
			}
			t := define(n, "ENUM")
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			if p.is('p', "{") {
				p.next()
				for !p.is('p', "}") {
					p.skipDescription()
					v, err := p.name()
					if err != nil {
						return nil, err
					}
					t.enum[v] = true
					if err := p.skipDirectives(); err != nil {
						return nil, err
					}
				}
				p.next()
			}
		case "union":
			n, err := p.name()
			if err != nil {
				return nil, err
			}
			t := define(n, "UNION")
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			if p.is('p', "=") {
				p.next()
				if p.is('p', "|") {
					p.next()
				}
				for {
					m, err := p.name()
					if err != nil {
						return nil, err
					}
					t.members = append(t.members, m)
					if !p.is('p', "|") {
						break
					}
					p.next()
				}
			}
		case "directive":
			if _, err := p.expect('p', "@"); err != nil {
				return nil, err
			}
			if _, err := p.name(); err != nil {
				return nil, err
			}
			if p.is('p', "(") {
				if _, err := p.argDefs(); err != nil {
					return nil, err
				}
			}
			if p.is('n', "repeatable") {
				p.next()
			}
			if _, err := p.expect('n', "on"); err != nil {
				return nil, err
			}
			if p.is('p', "|") {
				p.next()
			}
			for {
				if _, err := p.name(); err != nil {
					return nil, err
				}
				if !p.is('p', "|") {
					break
				}
				p.next()
			}
		default:
			return nil, fmt.Errorf("%s: unexpected %q at %d", name, kw, p.peek().pos)
		}
	}
	return g, nil
}

func (g *graphQL) Name() string { return g.name }

// --- query documents --------------------------------------------------------

type gqlValue struct {
	kind     byte // 'v' variable, 's' string, 'd' number, 'n' name (enum, true, false, null), 'l' list, 'o' object
	val      string
	list     []gqlValue
	obj      map[string]gqlValue
	objOrder []string
}

type gqlSel struct {
	name, alias string
	args        map[string]gqlValue
	sels        []gqlSel
	spread      string // named fragment spread
	inline      bool
	onType      string
}

type gqlOp struct {
	kind string
	vars map[string]*gqlArg
	sels []gqlSel
}

type gqlFragment struct {
	on   string
	sels []gqlSel
}

func (p *gqlParser) value() (gqlValue, error) {
	t := p.peek()
	switch {
	case t.kind == 'v':
		p.next()
		return gqlValue{kind: 'v', val: t.val}, nil
	case t.kind == 's' || t.kind == 'd' || t.kind == 'n':
		p.next()
		return gqlValue{kind: t.kind, val: t.val}, nil
	case t.kind == 'p' && t.val == "[":
		p.next()
		v := gqlValue{kind: 'l'}
		for !p.is('p', "]") {
			if !p.more() {
				return v, fmt.Errorf("unterminated list")
			}
			e, err := p.value()
			if err != nil {
				return v, err
			}
			v.list = append(v.list, e)
		}
		p.next()
		return v, nil
	case t.kind == 'p' && t.val == "{":
		p.next()
		v := gqlValue{kind: 'o', obj: map[string]gqlValue{}}
		for !p.is('p', "}") {
			if !p.more() {
				return v, fmt.Errorf("unterminated object")
			}
			k, err := p.name()
			if err != nil {
				return v, err
			}
			if _, err := p.expect('p', ":"); err != nil {
				return v, err
			}
			e, err := p.value()
			if err != nil {
				return v, err
			}
			v.obj[k] = e
			v.objOrder = append(v.objOrder, k)
		}
		p.next()
		return v, nil
	}
	return gqlValue{}, fmt.Errorf("expected a value at %d, found %q", t.pos, t.val)
}

// arguments parses ( name: value ... ).
func (p *gqlParser) arguments() (map[string]gqlValue, error) {
	args := map[string]gqlValue{}
	if _, err := p.expect('p', "("); err != nil {
		return nil, err
	}
	for !p.is('p', ")") {
		if !p.more() {
			return nil, fmt.Errorf("unterminated arguments")
		}
		n, err := p.name()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect('p', ":"); err != nil {
			return nil, err
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		args[n] = v
	}
	p.next()
	return args, nil
}

func (p *gqlParser) selectionSet() ([]gqlSel, error) {
	if _, err := p.expect('p', "{"); err != nil {
		return nil, err
	}
	var sels []gqlSel
	for !p.is('p', "}") {
		if !p.more() {
			return nil, fmt.Errorf("unterminated selection set")
		}
		var s gqlSel
		if p.is('p', "...") {
			p.next()
			s.inline = true
			if p.is('n', "on") {
				p.next()
				n, err := p.name()
				if err != nil {
					return nil, err
				}
				s.onType = n
			} else if p.is('n', "") {
				s.inline = false
				s.spread = p.next().val
				if err := p.skipDirectives(); err != nil {
					return nil, err
				}
				sels = append(sels, s)
				continue
			}
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			sub, err := p.selectionSet()
			if err != nil {
				return nil, err
			}
			s.sels = sub
			sels = append(sels, s)
			continue
		}
		n, err := p.name()
		if err != nil {
			return nil, err
		}
		s.name = n
		if p.is('p', ":") {
			p.next()
			s.alias = n
			if s.name, err = p.name(); err != nil {
				return nil, err
			}
		}
		if p.is('p', "(") {
			if s.args, err = p.arguments(); err != nil {
				return nil, err
			}
		}
		if err := p.skipDirectives(); err != nil {
			return nil, err
		}
		if p.is('p', "{") {
			if s.sels, err = p.selectionSet(); err != nil {
				return nil, err
			}
		}
		sels = append(sels, s)
	}
	p.next()
	return sels, nil
}

// document parses operations and fragments.
func (p *gqlParser) document() (map[string]*gqlOp, map[string]*gqlFragment, error) {
	ops := map[string]*gqlOp{}
	frags := map[string]*gqlFragment{}
	for p.more() {
		if p.is('p', "{") {
			sels, err := p.selectionSet()
			if err != nil {
				return nil, nil, err
			}
			if _, dup := ops[""]; dup {
				return nil, nil, fmt.Errorf("two anonymous operations")
			}
			ops[""] = &gqlOp{kind: "query", vars: map[string]*gqlArg{}, sels: sels}
			continue
		}
		kw, err := p.name()
		if err != nil {
			return nil, nil, err
		}
		if kw == "fragment" {
			n, err := p.name()
			if err != nil {
				return nil, nil, err
			}
			if _, err := p.expect('n', "on"); err != nil {
				return nil, nil, err
			}
			on, err := p.name()
			if err != nil {
				return nil, nil, err
			}
			if err := p.skipDirectives(); err != nil {
				return nil, nil, err
			}
			sels, err := p.selectionSet()
			if err != nil {
				return nil, nil, err
			}
			frags[n] = &gqlFragment{on: on, sels: sels}
			continue
		}
		if kw != "query" && kw != "mutation" && kw != "subscription" {
			return nil, nil, fmt.Errorf("unexpected %q at %d", kw, p.peek().pos)
		}
		op := &gqlOp{kind: kw, vars: map[string]*gqlArg{}}
		opName := ""
		if p.is('n', "") {
			opName = p.next().val
		}
		if p.is('p', "(") {
			p.next()
			for !p.is('p', ")") {
				v, err := p.expect('v', "")
				if err != nil {
					return nil, nil, err
				}
				if _, err := p.expect('p', ":"); err != nil {
					return nil, nil, err
				}
				ref, err := p.typeRef()
				if err != nil {
					return nil, nil, err
				}
				a := &gqlArg{typ: ref}
				if p.is('p', "=") {
					p.next()
					if err := p.skipValue(); err != nil {
						return nil, nil, err
					}
					a.hasDefault = true
				}
				if err := p.skipDirectives(); err != nil {
					return nil, nil, err
				}
				op.vars[v.val] = a
			}
			p.next()
		}
		if err := p.skipDirectives(); err != nil {
			return nil, nil, err
		}
		if op.sels, err = p.selectionSet(); err != nil {
			return nil, nil, err
		}
		if _, dup := ops[opName]; dup {
			return nil, nil, fmt.Errorf("operation %q defined twice", opName)
		}
		ops[opName] = op
	}
	if _, anon := ops[""]; anon && len(ops) > 1 {
		return nil, nil, fmt.Errorf("an anonymous operation mixed with named ones")
	}
	return ops, frags, nil
}

// --- validation -------------------------------------------------------------

// Validate checks a POST body {"query": ..., "variables": ...}.
func (g *graphQL) Validate(r *http.Request, body []byte) error {
	if r.Method != http.MethodPost {
		return fmt.Errorf("%s: GraphQL takes POST, not %s", g.name, r.Method)
	}
	var env struct {
		Query         string         `json:"query"`
		OperationName string         `json:"operationName"`
		Variables     map[string]any `json:"variables"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("%s: body is not a GraphQL request: %w", g.name, err)
	}
	if strings.TrimSpace(env.Query) == "" {
		return fmt.Errorf("%s: empty query", g.name)
	}
	toks, err := gqlLex(env.Query)
	if err != nil {
		return fmt.Errorf("%s: %w", g.name, err)
	}
	p := &gqlParser{toks: toks}
	ops, frags, err := p.document()
	if err != nil {
		return fmt.Errorf("%s: query does not parse: %w", g.name, err)
	}
	if len(ops) == 0 {
		return fmt.Errorf("%s: no operation", g.name)
	}
	var op *gqlOp
	switch {
	case env.OperationName != "":
		op = ops[env.OperationName]
		if op == nil {
			return fmt.Errorf("%s: operationName %q is not in the document", g.name, env.OperationName)
		}
	case len(ops) == 1:
		for _, o := range ops {
			op = o
		}
	default:
		return fmt.Errorf("%s: %d operations and no operationName", g.name, len(ops))
	}
	root := g.roots[op.kind]
	if _, ok := g.types[root]; !ok {
		return fmt.Errorf("%s: the schema has no %s type", g.name, op.kind)
	}
	// Variables: declared ones typed, undeclared ones refused.
	for n, a := range op.vars {
		if _, ok := g.types[a.typ.base()]; !ok {
			return fmt.Errorf("%s: variable $%s has unknown type %s", g.name, n, a.typ)
		}
		v, given := env.Variables[n]
		if !given {
			if a.typ.nonNull && !a.hasDefault {
				return fmt.Errorf("%s: variable $%s: %s is required but not given", g.name, n, a.typ)
			}
			continue
		}
		if err := g.checkJSON(v, a.typ); err != nil {
			return fmt.Errorf("%s: variable $%s: %w", g.name, n, err)
		}
	}
	for n := range env.Variables {
		if _, ok := op.vars[n]; !ok {
			return fmt.Errorf("%s: variable $%s is not declared by the operation", g.name, n)
		}
	}
	v := &gqlValidator{g: g, frags: frags, vars: op.vars}
	return v.sels(root, op.sels, root)
}

type gqlValidator struct {
	g     *graphQL
	frags map[string]*gqlFragment
	vars  map[string]*gqlArg
}

func (v *gqlValidator) sels(typeName string, sels []gqlSel, path string) error {
	t := v.g.types[typeName]
	if t == nil {
		return fmt.Errorf("%s: unknown type %s", path, typeName)
	}
	for _, s := range sels {
		switch {
		case s.spread != "":
			f := v.frags[s.spread]
			if f == nil {
				return fmt.Errorf("%s: fragment %s is not defined", path, s.spread)
			}
			if err := v.sels(f.on, f.sels, path+"/..."+s.spread); err != nil {
				return err
			}
		case s.inline:
			on := typeName
			if s.onType != "" {
				on = s.onType
			}
			if err := v.sels(on, s.sels, path+"/... on "+on); err != nil {
				return err
			}
		case s.name == "__typename":
		default:
			if t.kind != "OBJECT" && t.kind != "INTERFACE" {
				return fmt.Errorf("%s: field %s selected on %s %s", path, s.name, strings.ToLower(t.kind), typeName)
			}
			f := t.fields[s.name]
			if f == nil {
				return fmt.Errorf("%s: %s has no field %s", path, typeName, s.name)
			}
			for n, val := range s.args {
				a := f.args[n]
				if a == nil {
					return fmt.Errorf("%s: %s.%s takes no argument %s", path, typeName, s.name, n)
				}
				if err := v.value(val, a.typ); err != nil {
					return fmt.Errorf("%s: %s.%s(%s): %w", path, typeName, s.name, n, err)
				}
			}
			for n, a := range f.args {
				if _, given := s.args[n]; !given && a.typ.nonNull && !a.hasDefault {
					return fmt.Errorf("%s: %s.%s requires argument %s", path, typeName, s.name, n)
				}
			}
			ft := v.g.types[f.typ.base()]
			if ft == nil {
				return fmt.Errorf("%s: %s.%s has unknown type %s", path, typeName, s.name, f.typ)
			}
			composite := ft.kind == "OBJECT" || ft.kind == "INTERFACE" || ft.kind == "UNION"
			if composite && len(s.sels) == 0 {
				return fmt.Errorf("%s: %s.%s (%s) needs a selection set", path, typeName, s.name, f.typ)
			}
			if !composite && len(s.sels) > 0 {
				return fmt.Errorf("%s: %s.%s (%s) takes no selection set", path, typeName, s.name, f.typ)
			}
			if composite {
				if err := v.sels(f.typ.base(), s.sels, path+"/"+s.name); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// value checks a literal argument against its type.
func (v *gqlValidator) value(val gqlValue, ref gqlRef) error {
	if val.kind == 'v' {
		decl := v.vars[val.val]
		if decl == nil {
			return fmt.Errorf("variable $%s is not declared", val.val)
		}
		// A single value coerces to a list of one; a list never
		// coerces to a single value.
		if decl.typ.base() != ref.base() || (decl.typ.list != nil && ref.list == nil) {
			return fmt.Errorf("variable $%s is %s, argument wants %s", val.val, decl.typ, ref)
		}
		if ref.nonNull && !decl.typ.nonNull && !decl.hasDefault {
			return fmt.Errorf("variable $%s (%s) may be null, argument wants %s", val.val, decl.typ, ref)
		}
		return nil
	}
	if val.kind == 'n' && val.val == "null" {
		if ref.nonNull {
			return fmt.Errorf("null given for %s", ref)
		}
		return nil
	}
	if ref.list != nil {
		items := val.list
		if val.kind != 'l' {
			items = []gqlValue{val}
		}
		for _, it := range items {
			if err := v.value(it, *ref.list); err != nil {
				return err
			}
		}
		return nil
	}
	t := v.g.types[ref.name]
	if t == nil {
		return fmt.Errorf("unknown type %s", ref.name)
	}
	switch t.kind {
	case "ENUM":
		if val.kind != 'n' || !t.enum[val.val] {
			return fmt.Errorf("%q is not a value of enum %s", val.val, ref.name)
		}
	case "INPUT":
		if val.kind != 'o' {
			return fmt.Errorf("%s wants an object", ref.name)
		}
		for _, k := range val.objOrder {
			f := t.fields[k]
			if f == nil {
				return fmt.Errorf("input %s has no field %s", ref.name, k)
			}
			if err := v.value(val.obj[k], f.typ); err != nil {
				return fmt.Errorf("%s.%s: %w", ref.name, k, err)
			}
		}
		for k, f := range t.fields {
			if _, given := val.obj[k]; !given && f.typ.nonNull && f.args["="] == nil {
				return fmt.Errorf("input %s requires field %s", ref.name, k)
			}
		}
	case "SCALAR":
		return scalarLiteral(ref.name, val)
	default:
		return fmt.Errorf("%s %s is not an input type", strings.ToLower(t.kind), ref.name)
	}
	return nil
}

func scalarLiteral(name string, val gqlValue) error {
	switch name {
	case "String", "ID":
		if val.kind != 's' && !(name == "ID" && val.kind == 'd') {
			return fmt.Errorf("%s wants a string", name)
		}
	case "Int", "Float":
		if val.kind != 'd' {
			return fmt.Errorf("%s wants a number", name)
		}
	case "Boolean":
		if val.kind != 'n' || (val.val != "true" && val.val != "false") {
			return fmt.Errorf("Boolean wants true or false")
		}
	}
	return nil
}

// checkJSON checks a variable's JSON value against its declared type.
func (g *graphQL) checkJSON(v any, ref gqlRef) error {
	if v == nil {
		if ref.nonNull {
			return fmt.Errorf("null given for %s", ref)
		}
		return nil
	}
	if ref.list != nil {
		items, ok := v.([]any)
		if !ok {
			items = []any{v}
		}
		for _, it := range items {
			if err := g.checkJSON(it, *ref.list); err != nil {
				return err
			}
		}
		return nil
	}
	t := g.types[ref.name]
	if t == nil {
		return fmt.Errorf("unknown type %s", ref.name)
	}
	switch t.kind {
	case "ENUM":
		s, ok := v.(string)
		if !ok || !t.enum[s] {
			return fmt.Errorf("%v is not a value of enum %s", v, ref.name)
		}
	case "INPUT":
		obj, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s wants an object", ref.name)
		}
		for k, fv := range obj {
			f := t.fields[k]
			if f == nil {
				return fmt.Errorf("input %s has no field %s", ref.name, k)
			}
			if err := g.checkJSON(fv, f.typ); err != nil {
				return fmt.Errorf("%s.%s: %w", ref.name, k, err)
			}
		}
		for k, f := range t.fields {
			if _, given := obj[k]; !given && f.typ.nonNull && f.args["="] == nil {
				return fmt.Errorf("input %s requires field %s", ref.name, k)
			}
		}
	case "SCALAR":
		switch ref.name {
		case "String":
			if _, ok := v.(string); !ok {
				return fmt.Errorf("String wants a string, not %T", v)
			}
		case "ID":
			switch v.(type) {
			case string, float64, json.Number:
			default:
				return fmt.Errorf("ID wants a string, not %T", v)
			}
		case "Int", "Float":
			switch v.(type) {
			case float64, json.Number:
			default:
				return fmt.Errorf("%s wants a number, not %T", ref.name, v)
			}
		case "Boolean":
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("Boolean wants true or false, not %T", v)
			}
		}
	default:
		return fmt.Errorf("%s %s is not an input type", strings.ToLower(t.kind), ref.name)
	}
	return nil
}
