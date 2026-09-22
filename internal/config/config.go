// Package config loads and strictly validates the hallpass YAML file.
//
// The file is one flat list of connections. Every key is a scalar string.
// Unknown keys, inline secrets and dangling connection references are
// reported with file:line.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/secret"
)

// Config is the loaded file.
type Config struct {
	// Listen is the address for serve (default ":8080").
	Listen string
	// APIKey callers must present as a bearer token.
	APIKey secret.Secret
	// DecisionLog is a file path, "stderr", "stdout" or "none".
	DecisionLog string
	// DecisionCache is how long allow/deny answers are reused (default 30 s, 0 disables).
	DecisionCache time.Duration
	// IdentityCache is how long resolved identities are reused (default 15 min).
	IdentityCache time.Duration
	// Connections in file order.
	Connections []*integration.Settings
	// Integrations maps connection id to its integration.
	Integrations map[string]integration.Integration
}

// Defaults.
const (
	DefaultListen        = ":8080"
	DefaultDecisionCache = 30 * time.Second
	DefaultIdentityCache = 15 * time.Minute
	DefaultDecisionLog   = "stderr"
)

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Error is a validation problem with a location.
type Error struct {
	File string
	Line int
	Msg  string
}

func (e *Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg)
	}
	return fmt.Sprintf("%s: %s", e.File, e.Msg)
}

// Errors collects every problem found so the owner fixes them in one pass.
type Errors []*Error

func (es Errors) Error() string {
	ss := make([]string, len(es))
	for i, e := range es {
		ss[i] = e.Error()
	}
	return strings.Join(ss, "\n")
}

// Load reads and validates the file at path against the registry.
func Load(path string, reg *integration.Registry) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, data, reg)
}

// Parse validates YAML data. name is used in error messages.
func Parse(name string, data []byte, reg *integration.Registry) (*Config, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, &Error{File: name, Msg: err.Error()}
	}
	l := &loader{file: name, reg: reg, cfg: &Config{
		Listen:        DefaultListen,
		DecisionLog:   DefaultDecisionLog,
		DecisionCache: DefaultDecisionCache,
		IdentityCache: DefaultIdentityCache,
		Integrations:  map[string]integration.Integration{},
	}}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, &Error{File: name, Msg: "file is empty"}
	}
	l.top(doc.Content[0])
	if len(l.errs) > 0 {
		return nil, l.errs
	}
	return l.cfg, nil
}

type loader struct {
	file string
	reg  *integration.Registry
	cfg  *Config
	errs Errors
}

func (l *loader) errf(n *yaml.Node, format string, args ...any) {
	line := 0
	if n != nil {
		line = n.Line
	}
	l.errs = append(l.errs, &Error{File: l.file, Line: line, Msg: fmt.Sprintf(format, args...)})
}

func (l *loader) top(n *yaml.Node) {
	if n.Kind != yaml.MappingNode {
		l.errf(n, "top level must be a mapping")
		return
	}
	seenConnections := false
	seen := map[string]*yaml.Node{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if prev, dup := seen[k.Value]; dup {
			l.errf(k, "key %q repeated (first set at line %d)", k.Value, prev.Line)
			continue
		}
		seen[k.Value] = k
		switch k.Value {
		case "api_key":
			if s, ok := l.scalar(v, "api_key"); ok {
				sec, err := secret.Parse(s)
				if err != nil {
					l.errf(v, "api_key: %v", err)
				} else {
					l.cfg.APIKey = sec
				}
			}
		case "listen":
			if s, ok := l.scalar(v, "listen"); ok {
				l.cfg.Listen = s
			}
		case "decision_log":
			if s, ok := l.scalar(v, "decision_log"); ok {
				l.cfg.DecisionLog = s
			}
		case "decision_cache_seconds":
			if s, ok := l.scalar(v, k.Value); ok {
				l.cfg.DecisionCache = l.seconds(v, s, 0, 3600)
			}
		case "identity_cache_seconds":
			if s, ok := l.scalar(v, k.Value); ok {
				l.cfg.IdentityCache = l.seconds(v, s, 0, 24*3600)
			}
		case "connections":
			seenConnections = true
			l.connections(v)
		default:
			l.errf(k, "unknown key %q (known: api_key, listen, decision_log, decision_cache_seconds, identity_cache_seconds, connections)", k.Value)
		}
	}
	if l.cfg.APIKey.IsZero() {
		l.errf(n, "api_key is required (env:NAME or file:/path)")
	}
	if !seenConnections {
		l.errf(n, "connections is required")
	}
}

func (l *loader) seconds(n *yaml.Node, s string, min, max int) time.Duration {
	v, err := strconv.Atoi(s)
	if err != nil || v < min || v > max {
		l.errf(n, "must be a whole number of seconds between %d and %d", min, max)
		return 0
	}
	return time.Duration(v) * time.Second
}

func (l *loader) scalar(n *yaml.Node, key string) (string, bool) {
	if n.Kind != yaml.ScalarNode {
		l.errf(n, "%s must be a single value, not a list or mapping", key)
		return "", false
	}
	if n.Tag == "!!null" {
		l.errf(n, "%s is empty", key)
		return "", false
	}
	return n.Value, true
}

func (l *loader) connections(n *yaml.Node) {
	if n.Kind != yaml.SequenceNode {
		l.errf(n, "connections must be a list")
		return
	}
	ids := map[string]*yaml.Node{}
	type pending struct {
		s    *integration.Settings
		node *yaml.Node
		refs map[string]string // field -> integration
	}
	var all []pending
	for _, item := range n.Content {
		if item.Kind != yaml.MappingNode {
			l.errf(item, "each connection must be a mapping")
			continue
		}
		raw := map[string]*yaml.Node{}
		for i := 0; i+1 < len(item.Content); i += 2 {
			k, v := item.Content[i], item.Content[i+1]
			if _, dup := raw[k.Value]; dup {
				l.errf(k, "key %q repeated", k.Value)
				continue
			}
			raw[k.Value] = v
		}
		idNode, ok := raw["id"]
		if !ok {
			l.errf(item, "connection has no id")
			continue
		}
		id, ok := l.scalar(idNode, "id")
		if !ok {
			continue
		}
		if !idRe.MatchString(id) {
			l.errf(idNode, "id %q must match %s", id, idRe)
			continue
		}
		if prev, dup := ids[id]; dup {
			l.errf(idNode, "id %q already used at line %d", id, prev.Line)
			continue
		}
		ids[id] = idNode
		intNode, ok := raw["integration"]
		if !ok {
			l.errf(item, "connection %q has no integration", id)
			continue
		}
		intName, ok := l.scalar(intNode, "integration")
		if !ok {
			continue
		}
		integ, ok := l.reg.Lookup(intName)
		if !ok {
			l.errf(intNode, "connection %q: unknown integration %q (known: %s)", id, intName, strings.Join(l.reg.Names(), ", "))
			continue
		}
		s, refs := l.connection(id, integ, raw)
		if s == nil {
			continue
		}
		all = append(all, pending{s: s, node: item, refs: refs})
	}
	// Resolve references and order connections so dependencies come first.
	byID := map[string]pending{}
	for _, p := range all {
		byID[p.s.ID] = p
	}
	for _, p := range all {
		for field, want := range p.refs {
			target := p.s.Get(field)
			tp, ok := byID[target]
			if !ok {
				l.errf(p.node, "connection %q: %s refers to unknown connection %q", p.s.ID, field, target)
				continue
			}
			if tp.s.Integration != want {
				l.errf(p.node, "connection %q: %s must name a %s connection, but %q is %s", p.s.ID, field, want, target, tp.s.Integration)
			}
			if target == p.s.ID {
				l.errf(p.node, "connection %q: %s refers to itself", p.s.ID, field)
			}
		}
	}
	if len(l.errs) > 0 {
		return
	}
	// Topological order with cycle detection.
	state := map[string]int{}
	var order []*integration.Settings
	var visit func(p pending) bool
	visit = func(p pending) bool {
		switch state[p.s.ID] {
		case 1:
			l.errf(p.node, "connection %q: reference cycle", p.s.ID)
			return false
		case 2:
			return true
		}
		state[p.s.ID] = 1
		fields := make([]string, 0, len(p.refs))
		for f := range p.refs {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		for _, f := range fields {
			if !visit(byID[p.s.Get(f)]) {
				return false
			}
		}
		state[p.s.ID] = 2
		order = append(order, p.s)
		return true
	}
	for _, p := range all {
		visit(p)
	}
	l.cfg.Connections = order
	for _, p := range all {
		l.cfg.Integrations[p.s.ID], _ = l.reg.Lookup(p.s.Integration)
	}
}

// connection validates one mapping against the integration's fields.
func (l *loader) connection(id string, integ integration.Integration, raw map[string]*yaml.Node) (*integration.Settings, map[string]string) {
	fields := map[string]integration.Field{}
	for _, f := range integ.Fields() {
		fields[f.Name] = f
	}
	values := map[string]string{}
	secrets := map[string]secret.Secret{}
	refs := map[string]string{}
	s := integration.NewSettings(id, integ.Name(), nil, nil)
	ok := true

	for key, node := range raw {
		if key == "id" || key == "integration" {
			continue
		}
		val, isScalar := l.scalar(node, key)
		if !isScalar {
			ok = false
			continue
		}
		if integration.CommonFields[key] {
			switch key {
			case "ca_file":
				if _, err := os.Stat(val); err != nil {
					l.errf(node, "connection %q: ca_file: %v", id, err)
					ok = false
				}
				s.CAFile = val
			case "tls_server_name":
				s.TLSServerName = val
			case "proxy_url":
				if !strings.HasPrefix(val, "http://") && !strings.HasPrefix(val, "https://") {
					l.errf(node, "connection %q: proxy_url must start with http:// or https://", id)
					ok = false
				}
				s.ProxyURL = val
			case "timeout":
				d, err := time.ParseDuration(val)
				if err != nil || d <= 0 || d > 5*time.Minute {
					l.errf(node, "connection %q: timeout must be a duration such as 10s, up to 5m", id)
					ok = false
				}
				s.Timeout = d
			}
			continue
		}
		f, known := fields[key]
		if !known {
			l.errf(node, "connection %q: integration %s does not accept key %q (accepted: %s)", id, integ.Name(), key, acceptedKeys(integ))
			ok = false
			continue
		}
		if f.Secret {
			sec, err := secret.Parse(val)
			if err != nil {
				l.errf(node, "connection %q: %s: %v", id, key, err)
				ok = false
				continue
			}
			secrets[key] = sec
			continue
		}
		if val == "" {
			l.errf(node, "connection %q: %s is empty", id, key)
			ok = false
			continue
		}
		if len(f.Enum) > 0 && !contains(f.Enum, val) {
			l.errf(node, "connection %q: %s must be one of %s", id, key, strings.Join(f.Enum, ", "))
			ok = false
			continue
		}
		if f.Validate != nil {
			if err := f.Validate(val); err != nil {
				l.errf(node, "connection %q: %s: %v", id, key, err)
				ok = false
				continue
			}
		}
		if f.Ref != "" {
			refs[key] = f.Ref
		}
		values[key] = val
	}
	for _, f := range integ.Fields() {
		_, present := raw[f.Name]
		if f.Required && !present {
			l.errf(raw["id"], "connection %q: %s requires %s", id, integ.Name(), f.Name)
			ok = false
		}
		if !present && f.Default != "" {
			values[f.Name] = f.Default
		}
	}
	if !ok {
		return nil, nil
	}
	out := integration.NewSettings(id, integ.Name(), values, secrets)
	out.CAFile, out.TLSServerName, out.ProxyURL, out.Timeout = s.CAFile, s.TLSServerName, s.ProxyURL, s.Timeout
	return out, refs
}

func acceptedKeys(i integration.Integration) string {
	ks := []string{"ca_file", "tls_server_name", "proxy_url", "timeout"}
	for _, f := range i.Fields() {
		ks = append(ks, f.Name)
	}
	sort.Strings(ks)
	return strings.Join(ks, ", ")
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ErrNoConnections is returned by Validate when the file lists none.
var ErrNoConnections = errors.New("config: no connections")
