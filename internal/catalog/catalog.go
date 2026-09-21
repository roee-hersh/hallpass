// Package catalog defines the vocabulary shared by every integration:
// actions and resources.
package catalog

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Action is one thing a user may be allowed to do in an integration.
type Action struct {
	// Name is what callers send in the "action" field, for example "repo.push".
	Name string
	// Description is one line for humans, shown by `hallpass catalog`.
	Description string
	// Pattern is true for actions matched by shape rather than by exact name,
	// such as "raw:<verb>:<resource>". Name then documents the shape.
	Pattern bool

	// Method and PathTemplate are reserved for the future gateway phase.
	// Nothing reads them in v1.
	Method       string
	PathTemplate string
}

// Resource is a parsed "type:id" resource reference.
//
//	repo:acme/api            Type "repo",      ID "acme/api"
//	namespace:payments?name=api   Type "namespace", ID "payments", Query {name: api}
//	global                   Type "global",    ID ""
//	nonresource:/metrics     Type "nonresource", ID "/metrics"
type Resource struct {
	// Raw is the string exactly as the caller sent it.
	Raw string
	// Type is the part before the first colon.
	Type string
	// ID is the part after the first colon, before any "?". It may be empty.
	ID string
	// Query holds the optional key=value pairs after "?".
	Query url.Values
}

// MaxResourceLength bounds the caller-supplied resource string.
const MaxResourceLength = 1024

var typeRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ParseResource splits a resource reference into type, id and query.
// It does not know what types an integration accepts; each integration
// validates the type and id on its own with strict rules.
func ParseResource(raw string) (Resource, error) {
	r := Resource{Raw: raw}
	if raw == "" {
		return r, errors.New("resource is empty")
	}
	if len(raw) > MaxResourceLength {
		return r, fmt.Errorf("resource is longer than %d bytes", MaxResourceLength)
	}
	for _, c := range raw {
		if c < 0x20 || c == 0x7f {
			return r, errors.New("resource contains a control character")
		}
	}
	head, query, hasQuery := strings.Cut(raw, "?")
	typ, id, _ := strings.Cut(head, ":")
	if !typeRe.MatchString(typ) {
		return r, fmt.Errorf("resource type %q must match %s", typ, typeRe)
	}
	r.Type, r.ID = typ, id
	if hasQuery {
		q, err := url.ParseQuery(query)
		if err != nil {
			return r, fmt.Errorf("resource query: %w", err)
		}
		for k, vs := range q {
			if !typeRe.MatchString(k) || len(vs) != 1 {
				return r, fmt.Errorf("resource query key %q must be a single lowercase key", k)
			}
		}
		r.Query = q
	}
	return r, nil
}

// String returns the raw form.
func (r Resource) String() string { return r.Raw }

// Q returns one query value or "".
func (r Resource) Q(key string) string {
	if r.Query == nil {
		return ""
	}
	return r.Query.Get(key)
}

// SplitBranch separates an "@branch" suffix used by git hosts:
// "repo:acme/webapp@main" -> id "acme/webapp", branch "main".
func SplitBranch(id string) (base, branch string) {
	i := strings.LastIndex(id, "@")
	if i < 0 {
		return id, ""
	}
	return id[:i], id[i+1:]
}

// MaxActionLength bounds the caller-supplied action string.
const MaxActionLength = 200

var actionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/*-]*$`)

// ValidateActionName checks the shape of a caller-supplied action name.
func ValidateActionName(name string) error {
	if name == "" {
		return errors.New("action is empty")
	}
	if len(name) > MaxActionLength {
		return fmt.Errorf("action is longer than %d bytes", MaxActionLength)
	}
	if !actionRe.MatchString(name) {
		return fmt.Errorf("action %q contains characters outside %s", name, actionRe)
	}
	return nil
}
