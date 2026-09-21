// Package fake is a test integration. It talks to nothing. It exists so the
// engine, server and command can be exercised end to end, and so a fresh
// deployment can be smoke-tested before any real connection is added.
package fake

import (
	"context"
	"errors"
	"strings"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// Integration is the fake product.
type Integration struct{}

// Name is "fake".
func (Integration) Name() string { return "fake" }

// Fields: users, admins, fail.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		{Name: "users", Description: "comma-separated emails that exist and may read"},
		{Name: "admins", Description: "comma-separated emails allowed every action"},
		{Name: "fail", Default: "none", Enum: []string{"none", "upstream_timeout", "upstream_error", "credential_rejected", "upstream_rate_limited"},
			Description: "make every call fail with this code (for testing callers)"},
	}
}

// Actions of the fake integration.
func (Integration) Actions() []catalog.Action {
	return []catalog.Action{
		{Name: "thing.read", Description: "read a thing (any known user)"},
		{Name: "thing.write", Description: "write a thing (admins only)"},
		{Name: "thing.admin", Description: "administer a thing (admins only)"},
	}
}

// New builds a connection.
func (Integration) New(_ context.Context, s *integration.Settings, _ integration.Deps) (integration.Connection, error) {
	c := &Connection{users: set(s.Get("users")), admins: set(s.Get("admins"))}
	if f := s.Get("fail"); f != "none" && f != "" {
		c.fail = integration.Code(f)
	}
	return c, nil
}

func set(csv string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(csv, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			m[p] = true
		}
	}
	return m
}

// Connection is one fake system.
type Connection struct {
	users, admins map[string]bool
	fail          integration.Code
}

// ResolveIdentity: known users and admins resolve; an email containing
// "ambiguous" is ambiguous; everything else has no account.
func (c *Connection) ResolveIdentity(_ context.Context, u integration.User) (integration.Identity, error) {
	if c.fail != "" {
		return integration.Identity{}, integration.Errorf(c.fail, "fake failure")
	}
	email := strings.ToLower(u.Email)
	if strings.Contains(email, "ambiguous") {
		return integration.Identity{}, integration.UserAmbiguous("several accounts match %s", u.Email)
	}
	if !c.users[email] && !c.admins[email] {
		return integration.Identity{}, integration.UserNotFound("no account for %s", u.Email)
	}
	role := "user"
	if c.admins[email] {
		role = "admin"
	}
	return integration.Identity{ID: email, Display: email, Attrs: map[string]string{"role": role}}, nil
}

// Check evaluates the three actions on "thing:<id>" resources.
// The id "hidden" is not visible; "broken" is unsupported.
func (c *Connection) Check(_ context.Context, r integration.CheckRequest) (integration.Decision, error) {
	if c.fail != "" {
		return integration.Decision{}, integration.Errorf(c.fail, "fake failure")
	}
	if r.Resource.Type != "thing" || r.Resource.ID == "" {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "resource must be thing:<id>")
	}
	switch r.Resource.ID {
	case "hidden":
		return integration.UnknownDecision(integration.CodeResourceNotVisible, "thing %q is not visible to the fake credential", r.Resource.ID), nil
	case "broken":
		return integration.Unsupported("thing %q uses a policy the fake integration cannot evaluate", r.Resource.ID), nil
	}
	admin := r.Identity.Attr("role") == "admin"
	switch r.Action.Name {
	case "thing.read":
		return integration.Allowed("%s is a known user", r.Identity.Display), nil
	case "thing.write", "thing.admin":
		if admin {
			return integration.Allowed("%s is an admin", r.Identity.Display), nil
		}
		return integration.Denied("%s is not an admin", r.Identity.Display), nil
	}
	return integration.Decision{}, errors.New("unreachable: unknown action")
}

// Probe reports the configured user counts.
func (c *Connection) Probe(context.Context) (integration.ProbeResult, error) {
	if c.fail != "" {
		return integration.ProbeResult{}, integration.Errorf(c.fail, "fake failure")
	}
	var warnings []string
	if len(c.users)+len(c.admins) == 0 {
		warnings = append(warnings, "no users or admins configured; every check will answer user_not_found")
	}
	return integration.ProbeResult{
		Summary:  "fake integration ready",
		Warnings: warnings,
	}, nil
}
