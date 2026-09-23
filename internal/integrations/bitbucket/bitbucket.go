// Package bitbucket checks repository, project and workspace permissions in
// Bitbucket Cloud and Bitbucket Data Center.
//
// Cloud: hallpass finds the user among the workspace's members by email,
// reads the user's effective repository permission (the highest of direct,
// group and project grants, as Bitbucket computes it), the explicit project
// permission, the workspace role, and for @branch questions the branch
// restrictions. Data Center: hallpass finds the user by email, lists the
// groups the user belongs to, and combines the direct, group, project,
// project-default, public and global grants into the effective level, then
// the ref restrictions for @branch questions. Every call is a read with
// hallpass's own token; nothing is written.
package bitbucket

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const (
	editionCloud      = "cloud"
	editionDataCenter = "datacenter"

	authBearer = "bearer"
	authBasic  = "basic"

	defaultCloudURL = "https://api.bitbucket.org"
)

// Integration is the bitbucket product.
type Integration struct{}

// Name is "bitbucket".
func (Integration) Name() string { return "bitbucket" }

// Fields of a bitbucket connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		{Name: "edition", Default: editionCloud, Enum: []string{editionCloud, editionDataCenter},
			Description: "cloud: bitbucket.org; datacenter: a self-hosted Bitbucket Data Center or Server"},
		integration.URLField(false, "Data Center base URL (required there); Cloud default https://api.bitbucket.org"),
		{Name: "workspace", Validate: validateSlug,
			Description: "cloud: the workspace slug every resource belongs to; identities are resolved among its members"},
		{Name: "auth_mode", Default: authBearer, Enum: []string{authBearer, authBasic},
			Description: "bearer: a workspace access token (Cloud) or HTTP access token (Data Center); basic: an Atlassian API token with username (Cloud)"},
		{Name: "username", Description: "auth_mode basic: the Atlassian account email the API token belongs to"},
		integration.CredentialField(true, "the token"),
	}
}

func validateSlug(v string) error {
	if v == "" || validSlug(v) {
		return nil
	}
	return errors.New("must be a workspace slug")
}

// New builds a connection. It touches no network.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	if s.Secret("credential").IsZero() {
		return nil, errors.New("credential is required")
	}
	edition := s.Get("edition")
	if edition == "" {
		edition = editionCloud
	}
	base := strings.TrimRight(s.Get("url"), "/")
	c := &Connection{settings: s, edition: edition, workspace: s.Get("workspace")}
	switch edition {
	case editionCloud:
		if base == "" {
			base = defaultCloudURL
		}
		if !validSlug(c.workspace) {
			return nil, errors.New("workspace is required for edition cloud and must be a workspace slug")
		}
	case editionDataCenter:
		if base == "" {
			return nil, errors.New("url is required for edition datacenter")
		}
		if c.workspace != "" {
			return nil, errors.New("workspace applies to edition cloud only")
		}
	default:
		return nil, fmt.Errorf("edition %q must be cloud or datacenter", edition)
	}
	cred := s.Secret("credential")
	token := func(context.Context) (string, error) {
		t, err := cred.GetString()
		if err != nil {
			return "", integration.Wrap(integration.CodeCredentialRejected, err, "the token could not be read")
		}
		return strings.TrimSpace(t), nil
	}
	client := &httpx.Client{HTTP: hc, Base: base, Logger: d.Logger}
	switch s.Get("auth_mode") {
	case "", authBearer:
		client.Auth = httpx.BearerAuth(token)
	case authBasic:
		user := s.Get("username")
		if user == "" {
			return nil, errors.New("username is required in auth_mode basic")
		}
		client.Auth = httpx.BasicAuth(user, token)
	default:
		return nil, fmt.Errorf("auth_mode %q must be bearer or basic", s.Get("auth_mode"))
	}
	c.api = client
	return c, nil
}

// Connection is one Cloud workspace or one Data Center instance.
type Connection struct {
	settings  *integration.Settings
	edition   string
	workspace string
	api       *httpx.Client
}

// getJSON is one GET with JSON decoding. The raw httpx error is returned so
// callers can branch on 404.
func (c *Connection) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	resp, err := c.api.Do(ctx, &httpx.Request{Method: http.MethodGet, Path: path, Query: q})
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := resp.JSON(out); err != nil {
		return integration.Wrap(integration.CodeUpstreamError, err, "Bitbucket returned an unreadable response")
	}
	return nil
}

func (c *Connection) dataCenter() bool { return c.edition == editionDataCenter }

// classify maps an API error to an integration error. 404 is left to the
// caller: Bitbucket answers 404 for what the caller may not see.
func classify(err error, what string) *integration.Error {
	switch httpx.Status(err) {
	case 401:
		return integration.Wrap(integration.CodeCredentialRejected, err, "Bitbucket rejected hallpass's token")
	case 403:
		return integration.Wrap(integration.CodeCredentialRejected, err, "Bitbucket refused to %s (HTTP 403): hallpass's token lacks the permission that read needs", what)
	case 400:
		return integration.Wrap(integration.CodeInvalidRequest, err, "Bitbucket rejected the request to %s (HTTP 400)", what)
	}
	return httpx.Classify(err)
}

// ResolveIdentity maps the email to an account: a workspace member's
// Atlassian account id on Cloud, a user name on Data Center.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if !integration.IsEmail(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user email %q is not an address", email)
	}
	if c.dataCenter() {
		return c.dcIdentity(ctx, email)
	}
	return c.cloudIdentity(ctx, email)
}

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	t, err := parseTarget(r.ActionName, r.Resource, c.dataCenter())
	if err != nil {
		return integration.Decision{}, err
	}
	if r.Identity.Attr("active") == "false" {
		return integration.Denied("%s is deactivated", r.Identity.Display), nil
	}
	if c.dataCenter() {
		return c.dcCheck(ctx, t, r.Identity)
	}
	return c.cloudCheck(ctx, t, r.Identity)
}

// Probe verifies the token.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	if c.dataCenter() {
		return c.dcProbe(ctx)
	}
	return c.cloudProbe(ctx)
}
