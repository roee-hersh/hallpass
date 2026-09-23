// Package azure checks Azure role-based access control: may this user
// perform this resource provider operation at this scope.
//
// hallpass authenticates as an app registration, resolves the user to an
// Entra object id (through a microsoft365 connection or its own Graph
// call), lists the role assignments and deny assignments that apply to the
// user at the scope, including inherited ones and ones through groups, and
// evaluates the role definitions' actions and notActions the way Azure
// Resource Manager does. Deny assignments win; assignments with an ABAC
// condition answer unknown rather than allowed or denied. Nothing is
// written.
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/cache"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const (
	defaultARM       = "https://management.azure.com"
	defaultGraph     = "https://graph.microsoft.com"
	defaultAuthority = "https://login.microsoftonline.com"
	apiVersion       = "2022-04-01"

	// roleTTL is how long a role definition is kept.
	roleTTL = 5 * time.Minute
)

// Integration is the azure product.
type Integration struct{}

// Name is "azure".
func (Integration) Name() string { return "azure" }

// Fields of an azure connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		{Name: "tenant_id", Required: true, Description: "the Entra tenant id (GUID) or domain"},
		{Name: "client_id", Required: true, Description: "the app registration's application (client) id"},
		integration.CredentialField(true, "the app registration's client secret"),
		integration.ConnectionRefField("microsoft365_connection", "microsoft365", false,
			"resolve users through this microsoft365 connection instead of Graph with hallpass's own app registration"),
		{Name: "url", Default: defaultARM, Description: "the Azure Resource Manager endpoint"},
		{Name: "graph_url", Default: defaultGraph, Description: "the Microsoft Graph endpoint, when users are resolved here"},
		{Name: "authority_url", Default: defaultAuthority, Description: "the Entra token authority"},
	}
}

var tenantRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$`)

// New builds a connection. It touches no network.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	if s.Secret("credential").IsZero() {
		return nil, errors.New("credential is required")
	}
	tenant, clientID := strings.TrimSpace(s.Get("tenant_id")), strings.TrimSpace(s.Get("client_id"))
	if !tenantRe.MatchString(tenant) {
		return nil, errors.New("tenant_id must be a GUID or a domain")
	}
	if !guidRe.MatchString(clientID) {
		return nil, errors.New("client_id must be a GUID")
	}
	base := func(key, def string) (string, error) {
		v := strings.TrimRight(strings.TrimSpace(s.Get(key)), "/")
		if v == "" {
			v = def
		}
		if !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "http://") {
			return "", fmt.Errorf("%s must be an http(s) URL", key)
		}
		return v, nil
	}
	arm, err := base("url", defaultARM)
	if err != nil {
		return nil, err
	}
	graph, err := base("graph_url", defaultGraph)
	if err != nil {
		return nil, err
	}
	authority, err := base("authority_url", defaultAuthority)
	if err != nil {
		return nil, err
	}
	c := &Connection{roles: cache.New[string, roleDefinition](0), now: d.Now}
	if c.now == nil {
		c.now = time.Now
	}
	c.roles.SetClock(c.now)
	cred := s.Secret("credential")
	tokenURL := authority + "/" + httpx.PathEscape(tenant) + "/oauth2/v2.0/token"
	plain := &httpx.Client{HTTP: hc, Logger: d.Logger}
	secret := func(context.Context) (string, error) { return cred.GetString() }
	source := func(scope string) *authx.TokenSource {
		return &authx.TokenSource{Fetch: authx.ClientCredentials(plain, tokenURL, clientID, secret, scope), Now: c.now}
	}
	c.armTokens = source(arm + "/.default")
	c.arm = &httpx.Client{HTTP: hc, Base: arm, Logger: d.Logger, Auth: httpx.BearerAuth(c.armTokens.Get)}
	if ref := s.Get("microsoft365_connection"); ref != "" {
		c.identity, err = d.Connection(ref)
		if err != nil {
			return nil, fmt.Errorf("microsoft365_connection: %w", err)
		}
	} else {
		c.graphTokens = source(graph + "/.default")
		c.graph = &httpx.Client{HTTP: hc, Base: graph, Logger: d.Logger, Auth: httpx.BearerAuth(c.graphTokens.Get)}
	}
	return c, nil
}

// Connection is one tenant's Azure Resource Manager.
type Connection struct {
	arm, graph             *httpx.Client
	armTokens, graphTokens *authx.TokenSource
	// identity is the microsoft365 connection that resolves users, when
	// configured; graph is used otherwise.
	identity integration.Connection
	roles    *cache.TTL[string, roleDefinition]
	now      func() time.Time
}

// --- transport --------------------------------------------------------------

// armError is the body ARM sends with 4xx/5xx.
type armError struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

// errorCode extracts error.code from a status error's snippet.
func errorCode(err error) string {
	var se *httpx.StatusError
	if !errors.As(err, &se) {
		return ""
	}
	var ae armError
	if json.Unmarshal([]byte(se.Snippet), &ae) == nil && ae.Error.Code != "" {
		return ae.Error.Code
	}
	i := strings.Index(se.Snippet, `"code"`)
	if i < 0 {
		return ""
	}
	rest := strings.TrimLeft(se.Snippet[i+len(`"code"`):], " :")
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	rest = rest[1:]
	if j := strings.Index(rest, `"`); j >= 0 {
		return rest[:j]
	}
	return ""
}

func classifyToken(err error) *integration.Error {
	var te *authx.TokenError
	if errors.As(err, &te) {
		switch {
		case te.Status == 429:
			return integration.Wrap(integration.CodeUpstreamRateLimit, err, "the token endpoint rate limited hallpass")
		case te.Status >= 500:
			return integration.Wrap(integration.CodeUpstreamError, err, "the token endpoint failed (HTTP %d)", te.Status)
		}
	}
	return authx.ClassifyTokenError(err)
}

// getJSON performs one GET against client, retrying once after a 401 with
// a fresh token. notFound builds the error for a 404.
func (c *Connection) getJSON(ctx context.Context, client *httpx.Client, tokens *authx.TokenSource, path string, q url.Values, out any, notFound func() error) error {
	req := &httpx.Request{Path: path, Query: q}
	resp, err := client.Do(ctx, req)
	if httpx.Status(err) == 401 {
		tokens.Invalidate()
		resp, err = client.Do(ctx, req)
	}
	if err != nil {
		var te *authx.TokenError
		if errors.As(err, &te) {
			return classifyToken(err)
		}
		switch httpx.Status(err) {
		case 404:
			if notFound != nil {
				return notFound()
			}
		case 401:
			return integration.Wrap(integration.CodeCredentialRejected, err, "the token was rejected (HTTP 401)")
		case 403:
			// AuthorizationFailed on a scope: the app registration holds no
			// Reader there, so the scope is invisible to hallpass.
			if notFound != nil && errorCode(err) == "AuthorizationFailed" {
				return notFound()
			}
			return integration.Wrap(integration.CodeCredentialRejected, err, "the app registration may not read this (HTTP 403, %s); it needs Reader (Microsoft.Authorization/*/read) at or above the scope", orEmpty(errorCode(err), "no code"))
		case 400:
			return integration.Wrap(integration.CodeInvalidRequest, err, "the request was rejected (HTTP 400, %s)", orEmpty(errorCode(err), "no code"))
		}
		return httpx.Classify(err)
	}
	if err := resp.JSON(out); err != nil {
		return integration.Wrap(integration.CodeUpstreamError, err, "the response was not JSON")
	}
	return nil
}

func orEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// listARM pages through an ARM collection at path with the filter, following
// nextLink while it stays under the ARM endpoint.
func (c *Connection) listARM(ctx context.Context, path, filter string, notFound func() error) ([]json.RawMessage, error) {
	var items []json.RawMessage
	q := url.Values{"api-version": {apiVersion}, "$filter": {filter}}
	next := path
	for page := 0; next != ""; page++ {
		if page >= httpx.MaxPages {
			return nil, integration.Errorf(integration.CodeUpstreamError, "the listing at %s has more pages than hallpass follows", path)
		}
		var body struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"nextLink"`
		}
		if err := c.getJSON(ctx, c.arm, c.armTokens, next, q, &body, notFound); err != nil {
			return nil, err
		}
		items = append(items, body.Value...)
		next, q = body.NextLink, nil
		if next != "" && !c.arm.Within(next) {
			return nil, integration.Errorf(integration.CodeUpstreamError, "the listing sent a next link outside the ARM endpoint")
		}
	}
	return items, nil
}

// --- identity ---------------------------------------------------------------

type graphUser struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	AccountEnabled    *bool  `json:"accountEnabled"`
}

// odataString quotes a string literal for $filter: ' is doubled.
func odataString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// ResolveIdentity finds the user's Entra object id, through the
// microsoft365 connection when configured, else by mail or UPN in Graph.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	if c.identity != nil {
		id, err := c.identity.ResolveIdentity(ctx, u)
		if err != nil {
			return integration.Identity{}, err
		}
		if !guidRe.MatchString(id.ID) {
			return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "the microsoft365 connection returned an identity that is not an object id")
		}
		return id, nil
	}
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if !integration.IsEmail(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user email %q is not an address", email)
	}
	lit := odataString(email)
	var body struct {
		Value []graphUser `json:"value"`
	}
	q := url.Values{
		"$filter": {"mail eq " + lit + " or userPrincipalName eq " + lit},
		"$select": {"id,userPrincipalName,mail,accountEnabled"},
	}
	if err := c.getJSON(ctx, c.graph, c.graphTokens, "/v1.0/users", q, &body, nil); err != nil {
		return integration.Identity{}, err
	}
	var matches []graphUser
	for _, usr := range body.Value {
		if strings.EqualFold(usr.Mail, email) || strings.EqualFold(usr.UserPrincipalName, email) {
			matches = append(matches, usr)
		}
	}
	switch len(matches) {
	case 0:
		return integration.Identity{}, integration.UserNotFound("no Entra user has mail or UPN %s", email)
	case 1:
	default:
		return integration.Identity{}, integration.UserAmbiguous("%d Entra users have mail or UPN %s", len(matches), email)
	}
	usr := matches[0]
	if !guidRe.MatchString(usr.ID) {
		return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "Graph returned a user id that is not an object id")
	}
	enabled := "unknown"
	if usr.AccountEnabled != nil {
		enabled = fmt.Sprint(*usr.AccountEnabled)
	}
	return integration.Identity{ID: strings.ToLower(usr.ID), Display: email, Attrs: map[string]string{
		"upn":             usr.UserPrincipalName,
		"mail":            usr.Mail,
		"account_enabled": enabled,
	}}, nil
}

// --- RBAC data --------------------------------------------------------------

type permission struct {
	Actions        []string `json:"actions"`
	NotActions     []string `json:"notActions"`
	DataActions    []string `json:"dataActions"`
	NotDataActions []string `json:"notDataActions"`
	Condition      string   `json:"condition"`
}

type roleDefinition struct {
	ID         string `json:"id"`
	Properties struct {
		RoleName    string       `json:"roleName"`
		Type        string       `json:"type"`
		Permissions []permission `json:"permissions"`
	} `json:"properties"`
}

type roleAssignment struct {
	ID         string `json:"id"`
	Properties struct {
		Scope            string `json:"scope"`
		RoleDefinitionID string `json:"roleDefinitionId"`
		PrincipalID      string `json:"principalId"`
		PrincipalType    string `json:"principalType"`
		Condition        string `json:"condition"`
	} `json:"properties"`
}

type principal struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type denyAssignment struct {
	ID         string `json:"id"`
	Properties struct {
		DenyAssignmentName      string       `json:"denyAssignmentName"`
		Scope                   string       `json:"scope"`
		DoNotApplyToChildScopes bool         `json:"doNotApplyToChildScopes"`
		Permissions             []permission `json:"permissions"`
		Principals              []principal  `json:"principals"`
		ExcludePrincipals       []principal  `json:"excludePrincipals"`
		Condition               string       `json:"condition"`
	} `json:"properties"`
}

// roleDefinitionIDRe is the id of a role definition, at a scope or at the
// tenant root, ending in the definition's GUID.
var roleDefinitionIDRe = regexp.MustCompile(`^(/[A-Za-z0-9_.()-]+)*/providers/Microsoft\.Authorization/roleDefinitions/[0-9a-fA-F-]{36}$`)

// roleDefinition reads a role definition by its full id, cached for roleTTL.
func (c *Connection) roleDefinition(ctx context.Context, id string) (roleDefinition, error) {
	if !roleDefinitionIDRe.MatchString(id) {
		return roleDefinition{}, integration.Errorf(integration.CodeUpstreamError, "a role assignment names a role definition id of an unexpected shape")
	}
	return c.roles.Do(ctx, strings.ToLower(id), func(ctx context.Context) (roleDefinition, time.Duration, error) {
		var def roleDefinition
		err := c.getJSON(ctx, c.arm, c.armTokens, id, url.Values{"api-version": {apiVersion}}, &def, func() error {
			return integration.Errorf(integration.CodeUpstreamError, "role definition %s is assigned but cannot be read", id)
		})
		if err != nil {
			return roleDefinition{}, 0, err
		}
		return def, roleTTL, nil
	})
}

// --- evaluation -------------------------------------------------------------

// matchOperation reports whether pattern (with * wildcards) matches op.
// UNVERIFIED: the documentation's examples mix case (microsoft.web/sites/
// restart/Action) and show * spanning slashes (*/read, Microsoft.Compute/*),
// so operations compare case-insensitively and * spans any characters.
func matchOperation(pattern, op string) bool {
	pattern, op = strings.ToLower(pattern), strings.ToLower(op)
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == op
	}
	if !strings.HasPrefix(op, parts[0]) {
		return false
	}
	op = op[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		j := strings.Index(op, parts[i])
		if j < 0 {
			return false
		}
		op = op[j+len(parts[i]):]
	}
	return strings.HasSuffix(op, parts[len(parts)-1])
}

// grants reports whether the permission grants op: an action matches and
// no notAction subtracts it.
func (p permission) grants(op string, data bool) bool {
	allow, deny := p.Actions, p.NotActions
	if data {
		allow, deny = p.DataActions, p.NotDataActions
	}
	matched := false
	for _, a := range allow {
		if matchOperation(a, op) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, n := range deny {
		if matchOperation(n, op) {
			return false
		}
	}
	return true
}

// covers reports whether an assignment at assigned applies to the target
// scope: the same scope or an ancestor. Management groups and the tenant
// root are ancestors of every subscription; which management group holds
// a subscription is not read, so any management-group assignment ARM
// returned for a subscription-or-lower target is taken as inherited.
// exact restricts to the same scope (doNotApplyToChildScopes).
func covers(assigned, target string, exact bool) (applies, uncertain bool) {
	a, t := strings.ToLower(strings.TrimRight(assigned, "/")), strings.ToLower(strings.TrimRight(target, "/"))
	if a == t {
		return true, false
	}
	if exact {
		return false, false
	}
	if a == "" {
		return true, false // the tenant root
	}
	isMG := func(s string) bool { return strings.HasPrefix(s, "/providers/microsoft.management/managementgroups/") }
	switch {
	case isMG(a) && strings.HasPrefix(t, "/subscriptions/"):
		return true, false
	case isMG(a) && isMG(t):
		// A different management group: an ancestor or a descendant;
		// the hierarchy is not read.
		return false, true
	}
	return strings.HasPrefix(t, a+"/"), false
}

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	t, err := parseTarget(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, err
	}
	id := r.Identity
	who := id.Display
	if id.Attr("account_enabled") == "false" {
		return integration.Denied("%s's account is disabled", who), nil
	}
	oid := strings.ToLower(id.ID)
	if !guidRe.MatchString(oid) {
		return integration.Decision{}, integration.Errorf(integration.CodeUpstreamError, "the identity carries no object id")
	}
	filter := "assignedTo('" + oid + "')"
	op := t.action.operation
	notVisible := func() error {
		return integration.Errorf(integration.CodeResourceNotVisible, "%s does not exist or hallpass cannot read its assignments (it needs Reader there)", t)
	}

	// Deny assignments first: a deny wins over any grant.
	raw, err := c.listARM(ctx, t.scope+"/providers/Microsoft.Authorization/denyAssignments", filter, notVisible)
	if err != nil {
		return integration.Decision{}, err
	}
	var denyUncertain string
	for _, item := range raw {
		var d denyAssignment
		if err := json.Unmarshal(item, &d); err != nil {
			return integration.Decision{}, integration.Wrap(integration.CodeUpstreamError, err, "a deny assignment could not be decoded")
		}
		applies, uncertain := covers(d.Properties.Scope, t.scope, d.Properties.DoNotApplyToChildScopes)
		if !applies && !uncertain {
			continue
		}
		matched := false
		conditional := d.Properties.Condition != ""
		for _, p := range d.Properties.Permissions {
			if p.grants(op, t.action.data) {
				matched = true
				if p.Condition != "" {
					conditional = true
				}
			}
		}
		if !matched {
			continue
		}
		// UNVERIFIED: whether assignedTo() already leaves out denies whose
		// excludePrincipals name the user; applying them again is safe.
		excluded, excludeUnknown := false, false
		for _, p := range d.Properties.ExcludePrincipals {
			switch {
			case strings.EqualFold(p.ID, oid):
				excluded = true
			case strings.EqualFold(p.Type, "User") || strings.EqualFold(p.Type, "ServicePrincipal"):
				// Another principal, not this user.
			default:
				// A group: whether it holds the user is not read.
				excludeUnknown = true
			}
		}
		if excluded {
			continue
		}
		name := orEmpty(d.Properties.DenyAssignmentName, "unnamed")
		switch {
		case uncertain || excludeUnknown || conditional:
			if denyUncertain == "" {
				denyUncertain = name
			}
		default:
			return integration.Denied("deny assignment %q at %s blocks %s for %s", name, d.Properties.Scope, op, who), nil
		}
	}

	// Role assignments: any unconditional grant at or above the scope.
	raw, err = c.listARM(ctx, t.scope+"/providers/Microsoft.Authorization/roleAssignments", filter, notVisible)
	if err != nil {
		return integration.Decision{}, err
	}
	var conditionalRole, uncertainRole string
	roles := 0
	for _, item := range raw {
		var a roleAssignment
		if err := json.Unmarshal(item, &a); err != nil {
			return integration.Decision{}, integration.Wrap(integration.CodeUpstreamError, err, "a role assignment could not be decoded")
		}
		applies, uncertain := covers(a.Properties.Scope, t.scope, false)
		if !applies && !uncertain {
			continue
		}
		roles++
		def, err := c.roleDefinition(ctx, a.Properties.RoleDefinitionID)
		if err != nil {
			return integration.Decision{}, err
		}
		granted := false
		for _, p := range def.Properties.Permissions {
			if p.grants(op, t.action.data) {
				granted = true
				break
			}
		}
		if !granted {
			continue
		}
		name := orEmpty(def.Properties.RoleName, def.ID)
		switch {
		case uncertain:
			if uncertainRole == "" {
				uncertainRole = name
			}
		case a.Properties.Condition != "":
			if conditionalRole == "" {
				conditionalRole = name
			}
		default:
			if denyUncertain != "" {
				return integration.Unsupported("role %q grants %s to %s at %s, but deny assignment %q may block it (a condition, an excluded group or a management-group scope hallpass cannot evaluate)", name, op, who, a.Properties.Scope, denyUncertain), nil
			}
			via := "directly"
			if !strings.EqualFold(a.Properties.PrincipalID, oid) {
				via = "through " + strings.ToLower(orEmpty(a.Properties.PrincipalType, "group")) + " " + a.Properties.PrincipalID
			}
			return integration.Allowed("role %q assigned %s at %s grants %s to %s", name, via, a.Properties.Scope, op, who), nil
		}
	}
	switch {
	case conditionalRole != "":
		return integration.Unsupported("role %q grants %s to %s only under an ABAC condition hallpass does not evaluate", conditionalRole, op, who), nil
	case uncertainRole != "":
		return integration.Unsupported("role %q grants %s to %s at a management group whose place above %s hallpass cannot tell", uncertainRole, op, who, t), nil
	case roles == 0:
		return integration.Denied("%s has no role assignment at or above %s", who, t), nil
	}
	return integration.Denied("none of %s's %d role assignment(s) at or above %s grants %s", who, roles, t, op), nil
}

// --- probe ------------------------------------------------------------------

// Probe fetches an ARM token and lists role definitions at the tenant root
// (UNVERIFIED: the form az role definition list uses; the specification
// file has no path for it), and a Graph user page when identity is local.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var body struct {
		Value []json.RawMessage `json:"value"`
	}
	q := url.Values{"api-version": {apiVersion}, "$filter": {"type eq 'BuiltInRole'"}}
	if err := c.getJSON(ctx, c.arm, c.armTokens, "/providers/Microsoft.Authorization/roleDefinitions", q, &body, nil); err != nil {
		return integration.ProbeResult{}, err
	}
	res := integration.ProbeResult{Summary: fmt.Sprintf("authenticated to Azure Resource Manager; %d built-in role definitions visible", len(body.Value))}
	if c.identity == nil {
		var users struct {
			Value []graphUser `json:"value"`
		}
		if err := c.getJSON(ctx, c.graph, c.graphTokens, "/v1.0/users", url.Values{"$top": {"1"}, "$select": {"id"}}, &users, nil); err != nil {
			return integration.ProbeResult{}, err
		}
		res.Summary += "; Graph user listing works"
	}
	res.Warnings = append(res.Warnings,
		"role and deny assignments are visible only where the app registration holds Reader (Microsoft.Authorization/*/read); scopes it cannot read answer resource_not_visible",
		"assignments with ABAC conditions and deny assignments excluding groups answer unknown")
	return res, nil
}
