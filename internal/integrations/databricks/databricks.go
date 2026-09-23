// Package databricks checks permissions in one Databricks workspace.
//
// hallpass authenticates as a service principal (OAuth M2M) or with a
// personal access token, finds the user through the workspace SCIM API,
// and asks the workspace itself: the Unity Catalog effective-permissions
// endpoint for catalogs, schemas, tables, volumes, functions and models
// (which folds in privileges inherited down the hierarchy), and the
// Permissions API for clusters, jobs, warehouses, notebooks and the other
// workspace objects (whose ACLs carry inherited entries). Grants to the
// user's groups count, workspace admins hold CAN_MANAGE on every object,
// and the owner of a securable holds every privilege on it. Nothing is
// written.
package databricks

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const (
	modeOAuth = "oauth"
	modeToken = "token"

	scopeAllAPIs = "all-apis"
	adminsGroup  = "admins"

	scimUsers = "/api/2.0/preview/scim/v2/Users"
	scimMe    = "/api/2.0/preview/scim/v2/Me"
)

var (
	emailRe    = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+/=?^_{|}~.-]{1,64}@[A-Za-z0-9.-]{1,255}$`)
	clientIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{8,128}$`)
	// errorCodeRe finds error_code in a Databricks error body snippet. The
	// message is never used.
	errorCodeRe = regexp.MustCompile(`"error_code"\s*:\s*"([A-Z_]+)"`)
)

// Integration is the databricks product.
type Integration struct{}

// Name is "databricks".
func (Integration) Name() string { return "databricks" }

// Fields of a databricks connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		integration.URLField(true, "workspace URL, e.g. https://adb-1234567890123456.7.azuredatabricks.net or https://dbc-a1b2c3d4-e5f6.cloud.databricks.com"),
		{Name: "auth_mode", Default: modeOAuth, Enum: []string{modeOAuth, modeToken},
			Description: "oauth: service principal with client_id and an OAuth secret (credential); token: a personal access token (credential)"},
		{Name: "client_id", Validate: validateClientID,
			Description: "the service principal's application id, auth_mode oauth"},
		integration.CredentialField(true, "the service principal's OAuth secret (auth_mode oauth) or the personal access token (auth_mode token)"),
		{Name: "token_url", Validate: integration.ValidateHTTPSURL,
			Description: "OAuth token endpoint; default {url}/oidc/v1/token"},
		{Name: "admins_manage_all", Default: "true", Enum: []string{"true", "false"},
			Description: "true: members of the workspace admins group are allowed every workspace-object action, as Databricks grants them CAN_MANAGE on every object"},
	}
}

func validateClientID(v string) error {
	if v == "" || clientIDRe.MatchString(v) {
		return nil
	}
	return errors.New("must be a service principal application id")
}

// New builds a connection. It touches no network; the secret is read at
// call time so a rotated file takes effect.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(s.Get("url"), "/")
	if base == "" {
		return nil, errors.New("url is required")
	}
	c := &Connection{
		settings:   s,
		base:       base,
		mode:       s.Get("auth_mode"),
		clientID:   s.Get("client_id"),
		tokenURL:   strings.TrimRight(s.Get("token_url"), "/"),
		adminsRule: s.Bool("admins_manage_all", true),
		now:        d.Now,
	}
	if c.mode == "" {
		c.mode = modeOAuth
	}
	if s.Secret("credential").IsZero() {
		return nil, errors.New("credential is required")
	}
	switch c.mode {
	case modeOAuth:
		if err := validateClientID(c.clientID); err != nil || c.clientID == "" {
			return nil, errors.New("client_id is required in auth_mode oauth and must be a service principal application id")
		}
		if c.tokenURL == "" {
			c.tokenURL = base + "/oidc/v1/token"
		}
	case modeToken:
	default:
		return nil, fmt.Errorf("auth_mode %q must be oauth or token", c.mode)
	}
	if c.now == nil {
		c.now = time.Now
	}
	c.plain = &httpx.Client{HTTP: hc, Logger: d.Logger}
	c.tokens = &authx.TokenSource{Now: c.now, Fetch: c.mint}
	c.api = &httpx.Client{HTTP: hc, Base: base, Logger: d.Logger, Auth: httpx.BearerAuth(c.bearer)}
	return c, nil
}

// Connection is one workspace.
type Connection struct {
	settings   *integration.Settings
	base       string
	mode       string
	clientID   string
	tokenURL   string
	adminsRule bool
	now        func() time.Time

	plain  *httpx.Client // the token endpoint
	api    *httpx.Client // the workspace APIs
	tokens *authx.TokenSource
}

// --- authentication ---------------------------------------------------------

// bearer is the Authorization value: the cached OAuth token or the PAT.
func (c *Connection) bearer(ctx context.Context) (string, error) {
	if c.mode == modeToken {
		t, err := c.settings.Secret("credential").GetString()
		if err != nil {
			return "", integration.Wrap(integration.CodeCredentialRejected, err, "the access token could not be read")
		}
		return strings.TrimSpace(t), nil
	}
	t, err := c.tokens.Get(ctx)
	if err != nil {
		return "", tokenError(err)
	}
	return t, nil
}

// mint runs the client credentials grant: the client id and secret travel
// in an HTTP Basic header, as Databricks documents.
func (c *Connection) mint(ctx context.Context) (authx.Token, error) {
	secret, err := c.settings.Secret("credential").GetString()
	if err != nil {
		return authx.Token{}, integration.Wrap(integration.CodeCredentialRejected, err, "the OAuth secret could not be read")
	}
	basic := base64.StdEncoding.EncodeToString([]byte(c.clientID + ":" + strings.TrimSpace(secret)))
	return authx.FetchToken(ctx, c.plain, authx.TokenRequest{
		URL:    c.tokenURL,
		Form:   url.Values{"grant_type": {"client_credentials"}, "scope": {scopeAllAPIs}},
		Header: http.Header{"Authorization": {"Basic " + basic}},
		Now:    c.now,
	})
}

// tokenError classifies a minting failure.
func tokenError(err error) *integration.Error {
	var te *authx.TokenError
	if errors.As(err, &te) {
		switch {
		case te.Status == 429:
			return integration.Wrap(integration.CodeUpstreamRateLimit, err, "the token endpoint rate limited hallpass")
		case te.Status >= 500:
			return integration.Wrap(integration.CodeUpstreamError, err, "the token endpoint failed (HTTP %d)", te.Status)
		case te.Status == 401 || te.Status == 403 || te.Code == "invalid_client" || te.Code == "invalid_grant" || te.Code == "unauthorized_client":
			return integration.Wrap(integration.CodeCredentialRejected, err, "the token endpoint refused the service principal's client id and secret")
		}
	}
	return authx.ClassifyTokenError(err)
}

// --- API transport ----------------------------------------------------------

// errorCode extracts error_code from a Databricks error body snippet.
func errorCode(err error) string {
	var se *httpx.StatusError
	if !errors.As(err, &se) {
		return ""
	}
	if m := errorCodeRe.FindStringSubmatch(se.Snippet); m != nil {
		return m[1]
	}
	return ""
}

// classify maps an API error to an integration error. 404 is left to the
// caller, who knows whether it means the object or the user.
func classify(err error, what string) *integration.Error {
	switch httpx.Status(err) {
	case 401:
		return integration.Wrap(integration.CodeCredentialRejected, err, "the workspace rejected hallpass's credential")
	case 403:
		return integration.Wrap(integration.CodeCredentialRejected, err, "the workspace refused to %s (%s): hallpass's principal needs CAN_MANAGE on the object, or MANAGE, ownership or metastore admin for Unity Catalog grants", what, codeOr(errorCode(err), "PERMISSION_DENIED"))
	case 400:
		return integration.Wrap(integration.CodeInvalidRequest, err, "the workspace rejected the request to %s (%s)", what, codeOr(errorCode(err), "BAD_REQUEST"))
	}
	return httpx.Classify(err)
}

func codeOr(code, def string) string {
	if code == "" {
		return def
	}
	return code
}

// getJSON is one GET with JSON decoding; a 404 comes back as the raw
// httpx error so the caller can name what is missing.
func (c *Connection) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	resp, err := c.api.Do(ctx, &httpx.Request{Method: http.MethodGet, Path: path, Query: q})
	if err != nil {
		return err
	}
	if err := resp.JSON(out); err != nil {
		return integration.Wrap(integration.CodeUpstreamError, err, "the workspace returned an unreadable response")
	}
	return nil
}

// --- identity ---------------------------------------------------------------

// scimUser is the subset of a SCIM user hallpass reads.
type scimUser struct {
	ID       string `json:"id"`
	UserName string `json:"userName"`
	// Active is a pointer so an absent field is not mistaken for false.
	Active *bool `json:"active"`
	Groups []struct {
		Display string `json:"display"`
		Value   string `json:"value"`
	} `json:"groups"`
}

func (u scimUser) groupNames() []string {
	out := make([]string, 0, len(u.Groups))
	for _, g := range u.Groups {
		if g.Display != "" {
			out = append(out, g.Display)
		}
	}
	sort.Strings(out)
	return out
}

func (u scimUser) isAdmin() bool {
	for _, g := range u.Groups {
		if g.Display == adminsGroup {
			return true
		}
	}
	return false
}

// ResolveIdentity finds the workspace user whose userName is the email.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if !emailRe.MatchString(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user email %q is not an address", email)
	}
	var out struct {
		Resources []scimUser `json:"Resources"`
	}
	// emailRe admits no quote or backslash, so the filter cannot be broken
	// out of.
	q := url.Values{"filter": {`userName eq "` + email + `"`}, "attributes": {"id,userName,active,groups"}}
	if err := c.getJSON(ctx, scimUsers, q, &out); err != nil {
		if httpx.Status(err) == 404 {
			return integration.Identity{}, integration.UserNotFound("no workspace user with email %s", email)
		}
		return integration.Identity{}, classify(err, "search users")
	}
	var matches []scimUser
	for _, r := range out.Resources {
		if strings.EqualFold(r.UserName, email) {
			matches = append(matches, r)
		}
	}
	switch len(matches) {
	case 0:
		return integration.Identity{}, integration.UserNotFound("no workspace user with email %s", email)
	case 1:
	default:
		return integration.Identity{}, integration.UserAmbiguous("%d workspace users match %s", len(matches), email)
	}
	m := matches[0]
	active := "unknown"
	if m.Active != nil {
		active = fmt.Sprint(*m.Active)
	}
	return integration.Identity{
		ID:      strings.ToLower(m.UserName),
		Display: m.UserName,
		Attrs:   map[string]string{"id": m.ID, "active": active, "admin": fmt.Sprint(m.isAdmin())},
		Groups:  m.groupNames(),
	}, nil
}

// --- checks -----------------------------------------------------------------

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	q, err := parseRef(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, err
	}
	user := strings.ToLower(r.Identity.ID)
	if !emailRe.MatchString(user) {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "identity is not a workspace user")
	}
	switch r.Identity.Attr("active") {
	case "true":
	case "false":
		return integration.Denied("%s is deactivated in the workspace", user), nil
	default:
		return integration.Unsupported("the workspace did not report whether %s is active", user), nil
	}
	if q.uc {
		return c.checkUnityCatalog(ctx, q, user, r.Identity, r.Resource.Raw)
	}
	return c.checkWorkspaceObject(ctx, q, user, r.Identity, r.Resource.Raw)
}

// principalMatches reports whether an ACL or grant principal is the user or
// one of the user's groups.
func principalMatches(principal, user string, groups []string) bool {
	if strings.EqualFold(principal, user) {
		return true
	}
	for _, g := range groups {
		if principal == g {
			return true
		}
	}
	return false
}

// effectiveGrant is one privilege the user holds and where it came from.
type effectiveGrant struct {
	privilege, principal, from string
}

// checkUnityCatalog reads the securable's effective permissions, unions the
// privileges granted to the user and to the user's groups, and falls back to
// ownership when they do not cover the action.
func (c *Connection) checkUnityCatalog(ctx context.Context, q ref, user string, id integration.Identity, raw string) (integration.Decision, error) {
	held := map[string]bool{}
	var grants []effectiveGrant
	path := "/api/2.1/unity-catalog/effective-permissions/" + httpx.PathEscape(q.securable) + "/" + httpx.PathEscape(q.fullName)
	// max_results=0 asks for the server's page size; every page is followed.
	first := &httpx.Request{Method: http.MethodGet, Path: path, Query: url.Values{"max_results": {"0"}}}
	err := c.api.Paginate(ctx, first, func(resp *httpx.Response) (*httpx.Request, error) {
		var page struct {
			Assignments []struct {
				Principal  string `json:"principal"`
				Privileges []struct {
					Privilege         string `json:"privilege"`
					InheritedFromType string `json:"inherited_from_type"`
					InheritedFromName string `json:"inherited_from_name"`
				} `json:"privileges"`
			} `json:"privilege_assignments"`
			NextPageToken string `json:"next_page_token"`
		}
		if err := resp.JSON(&page); err != nil {
			return nil, integration.Wrap(integration.CodeUpstreamError, err, "the workspace returned an unreadable response")
		}
		for _, a := range page.Assignments {
			if !principalMatches(a.Principal, user, id.Groups) {
				continue
			}
			for _, p := range a.Privileges {
				held[p.Privilege] = true
				from := ""
				if p.InheritedFromType != "" {
					from = strings.ToLower(p.InheritedFromType) + " " + p.InheritedFromName
				}
				grants = append(grants, effectiveGrant{p.Privilege, a.Principal, from})
			}
		}
		if page.NextPageToken == "" {
			return nil, nil
		}
		return &httpx.Request{Method: http.MethodGet, Path: path, Query: url.Values{"max_results": {"0"}, "page_token": {page.NextPageToken}}}, nil
	})
	if err != nil {
		if httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s %s does not exist or hallpass cannot see it", q.securable, q.fullName), nil
		}
		if errors.Is(err, httpx.ErrTooManyPages) {
			return integration.Decision{}, integration.Wrap(integration.CodeUpstreamError, err, "too many pages of grants on %s %s", q.securable, q.fullName)
		}
		return integration.Decision{}, classify(err, "read the grants on "+q.securable+" "+q.fullName)
	}
	what := strings.Join(q.privileges, ", ") + " on " + raw
	if ok, _ := satisfiesPrivileges(held, q.privileges); ok {
		return integration.Allowed("%s holds %s (%s)", user, what, describeGrants(grants, user)), nil
	}
	// UNVERIFIED: whether effective-permissions already lists the owner's
	// implicit privileges; the owner is looked up separately so an owner
	// is never denied.
	owner, err := c.owner(ctx, q)
	if err != nil {
		if httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s %s does not exist or hallpass cannot see it", q.securable, q.fullName), nil
		}
		return integration.Decision{}, classify(err, "read "+q.securable+" "+q.fullName)
	}
	if owner != "" && principalMatches(owner, user, id.Groups) {
		return integration.Allowed("%s owns %s %s (owner %s), which carries %s", user, q.securable, q.fullName, owner, strings.Join(q.privileges, ", ")), nil
	}
	_, missing := satisfiesPrivileges(held, q.privileges)
	return integration.Denied("%s lacks %s on %s", user, strings.Join(missing, ", "), raw), nil
}

// describeGrants renders where the user's privileges come from, briefly.
func describeGrants(grants []effectiveGrant, user string) string {
	seen := map[string]bool{}
	var parts []string
	for _, g := range grants {
		var s string
		switch {
		case strings.EqualFold(g.principal, user) && g.from == "":
			s = "granted directly"
		case strings.EqualFold(g.principal, user):
			s = "inherited from " + g.from
		case g.from == "":
			s = "via group " + g.principal
		default:
			s = "via group " + g.principal + " on " + g.from
		}
		if !seen[s] {
			seen[s] = true
			parts = append(parts, s)
		}
	}
	if len(parts) > 3 {
		parts = append(parts[:3], "...")
	}
	return strings.Join(parts, "; ")
}

// ucCollections maps a securable type to its metadata endpoint.
var ucCollections = map[string]string{
	"catalog": "catalogs", "schema": "schemas", "table": "tables", "volume": "volumes", "function": "functions", "model": "models",
}

// owner reads the securable's owner: a user email or a group name.
func (c *Connection) owner(ctx context.Context, q ref) (string, error) {
	var out struct {
		Owner string `json:"owner"`
	}
	if err := c.getJSON(ctx, "/api/2.1/unity-catalog/"+ucCollections[q.securable]+"/"+httpx.PathEscape(q.fullName), nil, &out); err != nil {
		return "", err
	}
	return out.Owner, nil
}

// checkWorkspaceObject reads the object's ACL and looks for a level, held
// by the user or one of the user's groups, that implies the one needed.
func (c *Connection) checkWorkspaceObject(ctx context.Context, q ref, user string, id integration.Identity, raw string) (integration.Decision, error) {
	var acl struct {
		ObjectID string `json:"object_id"`
		Entries  []struct {
			UserName             string `json:"user_name"`
			GroupName            string `json:"group_name"`
			ServicePrincipalName string `json:"service_principal_name"`
			Permissions          []struct {
				Level     string `json:"permission_level"`
				Inherited bool   `json:"inherited"`
			} `json:"all_permissions"`
		} `json:"access_control_list"`
	}
	path := "/api/2.0/permissions/" + q.object + "/" + httpx.PathEscape(q.id)
	if err := c.getJSON(ctx, path, nil, &acl); err != nil {
		if httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s %s does not exist or hallpass cannot see it", q.object, q.id), nil
		}
		return integration.Decision{}, classify(err, "read the permissions of "+q.object+" "+q.id)
	}
	var held []string
	via := map[string]string{}
	for _, e := range acl.Entries {
		principal := e.UserName
		if principal == "" {
			principal = e.GroupName
		}
		if principal == "" || !principalMatches(principal, user, id.Groups) {
			continue
		}
		for _, p := range e.Permissions {
			held = append(held, p.Level)
			if _, ok := via[p.Level]; !ok {
				via[p.Level] = principal
			}
		}
	}
	what := q.level + " on " + raw
	if ok, by := satisfiesLevel(held, q.level, q.chains); ok {
		how := "granted directly"
		if !strings.EqualFold(via[by], user) {
			how = "via group " + via[by]
		}
		if by == q.level {
			return integration.Allowed("%s holds %s (%s)", user, what, how), nil
		}
		return integration.Allowed("%s holds %s, which implies %s (%s)", user, by, what, how), nil
	}
	if c.adminsRule && id.Attr("admin") == "true" {
		return integration.Allowed("%s is a workspace admin, which carries CAN_MANAGE on every object, so %s", user, what), nil
	}
	if len(held) == 0 {
		return integration.Denied("%s has no permission on %s", user, raw), nil
	}
	sort.Strings(held)
	return integration.Denied("%s holds only %s on %s, not %s", user, strings.Join(unique(held), ", "), raw, q.level), nil
}

func unique(xs []string) []string {
	var out []string
	for i, x := range xs {
		if i == 0 || xs[i-1] != x {
			out = append(out, x)
		}
	}
	return out
}

// --- probe ------------------------------------------------------------------

// Probe reads hallpass's own SCIM record and reports whether it is a
// workspace admin, which decides how much of the workspace it can read.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var me scimUser
	if err := c.getJSON(ctx, scimMe, url.Values{"attributes": {"id,userName,active,groups"}}, &me); err != nil {
		return integration.ProbeResult{}, classify(err, "read its own identity")
	}
	who := me.UserName
	if who == "" {
		who = "principal " + me.ID
	}
	out := integration.ProbeResult{Summary: fmt.Sprintf("authenticated as %s in %s (workspace admin: %v)", who, c.base, me.isAdmin())}
	if !me.isAdmin() {
		out.Warnings = append(out.Warnings, "hallpass's principal is not a workspace admin: workspace objects it lacks CAN_MANAGE on and Unity Catalog securables it does not own or MANAGE answer unknown")
	} else {
		out.Warnings = append(out.Warnings, "hallpass's principal is a workspace admin, which can also change the workspace; Databricks has no read-only admin role, so keep the credential tightly held")
	}
	if !c.adminsRule {
		out.Warnings = append(out.Warnings, "admins_manage_all is false: workspace admins are judged by the object ACL alone, which may omit their implicit CAN_MANAGE")
	}
	return out, nil
}
