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
	"slices"
	"sort"
	"strings"
	"sync"
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

	// selfTTL is how long hallpass's own SCIM record is kept.
	selfTTL = 10 * time.Minute
)

var (
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

	// self is hallpass's own principal name (a service principal's
	// application id, or a user's email), read once from SCIM /Me.
	selfMu      sync.Mutex
	self        string
	selfFetched time.Time
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
		return "", authx.ClassifyTokenError(err)
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
	case 404:
		return integration.Wrap(integration.CodeUpstreamError, err, "the workspace has no endpoint to %s: check url (%s)", what, codeOr(errorCode(err), "NOT_FOUND"))
	}
	return httpx.Classify(err)
}

func codeOr(code, def string) string {
	if code == "" {
		return def
	}
	return code
}

// getJSON is one GET with JSON decoding. In oauth mode a 401 drops the
// cached token and retries once with a fresh one. A 404 comes back as the
// raw httpx error so the caller can name what is missing.
func (c *Connection) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	resp, err := c.api.Do(ctx, &httpx.Request{Method: http.MethodGet, Path: path, Query: q})
	if httpx.Status(err) == 401 && c.mode == modeOAuth {
		c.tokens.Invalidate()
		resp, err = c.api.Do(ctx, &httpx.Request{Method: http.MethodGet, Path: path, Query: q})
	}
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

var scimAttributes = url.Values{"attributes": {"id,userName,active,groups"}}

// ResolveIdentity finds the workspace user whose userName is the email.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if !integration.IsEmail(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user email %q is not an address", email)
	}
	var out struct {
		Resources []scimUser `json:"Resources"`
	}
	// IsEmail admits no quote or backslash, so the filter cannot be broken
	// out of.
	q := url.Values{"filter": {`userName eq "` + email + `"`}, "attributes": scimAttributes["attributes"]}
	if err := c.getJSON(ctx, scimUsers, q, &out); err != nil {
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

// me reads hallpass's own SCIM record.
func (c *Connection) me(ctx context.Context) (scimUser, error) {
	var me scimUser
	if err := c.getJSON(ctx, scimMe, scimAttributes, &me); err != nil {
		return scimUser{}, classify(err, "read its own identity")
	}
	return me, nil
}

// selfName is hallpass's own principal name as it appears in grants, cached
// for selfTTL. It is needed to tell an empty grant listing from one Unity
// Catalog has filtered down to hallpass's own grants.
func (c *Connection) selfName(ctx context.Context) (string, error) {
	c.selfMu.Lock()
	defer c.selfMu.Unlock()
	if c.self != "" && c.now().Sub(c.selfFetched) < selfTTL {
		return c.self, nil
	}
	me, err := c.me(ctx)
	if err != nil {
		return "", err
	}
	if me.UserName == "" {
		return "", integration.Errorf(integration.CodeUpstreamError, "the workspace did not report hallpass's own principal name")
	}
	c.self, c.selfFetched = strings.ToLower(me.UserName), c.now()
	return c.self, nil
}

// --- checks -----------------------------------------------------------------

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	q, err := parseRef(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, err
	}
	user := strings.ToLower(r.Identity.ID)
	if !integration.IsEmail(user) {
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
	return slices.Contains(groups, principal)
}

// effectiveGrant is one privilege the user holds and where it came from.
type effectiveGrant struct {
	privilege, principal, from string
}

// grantListing is what one effective-permissions read yields for the user.
type grantListing struct {
	held   heldPrivileges
	grants []effectiveGrant
	// others is true when some principal other than hallpass itself
	// appears in the listing: proof that hallpass sees more than its own
	// grants.
	others bool
}

// readGrants reads every page of the securable's effective permissions and
// keeps the privileges of the user and of the user's groups.
func (c *Connection) readGrants(ctx context.Context, q ref, user string, groups []string, self string) (grantListing, error) {
	out := grantListing{held: newHeld()}
	path := "/api/2.1/unity-catalog/effective-permissions/" + httpx.PathEscape(q.securable) + "/" + httpx.PathEscape(q.fullName)
	// max_results=0 asks for the server's page size; every page is followed.
	query := url.Values{"max_results": {"0"}}
	for n := 0; ; n++ {
		if n >= httpx.MaxPages {
			return out, integration.Errorf(integration.CodeUpstreamError, "too many pages of grants on %s %s", q.securable, q.fullName)
		}
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
		if err := c.getJSON(ctx, path, query, &page); err != nil {
			return out, err
		}
		for _, a := range page.Assignments {
			if !strings.EqualFold(a.Principal, self) {
				out.others = true
			}
			if !principalMatches(a.Principal, user, groups) {
				continue
			}
			for _, p := range a.Privileges {
				from, scope := "", q.securable
				if p.InheritedFromType != "" {
					scope = strings.ToLower(p.InheritedFromType)
					from = scope + " " + p.InheritedFromName
				}
				if p.Privilege == privAllPrivileges {
					out.held.allOn = append(out.held.allOn, scope)
				} else {
					out.held.named[p.Privilege] = true
				}
				out.grants = append(out.grants, effectiveGrant{p.Privilege, a.Principal, from})
			}
		}
		if page.NextPageToken == "" {
			return out, nil
		}
		query = url.Values{"max_results": {"0"}, "page_token": {page.NextPageToken}}
	}
}

// checkUnityCatalog reads the securable's effective permissions, unions the
// privileges granted to the user and to the user's groups, and falls back to
// ownership when they do not cover the action.
func (c *Connection) checkUnityCatalog(ctx context.Context, q ref, user string, id integration.Identity, raw string) (integration.Decision, error) {
	self, err := c.selfName(ctx)
	if err != nil {
		return integration.Decision{}, err
	}
	what := q.securable + " " + q.fullName
	listing, err := c.readGrants(ctx, q, user, id.Groups, self)
	if err != nil {
		if httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s does not exist or hallpass cannot see it", what), nil
		}
		return integration.Decision{}, classify(err, "read the grants on "+what)
	}
	need := strings.Join(q.privileges, ", ") + " on " + raw
	if ok, _ := satisfiesPrivileges(listing.held, q.privileges); ok {
		return integration.Allowed("%s holds %s (%s)", user, need, describeGrants(listing.grants, user)), nil
	}
	// UNVERIFIED: whether effective-permissions already lists the owner's
	// implicit privileges; the owner is looked up separately so an owner
	// is never denied.
	owner, err := c.owner(ctx, q)
	if err != nil {
		if httpx.Status(err) == 404 {
			return integration.UnknownDecision(integration.CodeResourceNotVisible, "%s does not exist or hallpass cannot see it", what), nil
		}
		return integration.Decision{}, classify(err, "read "+what)
	}
	if owner != "" && principalMatches(owner, user, id.Groups) {
		// Ownership stands for every privilege on the securable itself,
		// MANAGE included, not for USE_CATALOG or USE_SCHEMA on its parents.
		held := newHeld()
		for k := range listing.held.named {
			held.named[k] = true
		}
		held.allOn = append(held.allOn, listing.held.allOn...)
		for _, p := range q.privileges {
			if covers(q.securable, p, true) {
				held.named[p] = true
			}
		}
		if ok, _ := satisfiesPrivileges(held, q.privileges); ok {
			return integration.Allowed("%s owns %s (owner %s), which carries %s", user, what, owner, strings.Join(q.privileges, ", ")), nil
		}
		_, missing := satisfiesPrivileges(held, q.privileges)
		return integration.Denied("%s owns %s but lacks %s on its parents", user, what, strings.Join(missing, ", ")), nil
	}
	if !listing.others {
		// Unity Catalog shows a principal without MANAGE or ownership only
		// its own grants, with a 200. A listing with nobody but hallpass in
		// it is either that or a securable nobody has grants on; hallpass
		// cannot tell, so it does not deny.
		return integration.UnknownDecision(integration.CodeResourceNotVisible, "the grants on %s list no principal but hallpass itself: either nobody else holds any, or hallpass may only see its own; give hallpass MANAGE on the catalog to be sure", what), nil
	}
	_, missing := satisfiesPrivileges(listing.held, q.privileges)
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
	if c.adminsRule && id.Attr("admin") == "true" && q.level != "IS_OWNER" {
		return integration.Allowed("%s is a workspace admin, which carries CAN_MANAGE on every object, so %s", user, what), nil
	}
	if len(held) == 0 {
		return integration.Denied("%s has no permission on %s", user, raw), nil
	}
	slices.Sort(held)
	return integration.Denied("%s holds only %s on %s, not %s", user, strings.Join(slices.Compact(held), ", "), raw, q.level), nil
}

// --- probe ------------------------------------------------------------------

// Probe reads hallpass's own SCIM record and reports whether it is a
// workspace admin, which decides how much of the workspace it can read.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	me, err := c.me(ctx)
	if err != nil {
		return integration.ProbeResult{}, err
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
