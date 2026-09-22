// Package jira checks Jira Cloud permissions with the permissions/check API.
//
// hallpass resolves the caller's email to an Atlassian accountId with the
// user search API, then asks POST /rest/api/3/permissions/check whether that
// account holds the permission on a project, an issue or globally. Jira
// evaluates permission schemes, project roles, groups and issue-level grants;
// hallpass only reads the answer. Nothing is changed.
//
// The package also holds the Atlassian Cloud transport (Site) that the
// confluence integration shares: the three auth modes (basic, scoped_token,
// oauth_client) and cloud id discovery. Jira Data Center is out of scope.
package jira

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/secret"
)

// Gateway is the Atlassian API gateway that scoped_token and oauth_client
// connections talk to, as https://api.atlassian.com/ex/<product>/<cloudId>.
// Tests point it at a fake server before calling New.
var Gateway = "https://api.atlassian.com"

// TokenURL is the OAuth 2.0 token endpoint used by oauth_client connections.
// Tests point it at a fake server before calling New.
var TokenURL = "https://auth.atlassian.com/oauth/token"

// Auth modes.
const (
	ModeBasic       = "basic"
	ModeScopedToken = "scoped_token"
	ModeOAuthClient = "oauth_client"
)

// SiteFields are the connection keys every Atlassian Cloud integration
// accepts: url, auth_mode, username, credential and client_id.
func SiteFields() []integration.Field {
	return []integration.Field{
		integration.URLField(true, "site URL, e.g. https://acme.atlassian.net"),
		{Name: "auth_mode", Default: ModeBasic, Enum: []string{ModeBasic, ModeScopedToken, ModeOAuthClient},
			Description: "basic: email + API token against the site; scoped_token: scoped API token against api.atlassian.com; oauth_client: OAuth 2.0 client credentials"},
		{Name: "username", Description: "email of the bot account (required for auth_mode basic)"},
		integration.CredentialField(true, "API token (basic, scoped_token) or OAuth client secret (oauth_client)"),
		{Name: "client_id", Description: "OAuth 2.0 client id (required for auth_mode oauth_client)"},
	}
}

// Site is one Atlassian Cloud site reached with one auth mode. A jira and a
// confluence connection each own one. Relative request paths are resolved
// against the site URL (basic) or the gateway (scoped_token, oauth_client),
// where the cloud id is discovered once and cached.
type Site struct {
	// URL is the site URL without a trailing slash.
	URL string
	// Mode is the auth mode.
	Mode string
	// Product is the gateway product segment: "jira" or "confluence".
	Product string

	client   *httpx.Client // authenticated
	plain    *httpx.Client // unauthenticated: tenant_info and the token endpoint
	gateway  string
	tokenURL string

	mu      sync.Mutex
	cloudID string
}

// NewSite builds the transport for one connection. It does not touch the
// network.
func NewSite(s *integration.Settings, d integration.Deps, product string) (*Site, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	cred := s.Secret("credential")
	if cred.IsZero() {
		return nil, errors.New("credential is required")
	}
	mode := s.Get("auth_mode")
	if mode == "" {
		mode = ModeBasic
	}
	site := &Site{
		URL:      strings.TrimRight(s.Get("url"), "/"),
		Mode:     mode,
		Product:  product,
		gateway:  strings.TrimRight(Gateway, "/"),
		tokenURL: TokenURL,
	}
	site.plain = &httpx.Client{HTTP: hc, Logger: d.Logger}
	secretString := func(context.Context) (string, error) { return cred.GetString() }
	var auth func(context.Context, *http.Request) error
	switch mode {
	case ModeBasic:
		user := s.Get("username")
		if user == "" {
			return nil, errors.New("username is required for auth_mode basic")
		}
		auth = httpx.BasicAuth(user, secretString)
	case ModeScopedToken:
		auth = httpx.BearerAuth(secretString)
	case ModeOAuthClient:
		clientID := s.Get("client_id")
		if clientID == "" {
			return nil, errors.New("client_id is required for auth_mode oauth_client")
		}
		ts := &authx.TokenSource{Fetch: site.fetchToken(clientID, cred), Now: d.Now}
		auth = httpx.BearerAuth(func(ctx context.Context) (string, error) {
			t, err := ts.Get(ctx)
			if err != nil {
				return "", authx.ClassifyTokenError(err)
			}
			return t, nil
		})
	default:
		return nil, fmt.Errorf("auth_mode %q must be basic, scoped_token or oauth_client", mode)
	}
	site.client = &httpx.Client{HTTP: hc, Logger: d.Logger, Auth: auth}
	return site, nil
}

// fetchToken is the OAuth 2.0 client credentials grant as Atlassian's token
// endpoint takes it: a JSON body with an audience.
func (s *Site) fetchToken(clientID string, cred secret.Secret) func(context.Context) (authx.Token, error) {
	return func(ctx context.Context) (authx.Token, error) {
		sec, err := cred.GetString()
		if err != nil {
			return authx.Token{}, err
		}
		// UNVERIFIED: Atlassian's client credentials grant is documented here
		// as a JSON body with audience api.atlassian.com; the exact shape is
		// not verified against a live token endpoint.
		body := map[string]string{
			"grant_type":    "client_credentials",
			"client_id":     clientID,
			"client_secret": sec,
			"audience":      "api.atlassian.com",
		}
		idem := false
		resp, err := s.plain.Do(ctx, &httpx.Request{Method: http.MethodPost, Path: s.tokenURL, JSON: body, Idempotent: &idem, Accept4xx: true})
		if err != nil {
			return authx.Token{}, err
		}
		var tr struct {
			AccessToken string          `json:"access_token"`
			ExpiresIn   json.RawMessage `json:"expires_in"`
			Error       string          `json:"error"`
		}
		if len(resp.Body) > 0 {
			_ = json.Unmarshal(resp.Body, &tr)
		}
		if resp.Status >= 400 || tr.Error != "" {
			return authx.Token{}, &authx.TokenError{Status: resp.Status, Code: tr.Error}
		}
		if tr.AccessToken == "" {
			return authx.Token{}, errors.New("token endpoint returned no access_token")
		}
		t := authx.Token{Value: tr.AccessToken}
		if secs := expiresIn(tr.ExpiresIn); secs > 0 {
			t.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
		}
		return t, nil
	}
}

func expiresIn(raw json.RawMessage) int64 {
	str := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	n, err := strconv.ParseInt(str, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

var cloudIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)

// CloudID returns the site's cloud id, discovering it on first use from
// GET {url}/_edge/tenant_info.
func (s *Site) CloudID(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cloudID != "" {
		return s.cloudID, nil
	}
	var out struct {
		CloudID string `json:"cloudId"`
	}
	if _, err := s.plain.GetJSON(ctx, s.URL+"/_edge/tenant_info", nil, &out); err != nil {
		return "", httpx.Classify(err)
	}
	if !cloudIDRe.MatchString(out.CloudID) {
		return "", integration.Errorf(integration.CodeUpstreamError, "tenant_info returned no usable cloudId")
	}
	s.cloudID = out.CloudID
	return s.cloudID, nil
}

// Base returns the URL relative paths are resolved against: the site URL for
// basic, or {gateway}/ex/{product}/{cloudId} for the token modes.
func (s *Site) Base(ctx context.Context) (string, error) {
	if s.Mode == ModeBasic {
		return s.URL, nil
	}
	id, err := s.CloudID(ctx)
	if err != nil {
		return "", err
	}
	return s.gateway + "/ex/" + s.Product + "/" + httpx.PathEscape(id), nil
}

// Client is the authenticated HTTP client. Requests through it must use
// absolute paths; Resolve builds them.
func (s *Site) Client() *httpx.Client { return s.client }

// Resolve turns a site-relative path into an absolute URL.
func (s *Site) Resolve(ctx context.Context, path string) (string, error) {
	if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "http://") {
		return path, nil
	}
	base, err := s.Base(ctx)
	if err != nil {
		return "", err
	}
	return base + "/" + strings.TrimLeft(path, "/"), nil
}

// Do performs one request, resolving a relative path against Base.
func (s *Site) Do(ctx context.Context, r *httpx.Request) (*httpx.Response, error) {
	p, err := s.Resolve(ctx, r.Path)
	if err != nil {
		return nil, err
	}
	rr := *r
	rr.Path = p
	return s.client.Do(ctx, &rr)
}

// GetJSON is Do + JSON decode for a GET.
func (s *Site) GetJSON(ctx context.Context, path string, q url.Values, out any) (*httpx.Response, error) {
	p, err := s.Resolve(ctx, path)
	if err != nil {
		return nil, err
	}
	return s.client.GetJSON(ctx, p, q, out)
}

// PostJSON is Do + JSON decode for a POST with a JSON body.
func (s *Site) PostJSON(ctx context.Context, path string, in, out any, idempotent bool) (*httpx.Response, error) {
	p, err := s.Resolve(ctx, path)
	if err != nil {
		return nil, err
	}
	return s.client.PostJSON(ctx, p, in, out, idempotent)
}

// Integration is the jira product.
type Integration struct{}

// Name is "jira".
func (Integration) Name() string { return "jira" }

// Fields of a jira connection.
func (Integration) Fields() []integration.Field { return SiteFields() }

// Actions of the jira integration: the native permission keys.
func (Integration) Actions() []catalog.Action {
	acts := make([]catalog.Action, 0, len(actionList))
	for _, a := range actionList {
		acts = append(acts, catalog.Action{Name: a.name, Description: a.desc})
	}
	return acts
}

// New builds a connection.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	site, err := NewSite(s, d, "jira")
	if err != nil {
		return nil, err
	}
	return &Connection{site: site}, nil
}

// Connection is one Jira Cloud site.
type Connection struct {
	site *Site
}

// Site returns the transport, for integrations on the same site.
func (c *Connection) Site() *Site { return c.site }

type user struct {
	AccountID   string `json:"accountId"`
	AccountType string `json:"accountType"`
	Active      bool   `json:"active"`
	Email       string `json:"emailAddress"`
	Display     string `json:"displayName"`
}

func identityOf(u user) integration.Identity {
	return integration.Identity{ID: u.AccountID, Display: u.Display}
}

// ResolveIdentity maps the caller's email to an Atlassian accountId.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	return c.LookupAccountID(ctx, u.Email)
}

// userSearchPageSize is maxResults for user/search; userSearchMaxPages caps
// how many pages hallpass reads before giving up on a crowded query.
const (
	userSearchPageSize = 50
	userSearchMaxPages = 5
)

// LookupAccountID finds the one active Atlassian account with the email.
// The confluence integration uses it, since Confluence's own user search
// has no email field.
//
// user/search?query= matches displayName as well as emailAddress, so a
// result counts only when its emailAddress equals the request email
// case-insensitively. A display name that looks like the email never does:
// a candidate whose email the profile hides is answered unsupported, not
// accepted, because hallpass cannot tell it from an impostor.
func (c *Connection) LookupAccountID(ctx context.Context, email string) (integration.Identity, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "no email given")
	}
	// UNVERIFIED: whether the query parameter matches an email the profile
	// hides. When it does not, hidden accounts never show up here and the
	// answer is user_not_found rather than the hidden-email branch below.
	var matches, hidden []user
	lastFull := false
	for page := 0; page < userSearchMaxPages; page++ {
		var users []user
		q := url.Values{
			"query":      {email},
			"startAt":    {strconv.Itoa(page * userSearchPageSize)},
			"maxResults": {strconv.Itoa(userSearchPageSize)},
		}
		if _, err := c.site.GetJSON(ctx, "/rest/api/3/user/search", q, &users); err != nil {
			if httpx.Status(err) == 403 {
				return integration.Identity{}, integration.Wrap(integration.CodeCredentialRejected, err,
					"hallpass's account may not search users; it needs Browse users and groups (HTTP 403)")
			}
			return integration.Identity{}, httpx.Classify(err)
		}
		for _, u := range users {
			if u.AccountType != "atlassian" || !u.Active {
				continue
			}
			switch {
			case u.Email == "":
				hidden = append(hidden, u)
			case strings.EqualFold(u.Email, email):
				matches = append(matches, u)
			}
		}
		lastFull = len(users) >= userSearchPageSize
		if !lastFull {
			break
		}
	}
	switch {
	case len(matches) == 1:
		return identityOf(matches[0]), nil
	case len(matches) > 1:
		return integration.Identity{}, integration.UserAmbiguous("%d active Atlassian accounts have the email %s", len(matches), email)
	case lastFull:
		// Every page read was full, so more candidates may follow; a not
		// found here could be a user on a page hallpass did not read.
		return integration.Identity{}, integration.Errorf(integration.CodeUnsupported,
			"too many candidates: the user search for %s filled %d pages without an exact email match", email, userSearchMaxPages)
	case len(hidden) > 0:
		return integration.Identity{}, integration.Errorf(integration.CodeUnsupported,
			"email hidden by profile visibility: %d candidate(s) for %s show no email; make the email visible to the site or use a scoped token that can read it", len(hidden), email)
	default:
		return integration.Identity{}, integration.UserNotFound("no active Atlassian account has the email %s", email)
	}
}

type projectPermission struct {
	Permissions []string `json:"permissions"`
	Projects    []int64  `json:"projects,omitempty"`
	Issues      []int64  `json:"issues,omitempty"`
}

type checkRequest struct {
	AccountID          string              `json:"accountId"`
	ProjectPermissions []projectPermission `json:"projectPermissions,omitempty"`
	GlobalPermissions  []string            `json:"globalPermissions,omitempty"`
}

type checkResponse struct {
	ProjectPermissions []struct {
		Permission string  `json:"permission"`
		Projects   []int64 `json:"projects"`
		Issues     []int64 `json:"issues"`
	} `json:"projectPermissions"`
	GlobalPermissions []string `json:"globalPermissions"`
}

// grants reports whether the response lists the id under the permission
// (granted) and whether the response echoed the permission at all
// (evaluated). Jira echoes every project permission it evaluated, with the
// ids that hold it, so a key missing from the echo was not evaluated and
// must not read as deny. Global permissions have no echo: the response
// lists only the keys the account holds.
func (r checkResponse) grants(perm string, kind resourceKind, id int64) (granted, evaluated bool) {
	if kind == resGlobal {
		for _, g := range r.GlobalPermissions {
			if g == perm {
				return true, true
			}
		}
		return false, true
	}
	for _, pp := range r.ProjectPermissions {
		if pp.Permission != perm {
			continue
		}
		evaluated = true
		ids := pp.Projects
		if kind == resIssue {
			ids = pp.Issues
		}
		for _, x := range ids {
			if x == id {
				return true, true
			}
		}
	}
	return false, evaluated
}

// Check posts one permissions/check for the account and the resource.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	act, ok := actions[r.ActionName]
	if !ok {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "unknown action %q", r.ActionName)
	}
	res, err := parseResource(r.Resource)
	if err != nil {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%v", err)
	}
	switch {
	case act.global && res.kind != resGlobal:
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%s is a global permission; use the resource global", act.name)
	case !act.global && res.kind == resGlobal:
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%s is a project permission; use project:<KEY> or issue:<KEY-N>", act.name)
	}
	body := checkRequest{AccountID: r.Identity.ID}
	var id int64
	switch res.kind {
	case resGlobal:
		body.GlobalPermissions = []string{act.name}
	case resProject:
		id, err = c.projectID(ctx, res.key)
		if err != nil {
			return decisionOrError(err)
		}
		body.ProjectPermissions = []projectPermission{{Permissions: []string{act.name}, Projects: []int64{id}}}
	case resIssue:
		id, err = c.issueID(ctx, res.key)
		if err != nil {
			return decisionOrError(err)
		}
		body.ProjectPermissions = []projectPermission{{Permissions: []string{act.name}, Issues: []int64{id}}}
	}
	var out checkResponse
	if _, err := c.site.PostJSON(ctx, "/rest/api/3/permissions/check", body, &out, true); err != nil {
		switch httpx.Status(err) {
		case 403:
			return integration.Decision{}, integration.Wrap(integration.CodeCredentialRejected, err,
				"hallpass's account may not check other users' permissions; it needs Administer Jira (HTTP 403)")
		case 400:
			// UNVERIFIED: Jira answers 400 for a permission key it does not
			// know. A project permission it silently drops instead is caught
			// below (no echo -> unsupported); a dropped global permission has
			// no echo to check and would read as deny.
			return integration.Unsupported("Jira rejected the permission check for %s; the permission key may not exist on this site", act.name), nil
		}
		return integration.Decision{}, httpx.Classify(err)
	}
	who := r.Identity.Display
	if who == "" {
		who = r.Identity.ID
	}
	granted, evaluated := out.grants(act.name, res.kind, id)
	switch {
	case !evaluated:
		return integration.Unsupported("Jira did not evaluate the permission key %s for %s; the key may not exist on this site", act.name, res.describe()), nil
	case granted:
		return integration.Allowed("%s holds %s on %s", who, act.name, res.describe()), nil
	}
	return integration.Denied("%s does not hold %s on %s", who, act.name, res.describe()), nil
}

// decisionOrError turns a not-visible error into a decision and passes
// everything else through.
func decisionOrError(err error) (integration.Decision, error) {
	var ie *integration.Error
	if errors.As(err, &ie) && ie.Code == integration.CodeResourceNotVisible {
		return ie.Decision(), nil
	}
	return integration.Decision{}, err
}

func parseID(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("upstream returned a non-numeric id")
	}
	return n, nil
}

// projectID looks the project up by key. The bulk permission endpoint
// silently ignores unknown ids, so this lookup is what distinguishes a
// missing project from a denied one.
func (c *Connection) projectID(ctx context.Context, key string) (int64, error) {
	var out struct {
		ID string `json:"id"`
	}
	if _, err := c.site.GetJSON(ctx, "/rest/api/3/project/"+httpx.PathEscape(key), nil, &out); err != nil {
		return 0, c.lookupError(err, "project "+key)
	}
	id, err := parseID(out.ID)
	if err != nil {
		return 0, integration.Wrap(integration.CodeUpstreamError, err, "project %s: %v", key, err)
	}
	return id, nil
}

// issueID looks the issue up by key.
func (c *Connection) issueID(ctx context.Context, key string) (int64, error) {
	var out struct {
		ID string `json:"id"`
	}
	q := url.Values{"fields": {"project"}}
	if _, err := c.site.GetJSON(ctx, "/rest/api/3/issue/"+httpx.PathEscape(key), q, &out); err != nil {
		return 0, c.lookupError(err, "issue "+key)
	}
	id, err := parseID(out.ID)
	if err != nil {
		return 0, integration.Wrap(integration.CodeUpstreamError, err, "issue %s: %v", key, err)
	}
	return id, nil
}

func (c *Connection) lookupError(err error, what string) error {
	switch httpx.Status(err) {
	case 404:
		return integration.Wrap(integration.CodeResourceNotVisible, err, "%s does not exist or is not visible to hallpass's account", what)
	case 403:
		return integration.Wrap(integration.CodeCredentialRejected, err, "hallpass's account may not browse %s (HTTP 403)", what)
	}
	return httpx.Classify(err)
}

// Probe verifies the credential, checks for Administer Jira and validates
// that every action key exists on the site.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var me struct {
		AccountID   string `json:"accountId"`
		DisplayName string `json:"displayName"`
	}
	if _, err := c.site.GetJSON(ctx, "/rest/api/3/myself", nil, &me); err != nil {
		if httpx.Status(err) == 403 {
			return integration.ProbeResult{}, integration.Wrap(integration.CodeCredentialRejected, err, "the credential is valid but may not read its own profile (HTTP 403)")
		}
		return integration.ProbeResult{}, httpx.Classify(err)
	}
	res := integration.ProbeResult{Summary: fmt.Sprintf("authenticated as %s (%s) with auth_mode %s", me.DisplayName, me.AccountID, c.site.Mode)}

	var mine struct {
		Permissions map[string]struct {
			HavePermission bool `json:"havePermission"`
		} `json:"permissions"`
	}
	if _, err := c.site.GetJSON(ctx, "/rest/api/3/mypermissions", url.Values{"permissions": {"ADMINISTER"}}, &mine); err != nil {
		return integration.ProbeResult{}, httpx.Classify(err)
	}
	if !mine.Permissions["ADMINISTER"].HavePermission {
		res.Warnings = append(res.Warnings, "hallpass's account lacks Administer Jira; permissions/check for other users will answer unknown (credential_rejected)")
	}

	var all struct {
		Permissions map[string]json.RawMessage `json:"permissions"`
	}
	if _, err := c.site.GetJSON(ctx, "/rest/api/3/permissions", nil, &all); err != nil {
		return integration.ProbeResult{}, httpx.Classify(err)
	}
	var missing []string
	for _, a := range actionList {
		if _, ok := all.Permissions[a.name]; !ok {
			missing = append(missing, a.name)
		}
	}
	if len(missing) > 0 {
		res.Warnings = append(res.Warnings, "this site does not list the permission keys "+strings.Join(missing, ", ")+"; checks for them will answer unknown or deny")
	}
	return res, nil
}
