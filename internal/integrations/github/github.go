// Package github checks repository, organization and team permissions
// through the GitHub REST and GraphQL APIs.
//
// hallpass authenticates as a GitHub App installed in one organization: it
// signs a short-lived JWT with the App's private key, exchanges it for an
// installation token (cached, refreshed before expiry) and reads with that.
// The App needs only read permissions. The user's email is mapped to a
// GitHub login through the organization's SAML identities, a login template
// or a mapping file, and the effective repository permission (the highest of
// direct, team, organization and enterprise grants, as GitHub computes it)
// is read from the collaborator permission endpoint. Nothing is written.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// Integration is the github product.
type Integration struct{}

// Name is "github".
func (Integration) Name() string { return "github" }

var (
	appIDRe          = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	installationIDRe = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// Fields of a github connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		integration.URLField(false, "GitHub Enterprise Server URL, e.g. https://github.example.com; omit for github.com"),
		{Name: "organization", Required: true, Validate: validateLogin,
			Description: "the organization the App is installed in; every resource must belong to it"},
		{Name: "app_id", Required: true, Validate: validateAppID,
			Description: "the App's client id (preferred) or numeric App id, used as the JWT issuer"},
		{Name: "installation_id", Validate: validateInstallationID,
			Description: "the App's installation id in the organization; discovered when omitted"},
		integration.CredentialField(true, "the App's private key, PEM (PKCS#1 or PKCS#8)"),
		{Name: "identity_mode", Default: modeSAML, Enum: []string{modeSAML, modeTemplate, modeMapFile},
			Description: "how an email becomes a login: saml (organization SAML identities), template (login_template) or map_file (user_map_file)"},
		{Name: "login_template", Default: "{local}", Validate: validateTemplate,
			Description: "template mode: placeholders {email}, {local}, {domain}, e.g. {local}-acme"},
		{Name: "user_map_file", Description: "map_file mode: path to a file of \"email login\" or \"email=login\" lines, # comments; re-read every 60 s"},
	}
}

func validateLogin(v string) error {
	if !validLogin(v) {
		return fmt.Errorf("%q is not a GitHub login", v)
	}
	return nil
}

func validateAppID(v string) error {
	if !appIDRe.MatchString(v) {
		return fmt.Errorf("%q is not an App client id or App id", v)
	}
	return nil
}

func validateInstallationID(v string) error {
	if !installationIDRe.MatchString(v) {
		return fmt.Errorf("%q is not a numeric installation id", v)
	}
	return nil
}

// Actions of the github integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList))
	for _, a := range actionList {
		out = append(out, catalog.Action{Name: a.name, Description: a.desc})
	}
	return out
}

const (
	apiVersion     = "2022-11-28"
	acceptJSON     = "application/vnd.github+json"
	publicREST     = "https://api.github.com"
	publicGraphQL  = "https://api.github.com/graphql"
	jwtBackdate    = 60 * time.Second
	jwtLifetime    = 9 * time.Minute
	tokenLifetime  = time.Hour
	mintIdempotent = true
)

// New builds a connection. It touches no network; the private key is read
// and parsed when a JWT is needed, so a rotated key file takes effect.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	if s.Secret("credential").IsZero() {
		return nil, errors.New("credential is required")
	}
	if s.Get("organization") == "" {
		return nil, errors.New("organization is required")
	}
	if s.Get("app_id") == "" {
		return nil, errors.New("app_id is required")
	}
	c := &Connection{
		settings:       s,
		org:            s.Get("organization"),
		appID:          s.Get("app_id"),
		installationID: s.Get("installation_id"),
		mode:           s.Get("identity_mode"),
		template:       s.Get("login_template"),
		mapFile:        s.Get("user_map_file"),
		logger:         d.Logger,
		now:            d.Now,
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.mode == "" {
		c.mode = modeSAML
	}
	if c.template == "" {
		c.template = "{local}"
	}
	switch c.mode {
	case modeSAML:
	case modeTemplate:
		if err := validateTemplate(c.template); err != nil {
			return nil, fmt.Errorf("login_template: %w", err)
		}
	case modeMapFile:
		if c.mapFile == "" {
			return nil, errors.New("identity_mode map_file requires user_map_file")
		}
		if fi, err := os.Stat(c.mapFile); err != nil {
			return nil, fmt.Errorf("user_map_file: %w", err)
		} else if fi.IsDir() {
			return nil, fmt.Errorf("user_map_file %s is a directory", c.mapFile)
		}
	default:
		return nil, fmt.Errorf("identity_mode %q must be one of saml, template, map_file", c.mode)
	}
	restBase, graphqlURL := publicREST, publicGraphQL
	if u := strings.TrimRight(s.Get("url"), "/"); u != "" {
		restBase, graphqlURL = u+"/api/v3", u+"/api/graphql"
	}
	c.graphqlURL = graphqlURL
	c.app = &httpx.Client{HTTP: hc, Base: restBase, Logger: d.Logger, Auth: c.jwtAuth}
	c.rest = &httpx.Client{HTTP: hc, Base: restBase, Logger: d.Logger, Auth: c.tokenAuth}
	c.tokens = &authx.TokenSource{Fetch: c.mintToken, DefaultTTL: tokenLifetime, Now: c.now}
	return c, nil
}

// Connection is one organization on one GitHub.
type Connection struct {
	settings       *integration.Settings
	org            string
	appID          string
	installationID string
	mode           string
	template       string
	mapFile        string
	graphqlURL     string
	logger         *slog.Logger
	now            func() time.Time

	// app authenticates as the App (JWT); rest as the installation (token).
	app    *httpx.Client
	rest   *httpx.Client
	tokens *authx.TokenSource

	instMu         sync.Mutex
	discoveredInst string

	samlMu      sync.Mutex
	samlEntries map[string]samlEntry
	samlLoaded  time.Time
	samlLoading chan struct{}

	mapMu      sync.Mutex
	mapEntries map[string]string
	mapRead    time.Time
}

// --- authentication ---------------------------------------------------------

// appJWT signs a fresh App JWT. GitHub allows at most 10 minutes of
// lifetime and rejects clocks ahead of its own, hence the backdated iat.
func (c *Connection) appJWT() (string, error) {
	pemText, err := c.settings.Secret("credential").GetString()
	if err != nil {
		return "", integration.Wrap(integration.CodeCredentialRejected, err, "the App private key could not be read")
	}
	key, err := authx.ParseRSAPrivateKey([]byte(pemText))
	if err != nil {
		return "", integration.Wrap(integration.CodeCredentialRejected, err, "the App private key is not a PEM RSA key")
	}
	now := c.now()
	claims := authx.StandardClaims{
		Iss: c.appID,
		Iat: authx.Unix(now.Add(-jwtBackdate)),
		Exp: authx.Unix(now.Add(jwtLifetime)),
	}
	return authx.SignJWT(key, authx.Header{Alg: authx.RS256}, claims)
}

func setGitHubHeaders(r *http.Request) {
	r.Header.Set("Accept", acceptJSON)
	r.Header.Set("X-GitHub-Api-Version", apiVersion)
}

func (c *Connection) jwtAuth(_ context.Context, r *http.Request) error {
	jwt, err := c.appJWT()
	if err != nil {
		return err
	}
	setGitHubHeaders(r)
	r.Header.Set("Authorization", "Bearer "+jwt)
	return nil
}

func (c *Connection) tokenAuth(ctx context.Context, r *http.Request) error {
	tok, err := c.tokens.Get(ctx)
	if err != nil {
		return err
	}
	setGitHubHeaders(r)
	r.Header.Set("Authorization", "Bearer "+tok)
	return nil
}

type installationRecord struct {
	ID          json.Number       `json:"id"`
	Permissions map[string]string `json:"permissions"`
	Account     struct {
		Login string `json:"login"`
	} `json:"account"`
}

// installation reads the App's installation in the organization with the JWT.
func (c *Connection) installation(ctx context.Context) (installationRecord, error) {
	var inst installationRecord
	_, err := c.app.GetJSON(ctx, "/orgs/"+httpx.PathEscape(c.org)+"/installation", nil, &inst)
	if err != nil {
		if httpx.Status(err) == http.StatusNotFound {
			return inst, integration.Wrap(integration.CodeCredentialRejected, err, "the App is not installed in organization %s (or app_id is wrong)", c.org)
		}
		return inst, c.classify(err, "read its installation in "+c.org)
	}
	return inst, nil
}

// installationIDFor returns the configured or discovered installation id.
func (c *Connection) installationIDFor(ctx context.Context) (string, error) {
	if c.installationID != "" {
		return c.installationID, nil
	}
	c.instMu.Lock()
	id := c.discoveredInst
	c.instMu.Unlock()
	if id != "" {
		return id, nil
	}
	inst, err := c.installation(ctx)
	if err != nil {
		return "", err
	}
	id = inst.ID.String()
	if !installationIDRe.MatchString(id) {
		return "", integration.Errorf(integration.CodeUpstreamError, "the installation record for %s carries no id", c.org)
	}
	c.instMu.Lock()
	c.discoveredInst = id
	c.instMu.Unlock()
	return id, nil
}

// mintToken exchanges the App JWT for an installation token.
func (c *Connection) mintToken(ctx context.Context) (authx.Token, error) {
	id, err := c.installationIDFor(ctx)
	if err != nil {
		return authx.Token{}, err
	}
	var out struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	_, err = c.app.PostJSON(ctx, "/app/installations/"+httpx.PathEscape(id)+"/access_tokens", map[string]any{}, &out, mintIdempotent)
	if err != nil {
		if httpx.Status(err) == http.StatusNotFound {
			return authx.Token{}, integration.Wrap(integration.CodeCredentialRejected, err, "installation %s was not found for this App", id)
		}
		return authx.Token{}, c.classify(err, "create an installation token")
	}
	if out.Token == "" {
		return authx.Token{}, integration.Errorf(integration.CodeUpstreamError, "the installation token response carried no token")
	}
	tok := authx.Token{Value: out.Token}
	if t, err := time.Parse(time.RFC3339, out.ExpiresAt); err == nil {
		tok.Expiry = t
	}
	return tok, nil
}

// --- transport helpers ------------------------------------------------------

// get performs one REST GET with the installation token. On a 401 the token
// is dropped and the call is retried once with a fresh one.
func (c *Connection) get(ctx context.Context, path string, out any) (*httpx.Response, error) {
	resp, err := c.rest.GetJSON(ctx, path, nil, out)
	if unauthorized(resp, err) {
		c.tokens.Invalidate()
		resp, err = c.rest.GetJSON(ctx, path, nil, out)
	}
	return resp, err
}

// unauthorized reports a 401 answered by the API itself, as opposed to a
// failure inside the token exchange (which has no response).
func unauthorized(resp *httpx.Response, err error) bool {
	return err != nil && resp != nil && resp.Status == http.StatusUnauthorized
}

// apiStatus is the HTTP status of a failed API call, or 0 when the failure
// was already classified (for example a 404 from the token exchange, which
// must not read as "user not found").
func apiStatus(err error) int {
	var ie *integration.Error
	if errors.As(err, &ie) {
		return 0
	}
	return httpx.Status(err)
}

// classify maps a failed call to an integration error. 401 and 403 mean
// the App's credential or permissions are insufficient, except a 403 that
// GitHub uses for an exhausted rate limit.
func (c *Connection) classify(err error, what string) *integration.Error {
	var ie *integration.Error
	if errors.As(err, &ie) {
		return ie
	}
	switch httpx.Status(err) {
	case http.StatusForbidden:
		var se *httpx.StatusError
		if errors.As(err, &se) && se.Header != nil {
			if strings.TrimSpace(se.Header.Get("X-RateLimit-Remaining")) == "0" || se.Header.Get("Retry-After") != "" {
				return integration.Wrap(integration.CodeUpstreamRateLimit, err, "GitHub rate limit exhausted for the App installation")
			}
		}
		return integration.Wrap(integration.CodeCredentialRejected, err, "the App may not %s (HTTP 403); check its permissions", what)
	case http.StatusUnauthorized:
		return integration.Wrap(integration.CodeCredentialRejected, err, "the App's credential was rejected (HTTP 401)")
	}
	return httpx.Classify(err)
}

type graphqlError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// graphql runs one query with the installation token and decodes data into
// out. GraphQL reports most failures as HTTP 200 with an errors array.
func (c *Connection) graphql(ctx context.Context, query string, vars map[string]any, out any) error {
	body := map[string]any{"query": query, "variables": vars}
	idem := true
	do := func() (*httpx.Response, error) {
		return c.rest.Do(ctx, &httpx.Request{Method: http.MethodPost, Path: c.graphqlURL, JSON: body, Idempotent: &idem})
	}
	resp, err := do()
	if unauthorized(resp, err) {
		c.tokens.Invalidate()
		resp, err = do()
	}
	if err != nil {
		return c.classify(err, "query GraphQL")
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []graphqlError  `json:"errors"`
	}
	if err := resp.JSON(&env); err != nil {
		return integration.Wrap(integration.CodeUpstreamError, err, "GraphQL response was not JSON")
	}
	for _, e := range env.Errors {
		switch strings.ToUpper(e.Type) {
		case "INSUFFICIENT_SCOPES", "FORBIDDEN":
			return integration.Errorf(integration.CodeCredentialRejected, "the App may not read organization SAML identities (GraphQL %s); it needs Organization members: read", e.Type)
		case "RATE_LIMITED":
			return integration.Errorf(integration.CodeUpstreamRateLimit, "GraphQL rate limit exhausted")
		}
	}
	if len(env.Errors) > 0 {
		t := env.Errors[0].Type
		if t == "" {
			t = "error"
		}
		return integration.Errorf(integration.CodeUpstreamError, "GraphQL query failed (%s)", t)
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return integration.Errorf(integration.CodeUpstreamError, "GraphQL response carried no data")
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return integration.Wrap(integration.CodeUpstreamError, err, "GraphQL data could not be decoded")
	}
	return nil
}

// --- check ------------------------------------------------------------------

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	a, ok := actions[r.ActionName]
	if !ok {
		return integration.Decision{}, integration.Errorf(integration.CodeUnknownAction, "unknown action %q", r.ActionName)
	}
	t, err := parseTarget(a, c.org, r.Resource)
	if err != nil {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%v", err)
	}
	login := r.Identity.ID
	if !validLogin(login) {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "identity %q is not a GitHub login", login)
	}
	switch t.kind {
	case "repo":
		return c.checkRepo(ctx, a, t, login)
	case "org":
		return c.checkOrg(ctx, a, t, login)
	default:
		return c.checkTeam(ctx, a, t, login)
	}
}

type permissionRecord struct {
	Permission string `json:"permission"`
	RoleName   string `json:"role_name"`
	User       *struct {
		Login       string       `json:"login"`
		Permissions *permissions `json:"permissions"`
	} `json:"user"`
}

func (c *Connection) checkRepo(ctx context.Context, a action, t target, login string) (integration.Decision, error) {
	repoPath := "/repos/" + httpx.PathEscape(t.owner) + "/" + httpx.PathEscape(t.repo)
	var rec permissionRecord
	if _, err := c.get(ctx, repoPath+"/collaborators/"+httpx.PathEscape(login)+"/permission", &rec); err != nil {
		if apiStatus(err) == http.StatusNotFound {
			return integration.UnknownDecision(integration.CodeResourceNotVisible,
				"repository %s/%s is not visible to the App, or %s is not a collaborator on a private repository", t.owner, t.repo, login), nil
		}
		return integration.Decision{}, c.classify(err, "read collaborator permissions on "+t.owner+"/"+t.repo)
	}
	var perms permissions
	switch {
	case rec.User != nil && rec.User.Permissions != nil:
		perms = *rec.User.Permissions
	case rec.Permission != "":
		perms = fromString(rec.Permission)
	default:
		return integration.Unsupported("GitHub reported no permissions for %s on %s/%s", login, t.owner, t.repo), nil
	}
	role := rec.RoleName
	if role == "" {
		role = rec.Permission
	}
	if role == "" {
		role = "none"
	}
	repo := t.owner + "/" + t.repo
	if !perms.has(a.level) {
		return integration.Denied("%s has %s on %s, which does not include %s", login, role, repo, a.level), nil
	}
	text := fmt.Sprintf("%s has %s on %s, which includes %s", login, role, repo, a.level)

	switch a.name {
	case "issue.create":
		var meta struct {
			HasIssues *bool `json:"has_issues"`
		}
		if _, err := c.get(ctx, repoPath, &meta); err != nil {
			if apiStatus(err) == http.StatusNotFound {
				return integration.UnknownDecision(integration.CodeResourceNotVisible, "repository %s is not visible to the App", repo), nil
			}
			return integration.Decision{}, c.classify(err, "read repository "+repo)
		}
		if meta.HasIssues == nil {
			return integration.Unsupported("%s; GitHub did not report whether issues are enabled on %s", text, repo), nil
		}
		if !*meta.HasIssues {
			return integration.Denied("issues are disabled on %s", repo), nil
		}
		text += "; issues are enabled"
	case "pr.create":
		if !perms.Push {
			text += " (via fork; pushing a branch to the repository itself needs push)"
		}
	case "repo.push", "pr.merge":
		if t.branch != "" {
			return c.annotateBranch(ctx, a, t, repoPath, text)
		}
	}
	return integration.Allowed("%s", text), nil
}

type branchRule struct {
	Type string `json:"type"`
}

// annotateBranch reads the rules that apply to the branch and adds them to
// an allow. A pull_request rule turns an allowed direct push into unknown.
func (c *Connection) annotateBranch(ctx context.Context, a action, t target, repoPath, text string) (integration.Decision, error) {
	var rules []branchRule
	_, err := c.get(ctx, repoPath+"/rules/branches/"+httpx.PathEscape(t.branch), &rules)
	if err != nil {
		switch apiStatus(err) {
		case http.StatusNotFound, http.StatusForbidden:
			// UNVERIFIED: which of 403/404 GitHub returns when the App
			// lacks the permission to read rulesets; both are ignored.
			return integration.Allowed("%s; the rules for branch %s could not be read", text, t.branch), nil
		}
		return integration.Decision{}, c.classify(err, "read branch rules of "+t.owner+"/"+t.repo)
	}
	if len(rules) == 0 {
		return integration.Allowed("%s; branch %s has no rules", text, t.branch), nil
	}
	seen := map[string]bool{}
	var types []string
	for _, r := range rules {
		if r.Type != "" && !seen[r.Type] {
			seen[r.Type] = true
			types = append(types, r.Type)
		}
	}
	sort.Strings(types)
	if seen["pull_request"] && a.name == "repo.push" {
		// UNVERIFIED: bypass actors of the ruleset may still push directly;
		// hallpass does not evaluate bypass lists.
		return integration.Unsupported("%s, but branch %s requires pull requests; direct push not allowed by rules", text, t.branch), nil
	}
	return integration.Allowed("%s; branch %s has %d rules (types %s): a direct push may still be rejected",
		text, t.branch, len(rules), strings.Join(types, ", ")), nil
}

type membershipRecord struct {
	State string `json:"state"`
	Role  string `json:"role"`
}

func (c *Connection) orgMembership(ctx context.Context, t target, login string) (membershipRecord, bool, error) {
	var m membershipRecord
	_, err := c.get(ctx, "/orgs/"+httpx.PathEscape(t.owner)+"/memberships/"+httpx.PathEscape(login), &m)
	if err != nil {
		if apiStatus(err) == http.StatusNotFound {
			return m, false, nil
		}
		return m, false, c.classify(err, "read organization memberships of "+t.owner)
	}
	return m, true, nil
}

func (c *Connection) checkOrg(ctx context.Context, a action, t target, login string) (integration.Decision, error) {
	m, member, err := c.orgMembership(ctx, t, login)
	if err != nil {
		return integration.Decision{}, err
	}
	if !member {
		return integration.Denied("%s is not a member of organization %s", login, t.owner), nil
	}
	if m.State != "active" {
		return integration.Denied("%s's membership in organization %s is %s, not active", login, t.owner, orEmpty(m.State, "unknown")), nil
	}
	switch a.name {
	case "org.member":
		return integration.Allowed("%s is an active %s of organization %s", login, orEmpty(m.Role, "member"), t.owner), nil
	case "org.admin":
		if m.Role == "admin" {
			return integration.Allowed("%s is an owner of organization %s", login, t.owner), nil
		}
		return integration.Denied("%s is a %s of organization %s, not an owner", login, orEmpty(m.Role, "member"), t.owner), nil
	default: // org.repo.create
		if m.Role == "admin" {
			return integration.Allowed("%s is an owner of organization %s and may create repositories", login, t.owner), nil
		}
		var org struct {
			// UNVERIFIED: whether an installation token sees these
			// fields; absent means unknown.
			MembersCanCreate         *bool `json:"members_can_create_repositories"`
			MembersCanCreatePublic   *bool `json:"members_can_create_public_repositories"`
			MembersCanCreatePrivate  *bool `json:"members_can_create_private_repositories"`
			MembersCanCreateInternal *bool `json:"members_can_create_internal_repositories"`
		}
		if _, err := c.get(ctx, "/orgs/"+httpx.PathEscape(t.owner), &org); err != nil {
			return integration.Decision{}, c.classify(err, "read organization "+t.owner)
		}
		if org.MembersCanCreate == nil {
			return integration.Unsupported("GitHub did not report whether members of %s may create repositories; the App may need Organization administration: read", t.owner), nil
		}
		if !*org.MembersCanCreate {
			return integration.Denied("%s is a member of organization %s, whose members may not create repositories", login, t.owner), nil
		}
		var kinds []string
		for _, k := range []struct {
			name string
			v    *bool
		}{{"public", org.MembersCanCreatePublic}, {"private", org.MembersCanCreatePrivate}, {"internal", org.MembersCanCreateInternal}} {
			if k.v != nil && *k.v {
				kinds = append(kinds, k.name)
			}
		}
		text := fmt.Sprintf("%s is a member of organization %s, whose members may create repositories", login, t.owner)
		if len(kinds) > 0 {
			text += " (" + strings.Join(kinds, ", ") + ")"
		}
		return integration.Allowed("%s", text), nil
	}
}

func (c *Connection) checkTeam(ctx context.Context, a action, t target, login string) (integration.Decision, error) {
	teamPath := "/orgs/" + httpx.PathEscape(t.owner) + "/teams/" + httpx.PathEscape(t.team)
	var m membershipRecord
	_, err := c.get(ctx, teamPath+"/memberships/"+httpx.PathEscape(login), &m)
	if err != nil {
		if apiStatus(err) != http.StatusNotFound {
			return integration.Decision{}, c.classify(err, "read memberships of team "+t.String())
		}
		// 404 is both "not a member" and "no such team"; tell them apart
		// so a typo in the slug is not reported as a deny.
		if _, err := c.get(ctx, teamPath, nil); err != nil {
			if apiStatus(err) == http.StatusNotFound {
				return integration.UnknownDecision(integration.CodeResourceNotVisible, "team %s does not exist or is not visible to the App", t.String()), nil
			}
			return integration.Decision{}, c.classify(err, "read team "+t.String())
		}
		return integration.Denied("%s is not a member of team %s", login, t.String()), nil
	}
	if m.State != "active" {
		return integration.Denied("%s's membership in team %s is %s, not active", login, t.String(), orEmpty(m.State, "unknown")), nil
	}
	if a.name == "team.maintainer" {
		if m.Role == "maintainer" {
			return integration.Allowed("%s is a maintainer of team %s", login, t.String()), nil
		}
		return integration.Denied("%s is a %s of team %s, not a maintainer", login, orEmpty(m.Role, "member"), t.String()), nil
	}
	return integration.Allowed("%s is an active %s of team %s", login, orEmpty(m.Role, "member"), t.String()), nil
}

func orEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// --- probe ------------------------------------------------------------------

// Probe reads the App and its installation with the JWT, then checks the
// installation's permissions: metadata and members must be readable, and
// anything writable is reported as over-privileged.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	var app struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	if _, err := c.app.GetJSON(ctx, "/app", nil, &app); err != nil {
		return integration.ProbeResult{}, c.classify(err, "read the App (GET /app)")
	}
	inst, err := c.installation(ctx)
	if err != nil {
		return integration.ProbeResult{}, err
	}
	name := app.Slug
	if name == "" {
		name = orEmpty(app.Name, c.appID)
	}
	res := integration.ProbeResult{Summary: fmt.Sprintf("app %s installed in %s", name, c.org)}
	if c.installationID != "" && inst.ID.String() != c.installationID {
		res.Warnings = append(res.Warnings, fmt.Sprintf("installation_id %s does not match the installation GitHub reports for %s (%s)", c.installationID, c.org, inst.ID.String()))
	}
	if inst.Permissions["metadata"] == "" {
		res.Warnings = append(res.Warnings, "the installation lacks Repository metadata: read; repository permission checks will fail")
	}
	if inst.Permissions["members"] == "" {
		res.Warnings = append(res.Warnings, "the installation lacks Organization members: read; organization, team and SAML identity lookups will fail")
	}
	keys := make([]string, 0, len(inst.Permissions))
	for k := range inst.Permissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch v := inst.Permissions[k]; v {
		case "write", "admin":
			res.Warnings = append(res.Warnings, fmt.Sprintf("over-privileged: the installation has %s: %s; hallpass only reads", k, v))
		}
	}
	if c.mode == modeSAML {
		var data samlData
		err := c.graphql(ctx, `query($org:String!){ organization(login:$org){ samlIdentityProvider { externalIdentities(first:1){ nodes { user { login } } } } } }`, map[string]any{"org": c.org}, &data)
		switch {
		case err != nil:
			res.Warnings = append(res.Warnings, "SAML identity lookup failed: "+strconv.Quote(errText(err)))
		case data.Organization == nil || data.Organization.SAMLIdentityProvider == nil:
			res.Warnings = append(res.Warnings, "organization "+c.org+" has no SAML identity provider; identity_mode saml will not resolve anyone (use template or map_file)")
		}
	}
	return res, nil
}

// errText is the code and text of an integration error, never its cause.
func errText(err error) string {
	var ie *integration.Error
	if errors.As(err, &ie) {
		return string(ie.Code) + ": " + ie.Text
	}
	return "upstream call failed"
}
