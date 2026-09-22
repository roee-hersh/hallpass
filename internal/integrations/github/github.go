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
		{Name: "email_domains", Validate: validateEmailDomains,
			Description: "template mode (required): comma-separated email domains the template applies to; other domains are unknown"},
		{Name: "user_map_file", Description: "map_file mode: path to a file of \"email login\" or \"email=login\" lines, # comments; re-read every 60 s"},
	}
}

// emailDomainRe is one entry of email_domains.
var emailDomainRe = regexp.MustCompile(`^[a-z0-9.-]+$`)

// parseEmailDomains splits the comma-separated email_domains value and
// validates each entry.
func parseEmailDomains(v string) ([]string, error) {
	var out []string
	for _, d := range strings.Split(v, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if !emailDomainRe.MatchString(d) {
			return nil, fmt.Errorf("%q is not a lowercase domain name", d)
		}
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, errors.New("must list at least one domain")
	}
	return out, nil
}

func validateEmailDomains(v string) error {
	_, err := parseEmailDomains(v)
	return err
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
		if s.Get("email_domains") == "" {
			return nil, errors.New("identity_mode template requires email_domains: the template would otherwise map any domain's local part to a login")
		}
		domains, err := parseEmailDomains(s.Get("email_domains"))
		if err != nil {
			return nil, fmt.Errorf("email_domains: %w", err)
		}
		c.emailDomains = map[string]bool{}
		for _, d := range domains {
			c.emailDomains[d] = true
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
	emailDomains   map[string]bool // template mode: lowercase domains the template applies to
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
	samlIndex   *samlIndex
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

// builtinRole reports whether a role_name is one of GitHub's five base
// roles (or "none"). Anything else is a custom repository role, whose extra
// abilities the five permission booleans do not describe.
func builtinRole(name string) bool {
	switch name {
	case "", "none", "read", "pull", "triage", "write", "push", "maintain", "admin":
		return true
	}
	return false
}

// repoMeta is the part of GET /repos/{owner}/{repo} the checks read.
type repoMeta struct {
	HasIssues    *bool  `json:"has_issues"`
	AllowForking *bool  `json:"allow_forking"`
	Visibility   string `json:"visibility"`
}

func (c *Connection) repoMeta(ctx context.Context, repoPath, repo string) (repoMeta, error) {
	var meta repoMeta
	if _, err := c.get(ctx, repoPath, &meta); err != nil {
		if apiStatus(err) == http.StatusNotFound {
			return meta, integration.Errorf(integration.CodeResourceNotVisible, "repository %s is not visible to the App", repo)
		}
		return meta, c.classify(err, "read repository "+repo)
	}
	return meta, nil
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
	repo := t.owner + "/" + t.repo
	var perms permissions
	switch {
	case rec.User != nil && rec.User.Permissions != nil:
		perms = *rec.User.Permissions
	case rec.Permission != "":
		if !builtinRole(rec.Permission) {
			return integration.Unsupported("GitHub reported permission %q for %s on %s, which hallpass does not model", rec.Permission, login, repo), nil
		}
		perms = fromString(rec.Permission)
	default:
		return integration.Unsupported("GitHub reported no permissions for %s on %s", login, repo), nil
	}
	role := rec.RoleName
	if role == "" {
		role = rec.Permission
	}
	if role == "" {
		role = "none"
	}
	if !perms.has(a.level) {
		if !builtinRole(rec.RoleName) {
			return integration.Unsupported("%s has custom repository role %s on %s; extra abilities not modeled, so %s cannot be evaluated", login, role, repo, a.level), nil
		}
		return integration.Denied("%s has %s on %s, which does not include %s", login, role, repo, a.level), nil
	}
	text := fmt.Sprintf("%s has %s on %s, which includes %s", login, role, repo, a.level)

	switch a.name {
	case "issue.create":
		meta, err := c.repoMeta(ctx, repoPath, repo)
		if err != nil {
			return integration.Decision{}, err
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
			// Without push the branch must come from a fork, so forking
			// must be possible on this repository.
			meta, err := c.repoMeta(ctx, repoPath, repo)
			if err != nil {
				return integration.Decision{}, err
			}
			if meta.AllowForking == nil {
				return integration.Unsupported("%s but not push; GitHub did not report whether %s may be forked", text, repo), nil
			}
			if !*meta.AllowForking {
				return integration.Denied("forking disabled on %s; pull request needs push access, and %s has only %s", repo, login, role), nil
			}
			// UNVERIFIED: allow_forking on a private or internal repository
			// is assumed to reflect the organization's "members can fork"
			// policy; the visibility is quoted so a reader can tell.
			text += " (via fork; pushing a branch to the repository itself needs push"
			if meta.Visibility != "" {
				text += "; the repository is " + meta.Visibility
			}
			text += ")"
		}
	case "repo.push", "pr.merge":
		if t.branch != "" {
			return c.annotateBranch(ctx, a, t, repoPath, login, perms, text)
		}
	}
	return integration.Allowed("%s", text), nil
}

// --- branch rules and protection --------------------------------------------

type branchRule struct {
	Type string `json:"type"`
}

// branchProtection is the part of the classic branch protection record
// (GET /repos/{owner}/{repo}/branches/{branch}/protection) that hallpass
// evaluates. Every object is optional: absent means the setting is off.
// UNVERIFIED: the field shapes follow GitHub's OpenAPI description
// (restrictions.users[].login, restrictions.teams[].slug,
// required_pull_request_reviews present, enforce_admins.enabled); no live
// response was captured.
type branchProtection struct {
	EnforceAdmins *struct {
		Enabled bool `json:"enabled"`
	} `json:"enforce_admins"`
	RequiredPullRequestReviews *struct {
		RequiredApprovingReviewCount int `json:"required_approving_review_count"`
	} `json:"required_pull_request_reviews"`
	Restrictions *struct {
		Users []struct {
			Login string `json:"login"`
		} `json:"users"`
		Teams []struct {
			Slug string `json:"slug"`
		} `json:"teams"`
		Apps []struct {
			Slug string `json:"slug"`
		} `json:"apps"`
	} `json:"restrictions"`
}

// pushBlockingRules are the ruleset rule types under which a direct push to
// an existing branch is only possible for bypass actors, with what each
// means. creation and deletion do not affect a push to an existing branch.
var pushBlockingRules = []struct{ typ, means string }{
	{"pull_request", "requires pull requests"},
	{"update", "restricts updates to bypass actors"},
	{"merge_queue", "requires the merge queue"},
}

// forbidden maps a 403 on a read that needs an extra App permission: a
// rate-limit 403 keeps its meaning, anything else is unknown (unsupported)
// with a hint at the permission to grant.
func (c *Connection) forbidden(err error, text string) error {
	if ie := c.classify(err, ""); ie.Code == integration.CodeUpstreamRateLimit {
		return ie
	}
	return integration.Wrap(integration.CodeUnsupported, err, "%s", text)
}

// branchRules reads the ruleset rules that apply to the branch. The endpoint
// answers 200 with an empty list when no rule applies, so a 404 means the
// repository or branch is not visible.
func (c *Connection) branchRules(ctx context.Context, t target, repoPath string) ([]branchRule, error) {
	var rules []branchRule
	_, err := c.get(ctx, repoPath+"/rules/branches/"+httpx.PathEscape(t.branch), &rules)
	if err != nil {
		switch apiStatus(err) {
		case http.StatusForbidden:
			return nil, c.forbidden(err, fmt.Sprintf("branch rules of %s not readable; grant the App Repository Administration: read", t.String()))
		case http.StatusNotFound:
			return nil, integration.Errorf(integration.CodeResourceNotVisible, "branch %s does not exist or is not visible to the App", t.String())
		}
		return nil, c.classify(err, "read branch rules of "+t.owner+"/"+t.repo)
	}
	return rules, nil
}

// branchProtection reads the classic protection of the branch; nil when the
// branch has none (GitHub answers 404 "Branch not protected").
func (c *Connection) branchProtection(ctx context.Context, t target, repoPath string) (*branchProtection, error) {
	var prot branchProtection
	_, err := c.get(ctx, repoPath+"/branches/"+httpx.PathEscape(t.branch)+"/protection", &prot)
	if err != nil {
		switch apiStatus(err) {
		case http.StatusNotFound:
			return nil, nil
		case http.StatusForbidden:
			return nil, c.forbidden(err, fmt.Sprintf("branch protection of %s not readable; grant the App Repository Administration: read", t.String()))
		}
		return nil, c.classify(err, "read branch protection of "+t.owner+"/"+t.repo)
	}
	return &prot, nil
}

// inRestrictions reports whether the login may push under the branch's push
// restrictions: listed directly, or an active member of a listed team.
// Apps are not people and are skipped.
func (c *Connection) inRestrictions(ctx context.Context, t target, prot *branchProtection, login string) (bool, error) {
	for _, u := range prot.Restrictions.Users {
		if strings.EqualFold(u.Login, login) {
			return true, nil
		}
	}
	for _, team := range prot.Restrictions.Teams {
		if !slugRe.MatchString(team.Slug) || len(team.Slug) > 255 {
			return false, integration.Errorf(integration.CodeUnsupported, "branch %s restricts pushes to a team whose slug hallpass cannot look up", t.String())
		}
		var m membershipRecord
		_, err := c.get(ctx, "/orgs/"+httpx.PathEscape(t.owner)+"/teams/"+httpx.PathEscape(team.Slug)+"/memberships/"+httpx.PathEscape(login), &m)
		if err != nil {
			switch apiStatus(err) {
			case http.StatusNotFound:
				continue
			case http.StatusForbidden:
				return false, c.forbidden(err, fmt.Sprintf("branch %s restricts pushes to team %s, whose members the App may not read", t.String(), team.Slug))
			}
			return false, c.classify(err, "read memberships of team "+t.owner+"/"+team.Slug)
		}
		switch m.State {
		case "active":
			return true, nil
		case "":
			return false, integration.Errorf(integration.CodeUnsupported, "GitHub reported no membership state for %s in team %s/%s", login, t.owner, team.Slug)
		}
	}
	return false, nil
}

// annotateBranch evaluates the branch's ruleset rules and classic protection
// on top of an allowed push or merge. A push restriction that excludes the
// login is a deny; a rule that routes changes through pull requests turns an
// allowed direct push into unknown.
func (c *Connection) annotateBranch(ctx context.Context, a action, t target, repoPath, login string, perms permissions, text string) (integration.Decision, error) {
	rules, err := c.branchRules(ctx, t, repoPath)
	if err != nil {
		return integration.Decision{}, err
	}
	prot, err := c.branchProtection(ctx, t, repoPath)
	if err != nil {
		return integration.Decision{}, err
	}
	branch := t.branch

	// Classic protection. UNVERIFIED: the restrictions of a classic rule are
	// assumed not to apply to repository admins unless enforce_admins is
	// enabled ("Do not allow bypassing the above settings"); when GitHub
	// does not report enforce_admins for an admin the answer is unknown.
	adminBypass := false
	if prot != nil && perms.Admin {
		if prot.EnforceAdmins == nil {
			return integration.Unsupported("%s, but branch %s is protected and GitHub did not report whether admins are exempt", text, branch), nil
		}
		adminBypass = !prot.EnforceAdmins.Enabled
	}
	if prot != nil && prot.Restrictions != nil && !adminBypass {
		listed, err := c.inRestrictions(ctx, t, prot, login)
		if err != nil {
			return integration.Decision{}, err
		}
		if !listed {
			if a.name == "repo.push" {
				return integration.Denied("branch %s restricts pushes to listed users, teams and apps, and %s is not among them", branch, login), nil
			}
			// UNVERIFIED: whether a push restriction also blocks merging a
			// pull request into the branch; treated as unknown.
			return integration.Unsupported("%s, but branch %s restricts pushes and %s is not among the listed users and teams; merging may be rejected", text, branch, login), nil
		}
		text += fmt.Sprintf("; %s is among those allowed to push to branch %s", login, branch)
	}

	// Ruleset rules.
	seen := map[string]bool{}
	var types []string
	for _, r := range rules {
		if r.Type != "" && !seen[r.Type] {
			seen[r.Type] = true
			types = append(types, r.Type)
		}
	}
	sort.Strings(types)
	if a.name == "repo.push" {
		for _, r := range pushBlockingRules {
			if seen[r.typ] {
				// UNVERIFIED: bypass actors of the ruleset may still push
				// directly; hallpass does not evaluate bypass lists.
				return integration.Unsupported("%s, but branch %s %s (%s rule); direct push not allowed by rules", text, branch, r.means, r.typ), nil
			}
		}
		if prot != nil && prot.RequiredPullRequestReviews != nil && !adminBypass {
			return integration.Unsupported("%s, but branch %s requires pull request reviews; direct push not allowed by its protection", text, branch), nil
		}
	}
	if adminBypass {
		text += fmt.Sprintf("; %s is an admin and branch %s does not enforce its protection for admins", login, branch)
	}
	switch {
	case len(rules) == 0 && prot == nil:
		return integration.Allowed("%s; branch %s has no rules and no classic protection", text, branch), nil
	case len(rules) == 0:
		return integration.Allowed("%s; branch %s has classic protection: a direct push may still be rejected", text, branch), nil
	}
	return integration.Allowed("%s; branch %s has %d rules (types %s): a direct push may still be rejected",
		text, branch, len(rules), strings.Join(types, ", ")), nil
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
	if m.State == "" {
		return integration.Unsupported("GitHub reported no membership state for %s in organization %s", login, t.owner), nil
	}
	if m.State != "active" {
		return integration.Denied("%s's membership in organization %s is %s, not active", login, t.owner, m.State), nil
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
	if m.State == "" {
		return integration.Unsupported("GitHub reported no membership state for %s in team %s", login, t.String()), nil
	}
	if m.State != "active" {
		return integration.Denied("%s's membership in team %s is %s, not active", login, t.String(), m.State), nil
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
