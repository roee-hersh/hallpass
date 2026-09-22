// Package googlecloud checks Google Cloud IAM permissions with the Policy
// Troubleshooter API.
//
// One connection is one credential. hallpass authenticates as a service
// account (a key, or the runtime identity on GCE/GKE) and asks
// policytroubleshooter.googleapis.com whether a principal holds a permission
// on a full resource name. Google evaluates the allow and deny policies of
// the resource and every ancestor, including group membership, and answers
// CAN_ACCESS, CANNOT_ACCESS, UNKNOWN_CONDITIONAL or UNKNOWN_INFO. Nothing is
// written and no user credential is ever used.
package googlecloud

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const (
	defaultTokenURL = "https://oauth2.googleapis.com/token"
	defaultAPI      = "https://policytroubleshooter.googleapis.com"
	defaultMetadata = "http://metadata.google.internal"

	scopeCloudPlatform = "https://www.googleapis.com/auth/cloud-platform"

	modeKey     = "key"
	modeKeyless = "keyless"

	assertionTTL = time.Hour
)

var emailRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+/=?^_{|}~.-]{1,64}@[A-Za-z0-9.-]{1,255}$`)

// Integration is the googlecloud product.
type Integration struct{}

// Name is "googlecloud".
func (Integration) Name() string { return "googlecloud" }

// Fields of a googlecloud connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		integration.CredentialField(false, "service-account key JSON (file:); required in auth_mode key"),
		{Name: "scope", Required: true, Validate: validateScope,
			Description: "organization:<number>, folder:<number> or project:<id> under which hallpass's credential can read IAM policies; the probe checks it"},
		{Name: "auth_mode", Default: modeKey, Enum: []string{modeKey, modeKeyless},
			Description: "key: sign a JWT with the key JSON; keyless: use the GCE/GKE runtime identity from the metadata server"},
		{Name: "quota_project", Validate: validateProject,
			Description: "project billed for the API calls (X-Goog-User-Project); needed when the credential's own project has the API disabled"},
		integration.ConnectionRefField("googleworkspace_connection", "googleworkspace", false,
			"optional: resolve the user in this Workspace first, so an unknown email is user_not_found and a suspended account is denied"),
		{Name: "token_url", Default: defaultTokenURL, Validate: integration.ValidateHTTPSURL,
			Description: "OAuth token endpoint"},
		{Name: "api_url", Default: defaultAPI, Validate: integration.ValidateHTTPSURL,
			Description: "Policy Troubleshooter API endpoint"},
		{Name: "metadata_url", Default: defaultMetadata, Validate: validateHTTPURL,
			Description: "GCE metadata server, auth_mode keyless only"},
	}
}

func validateProject(v string) error {
	if v == "" || projectRe.MatchString(v) {
		return nil
	}
	return errors.New("must be a project id")
}

func validateScope(v string) error {
	if v == "" {
		return nil
	}
	_, err := parseScope(v)
	return err
}

// parseScope validates organization:<n>, folder:<n> or project:<id> and
// returns the full resource name.
func parseScope(v string) (string, error) {
	r, err := catalog.ParseResource(v)
	if err != nil {
		return "", err
	}
	switch r.Type {
	case "organization", "folder", "project":
	default:
		return "", fmt.Errorf("scope %q must be organization:<number>, folder:<number> or project:<id>", v)
	}
	if len(r.Query) > 0 {
		return "", fmt.Errorf("scope %q must not carry a query", v)
	}
	full, err := fullResourceName(r)
	if err != nil {
		return "", fmt.Errorf("scope %q: %v", v, err)
	}
	return full, nil
}

// validateHTTPURL is ValidateHTTPSURL that also accepts plain http://, for
// the link-local metadata server.
func validateHTTPURL(v string) error {
	if strings.HasPrefix(v, "http://") && !strings.ContainsAny(v, " \t\r\n#?") {
		return nil
	}
	return integration.ValidateHTTPSURL(v)
}

// New builds a connection. It touches no network; the key is read when a
// token is minted, so a rotated key file takes effect.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	c := &Connection{
		settings:     s,
		mode:         s.Get("auth_mode"),
		quotaProject: s.Get("quota_project"),
		tokenURL:     strings.TrimRight(s.Get("token_url"), "/"),
		metadataURL:  strings.TrimRight(s.Get("metadata_url"), "/"),
		now:          d.Now,
		tokenURLFrom: "config",
	}
	c.scope, err = parseScope(s.Get("scope"))
	if err != nil {
		return nil, err
	}
	if c.mode == "" {
		c.mode = modeKey
	}
	switch c.mode {
	case modeKey:
		if s.Secret("credential").IsZero() {
			return nil, errors.New("credential is required in auth_mode key")
		}
	case modeKeyless:
	default:
		return nil, fmt.Errorf("auth_mode %q must be key or keyless", c.mode)
	}
	if c.quotaProject != "" && !projectRe.MatchString(c.quotaProject) {
		return nil, errors.New("quota_project must be a project id")
	}
	if ws := s.Get("googleworkspace_connection"); ws != "" {
		c.workspace, err = d.Connection(ws)
		if err != nil {
			return nil, err
		}
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.tokenURL == "" {
		c.tokenURLFrom = "key"
	}
	if c.metadataURL == "" {
		c.metadataURL = defaultMetadata
	}
	api := strings.TrimRight(s.Get("api_url"), "/")
	if api == "" {
		api = defaultAPI
	}
	c.plain = &httpx.Client{HTTP: hc, Logger: d.Logger}
	c.api = &httpx.Client{HTTP: hc, Base: api, Logger: d.Logger}
	c.tokens = &authx.TokenSource{Now: c.now, Fetch: c.mint}
	return c, nil
}

// Connection is one credential asking the Policy Troubleshooter.
type Connection struct {
	settings     *integration.Settings
	scope        string // full resource name of the configured scope
	mode         string
	quotaProject string
	tokenURL     string
	metadataURL  string
	now          func() time.Time
	workspace    integration.Connection // optional identity source

	// tokenURLFrom is "config" or "key" (use the key's token_uri).
	tokenURLFrom string

	plain  *httpx.Client // token and metadata endpoints
	api    *httpx.Client // the troubleshooter, per-call bearer
	tokens *authx.TokenSource
}

// --- authentication ---------------------------------------------------------

// saKey is the service-account key JSON.
type saKey struct {
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
	TokenURI     string `json:"token_uri"`
	ProjectID    string `json:"project_id"`
}

func (c *Connection) loadKey() (saKey, *rsa.PrivateKey, error) {
	raw, err := c.settings.Secret("credential").GetString()
	if err != nil {
		return saKey{}, nil, integration.Wrap(integration.CodeCredentialRejected, err, "the service-account key could not be read")
	}
	var k saKey
	if err := json.Unmarshal([]byte(raw), &k); err != nil {
		return saKey{}, nil, integration.Wrap(integration.CodeCredentialRejected, err, "credential is not a service-account key JSON")
	}
	if !emailRe.MatchString(k.ClientEmail) || k.PrivateKey == "" {
		return saKey{}, nil, integration.Errorf(integration.CodeCredentialRejected, "the service-account key JSON lacks client_email or private_key")
	}
	key, err := authx.ParseRSAPrivateKey([]byte(k.PrivateKey))
	if err != nil {
		return saKey{}, nil, integration.Wrap(integration.CodeCredentialRejected, err, "the service-account private_key is not a PEM RSA key")
	}
	return k, key, nil
}

// claims of the JWT bearer assertion: the service account itself, one scope.
type claims struct {
	Iss   string `json:"iss"`
	Scope string `json:"scope"`
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

// mint obtains an access token for the service account.
func (c *Connection) mint(ctx context.Context) (authx.Token, error) {
	if c.mode == modeKeyless {
		return c.fetchMetadataToken(ctx)
	}
	k, key, err := c.loadKey()
	if err != nil {
		return authx.Token{}, err
	}
	tokenURL := c.tokenURL
	if c.tokenURLFrom == "key" && k.TokenURI != "" {
		if err := integration.ValidateHTTPSURL(k.TokenURI); err != nil {
			return authx.Token{}, integration.Wrap(integration.CodeCredentialRejected, err, "the key's token_uri is not an https URL")
		}
		tokenURL = k.TokenURI
	}
	if tokenURL == "" {
		tokenURL = defaultTokenURL
	}
	now := c.now()
	payload, err := json.Marshal(claims{Iss: k.ClientEmail, Scope: scopeCloudPlatform, Aud: tokenURL, Iat: authx.Unix(now), Exp: authx.Unix(now.Add(assertionTTL))})
	if err != nil {
		return authx.Token{}, err
	}
	fetch := authx.JWTBearer(c.plain, tokenURL, func(context.Context) (string, error) {
		return authx.SignJWT(key, authx.Header{Alg: authx.RS256, Kid: k.PrivateKeyID}, payload)
	}, nil)
	return fetch(ctx)
}

// fetchMetadataToken reads the attached service account's token from the
// GCE metadata server. Its scope is whatever the instance was created with;
// cloud-platform is the default.
func (c *Connection) fetchMetadataToken(ctx context.Context) (authx.Token, error) {
	var out struct {
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
	}
	resp, err := c.plain.Do(ctx, &httpx.Request{Method: http.MethodGet,
		Path:   c.metadataURL + "/computeMetadata/v1/instance/service-accounts/default/token",
		Header: http.Header{"Metadata-Flavor": {"Google"}}})
	if err != nil {
		return authx.Token{}, integration.Wrap(integration.CodeCredentialRejected, err, "the metadata server gave no token; auth_mode keyless needs a GCE or GKE Workload Identity")
	}
	if err := resp.JSON(&out); err != nil || out.AccessToken == "" {
		return authx.Token{}, integration.Errorf(integration.CodeCredentialRejected, "the metadata server returned no access_token")
	}
	t := authx.Token{Value: out.AccessToken}
	var secs int64
	if json.Unmarshal(out.ExpiresIn, &secs) == nil && secs > 0 {
		t.Expiry = c.now().Add(time.Duration(secs) * time.Second)
	}
	return t, nil
}

// whoami is the service account email, for the probe. Keyless mode asks
// the metadata server; a failure there leaves it empty.
func (c *Connection) whoami(ctx context.Context) string {
	if c.mode == modeKey {
		if k, _, err := c.loadKey(); err == nil {
			return k.ClientEmail
		}
		return ""
	}
	resp, err := c.plain.Do(ctx, &httpx.Request{Method: http.MethodGet,
		Path:   c.metadataURL + "/computeMetadata/v1/instance/service-accounts/default/email",
		Header: http.Header{"Metadata-Flavor": {"Google"}}})
	if err != nil {
		return ""
	}
	email := strings.TrimSpace(string(resp.Body))
	if !emailRe.MatchString(email) {
		return ""
	}
	return email
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
		case te.Code == "invalid_grant" || te.Code == "unauthorized_client" || te.Code == "invalid_client":
			return integration.Wrap(integration.CodeCredentialRejected, err, "the token endpoint refused the service-account assertion (%s): the key is revoked, the account is disabled or the clock is off", te.Code)
		}
	}
	return authx.ClassifyTokenError(err)
}

// --- API transport ----------------------------------------------------------

var reasonRe = regexp.MustCompile(`"reason"\s*:\s*"([A-Za-z_]+)"`)

// reason extracts the first reason from a Google error body snippet. The
// message is never used.
func reason(err error) string {
	var se *httpx.StatusError
	if !errors.As(err, &se) {
		return ""
	}
	if m := reasonRe.FindStringSubmatch(se.Snippet); m != nil {
		return m[1]
	}
	return ""
}

// call performs one API request. A 401 invalidates the token and retries
// once. The returned error is the raw httpx error so callers can branch on
// the status; classify maps everything else.
func (c *Connection) call(ctx context.Context, req *httpx.Request) (*httpx.Response, error) {
	attempt := func() (*httpx.Response, error) {
		tok, err := c.tokens.Get(ctx)
		if err != nil {
			return nil, tokenError(err)
		}
		r := *req
		r.Header = req.Header.Clone()
		if r.Header == nil {
			r.Header = http.Header{}
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		if c.quotaProject != "" {
			r.Header.Set("X-Goog-User-Project", c.quotaProject)
		}
		return c.api.Do(ctx, &r)
	}
	resp, err := attempt()
	if httpx.Status(err) == 401 {
		c.tokens.Invalidate()
		resp, err = attempt()
	}
	return resp, err
}

// rateLimitReasons are the 403 reasons that mean "slow down".
var rateLimitReasons = map[string]bool{
	"rateLimitExceeded": true, "userRateLimitExceeded": true, "quotaExceeded": true,
	"dailyLimitExceeded": true, "RATE_LIMIT_EXCEEDED": true,
}

// classify maps an API error to an integration error. A 403 is hallpass's
// own setup (the API is not enabled, the service account lacks the role,
// the quota project is wrong) unless its reason is a rate limit.
func classify(err error) *integration.Error {
	switch httpx.Status(err) {
	case 403:
		r := reason(err)
		if rateLimitReasons[r] {
			return integration.Wrap(integration.CodeUpstreamRateLimit, err, "rate limited by Google")
		}
		if r == "" {
			return integration.Wrap(integration.CodeCredentialRejected, err, "the Policy Troubleshooter refused the call (HTTP 403): enable the API, grant the service account roles/iam.securityReviewer, or set quota_project")
		}
		return integration.Wrap(integration.CodeCredentialRejected, err, "the Policy Troubleshooter refused the call (HTTP 403, %s): enable the API, grant the service account roles/iam.securityReviewer, or set quota_project", r)
	case 400:
		return integration.Wrap(integration.CodeInvalidRequest, err, "the Policy Troubleshooter rejected the request: check the permission name, the resource and that the principal is a Google Account or service account")
	case 404:
		return integration.Wrap(integration.CodeResourceNotVisible, err, "the Policy Troubleshooter found no such resource")
	}
	return httpx.Classify(err)
}

// --- identity ---------------------------------------------------------------

// ResolveIdentity takes the email as the principal. With a
// googleworkspace_connection the Workspace Directory decides whether the
// account exists (aliases become the primary address) and whether it is
// suspended or archived; without one the troubleshooter is asked about the
// address as given.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if !emailRe.MatchString(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user email %q is not an address", email)
	}
	if c.workspace == nil {
		return integration.Identity{ID: email, Display: email, Attrs: map[string]string{"source": "email"}}, nil
	}
	ws, err := c.workspace.ResolveIdentity(ctx, u)
	if err != nil {
		return integration.Identity{}, err
	}
	primary := strings.ToLower(ws.ID)
	if !emailRe.MatchString(primary) {
		return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "the Workspace connection returned an identity that is not an email")
	}
	return integration.Identity{
		ID:      primary,
		Display: primary,
		Attrs: map[string]string{
			"source":    "googleworkspace",
			"suspended": attrOr(ws, "suspended", "unknown"),
			"archived":  attrOr(ws, "archived", "unknown"),
		},
	}, nil
}

func attrOr(id integration.Identity, k, def string) string {
	if v := id.Attr(k); v != "" {
		return v
	}
	return def
}

// --- checks -----------------------------------------------------------------

// accessTuple is the troubleshooter's question.
type accessTuple struct {
	Principal        string `json:"principal"`
	FullResourceName string `json:"fullResourceName"`
	Permission       string `json:"permission"`
}

// troubleshootResponse is the subset of the v3 response hallpass reads.
type troubleshootResponse struct {
	OverallAccessState string `json:"overallAccessState"`
	AccessTuple        struct {
		PermissionFQDN string `json:"permissionFqdn"`
	} `json:"accessTuple"`
	AllowPolicyExplanation struct {
		AllowAccessState string `json:"allowAccessState"`
	} `json:"allowPolicyExplanation"`
	DenyPolicyExplanation struct {
		DenyAccessState    string `json:"denyAccessState"`
		PermissionDeniable *bool  `json:"permissionDeniable"`
	} `json:"denyPolicyExplanation"`
}

// The v3 states.
const (
	stateCanAccess          = "CAN_ACCESS"
	stateCannotAccess       = "CANNOT_ACCESS"
	stateUnknownInfo        = "UNKNOWN_INFO"
	stateUnknownConditional = "UNKNOWN_CONDITIONAL"

	allowGranted    = "ALLOW_ACCESS_STATE_GRANTED"
	allowNotGranted = "ALLOW_ACCESS_STATE_NOT_GRANTED"
	allowUnknownCon = "ALLOW_ACCESS_STATE_UNKNOWN_CONDITIONAL"
	allowUnknownInf = "ALLOW_ACCESS_STATE_UNKNOWN_INFO"

	denyDenied     = "DENY_ACCESS_STATE_DENIED"
	denyNotDenied  = "DENY_ACCESS_STATE_NOT_DENIED"
	denyUnknownCon = "DENY_ACCESS_STATE_UNKNOWN_CONDITIONAL"
	denyUnknownInf = "DENY_ACCESS_STATE_UNKNOWN_INFO"
)

// troubleshoot asks one question.
func (c *Connection) troubleshoot(ctx context.Context, principal, permission, resource string) (troubleshootResponse, error) {
	var out troubleshootResponse
	// The call reads policies and is safe to retry.
	idem := true
	resp, err := c.call(ctx, &httpx.Request{Method: http.MethodPost, Path: "/v3/iam:troubleshoot",
		JSON: map[string]accessTuple{"accessTuple": {Principal: principal, FullResourceName: resource, Permission: permission}}, Idempotent: &idem})
	if err != nil {
		return out, classify(err)
	}
	if err := resp.JSON(&out); err != nil {
		return out, integration.Wrap(integration.CodeUpstreamError, err, "the Policy Troubleshooter returned an unreadable response")
	}
	return out, nil
}

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	q, err := parseRef(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, err
	}
	principal := strings.ToLower(r.Identity.ID)
	if !emailRe.MatchString(principal) {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "identity is not an email address")
	}
	if r.Identity.Attr("source") == "googleworkspace" {
		for _, state := range []string{"suspended", "archived"} {
			switch r.Identity.Attr(state) {
			case "true":
				return integration.Denied("%s is %s in Google Workspace", principal, state), nil
			case "false":
			default:
				return integration.Unsupported("the Workspace Directory did not report whether %s is %s", principal, state), nil
			}
		}
	}
	res, err := c.troubleshoot(ctx, principal, q.permission, q.resource)
	if err != nil {
		return integration.Decision{}, err
	}
	what := q.permission + " on " + r.Resource.Raw
	switch res.OverallAccessState {
	case stateCanAccess:
		return integration.Allowed("%s holds %s", principal, what), nil
	case stateCannotAccess:
		// UNVERIFIED: a principal that is not a Google Account or a service
		// account (a Workforce Identity user, a typo) is assumed to come back
		// CANNOT_ACCESS or HTTP 400, never some other state.
		if res.DenyPolicyExplanation.DenyAccessState == denyDenied {
			return integration.Denied("a deny policy denies %s %s", principal, what), nil
		}
		return integration.Denied("no allow policy grants %s %s", principal, what), nil
	case stateUnknownConditional:
		return integration.Unsupported("whether %s holds %s depends on a policy condition the troubleshooter could not evaluate", principal, what), nil
	case stateUnknownInfo:
		// UNVERIFIED: UNKNOWN_INFO is also what the troubleshooter answers
		// when it cannot read the membership of a Google Group in a binding;
		// hallpass cannot tell that apart from an unreadable policy.
		return integration.UnknownDecision(integration.CodeResourceNotVisible, "hallpass cannot read every policy that applies to %s, or the resource does not exist; the service account needs roles/iam.securityReviewer above it", r.Resource.Raw), nil
	}
	return integration.Decision{}, integration.Errorf(integration.CodeUpstreamError, "the Policy Troubleshooter returned an unknown access state")
}

// --- probe ------------------------------------------------------------------

// Probe mints a token and asks the troubleshooter whether the service
// account itself may get the configured scope. CAN_ACCESS or CANNOT_ACCESS
// proves the API is enabled and the policies under scope are readable;
// UNKNOWN_INFO means the securityReviewer role is missing there.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	who := c.whoami(ctx)
	if who == "" {
		return integration.ProbeResult{}, integration.Errorf(integration.CodeCredentialRejected, "could not determine the service account's email")
	}
	permission := "resourcemanager.projects.get"
	switch {
	case strings.Contains(c.scope, "/folders/"):
		permission = "resourcemanager.folders.get"
	case strings.Contains(c.scope, "/organizations/"):
		permission = "resourcemanager.organizations.get"
	}
	res, err := c.troubleshoot(ctx, who, permission, c.scope)
	if err != nil {
		return integration.ProbeResult{}, err
	}
	out := integration.ProbeResult{Summary: fmt.Sprintf("service account %s asks the Policy Troubleshooter about %s (%s)", who, c.settings.Get("scope"), res.OverallAccessState)}
	switch res.OverallAccessState {
	case stateCanAccess, stateCannotAccess, stateUnknownConditional:
	case stateUnknownInfo:
		// UNVERIFIED: roles/iam.securityReviewer is assumed to be enough for
		// the troubleshooter to read every allow and deny policy under scope.
		out.Warnings = append(out.Warnings, fmt.Sprintf("the troubleshooter could not read every policy under %s: grant %s roles/iam.securityReviewer there, or every check will be unknown", c.settings.Get("scope"), who))
	default:
		out.Warnings = append(out.Warnings, "the troubleshooter returned an unknown access state")
	}
	if c.workspace == nil {
		out.Warnings = append(out.Warnings, "no googleworkspace_connection: an email with no Google Account is answered by the troubleshooter as if it existed (deny), never user_not_found")
	}
	out.Warnings = append(out.Warnings, "the Policy Troubleshooter discloses which permissions other principals hold; this is inherent to how hallpass checks")
	return out, nil
}
