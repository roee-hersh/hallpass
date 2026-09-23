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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	if v == "" || isProject(v) {
		return nil
	}
	return errors.New("must be a project id or number")
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
// token is minted, so a rotated key file takes effect. The config loader
// has already run every Field's Validate and Enum; the checks repeated here
// cover connections built from raw settings, as tests do.
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
	if err := validateProject(c.quotaProject); err != nil {
		return nil, fmt.Errorf("quota_project: %v", err)
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
		c.tokenURL = defaultTokenURL
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

	plain  *httpx.Client // token and metadata endpoints
	api    *httpx.Client // the troubleshooter, per-call bearer
	tokens *authx.TokenSource
}

// --- authentication ---------------------------------------------------------

func (c *Connection) loadKey() (authx.GoogleServiceAccountKey, error) {
	raw, err := c.settings.Secret("credential").GetString()
	if err != nil {
		return authx.GoogleServiceAccountKey{}, integration.Wrap(integration.CodeCredentialRejected, err, "the service-account key could not be read")
	}
	return authx.ParseGoogleServiceAccountKey(raw)
}

// claims of the JWT bearer assertion: the service account itself, one scope.
type claims struct {
	Iss   string `json:"iss"`
	Scope string `json:"scope"`
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

// mint obtains an access token for the service account: a JWT bearer
// exchange in key mode, the metadata server's token in keyless mode.
func (c *Connection) mint(ctx context.Context) (authx.Token, error) {
	if c.mode == modeKeyless {
		return authx.GoogleMetadataToken(ctx, c.plain, c.metadataURL, c.now)
	}
	k, err := c.loadKey()
	if err != nil {
		return authx.Token{}, err
	}
	now := c.now()
	payload, err := json.Marshal(claims{Iss: k.ClientEmail, Scope: scopeCloudPlatform, Aud: c.tokenURL, Iat: authx.Unix(now), Exp: authx.Unix(now.Add(assertionTTL))})
	if err != nil {
		return authx.Token{}, err
	}
	assertion, err := authx.SignJWT(k.Key, authx.Header{Alg: authx.RS256, Kid: k.PrivateKeyID}, payload)
	if err != nil {
		return authx.Token{}, err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	return authx.FetchToken(ctx, c.plain, authx.TokenRequest{URL: c.tokenURL, Form: form, Now: c.now})
}

// whoami is the service account's email, for the probe: the key's
// client_email, or in keyless mode the metadata server's answer.
func (c *Connection) whoami(ctx context.Context) (string, error) {
	if c.mode == modeKey {
		k, err := c.loadKey()
		if err != nil {
			return "", err
		}
		return k.ClientEmail, nil
	}
	resp, err := c.plain.Do(ctx, &httpx.Request{Method: http.MethodGet,
		Path:   c.metadataURL + "/computeMetadata/v1/instance/service-accounts/default/email",
		Header: http.Header{"Metadata-Flavor": {"Google"}}})
	if err != nil {
		return "", integration.Wrap(integration.CodeCredentialRejected, err, "the metadata server did not report the service account's email; auth_mode keyless needs a GCE or GKE Workload Identity")
	}
	email := strings.TrimSpace(string(resp.Body))
	if !emailRe.MatchString(email) {
		return "", integration.Errorf(integration.CodeCredentialRejected, "the metadata server returned no service account email")
	}
	return email, nil
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

// call performs one API request with the bearer token. 4xx responses are
// returned whole so their status and reason can be read from the full
// body; a 401 invalidates the token and retries once. Transport errors,
// timeouts and 5xx come back as httpx errors.
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
		r.Accept4xx = true
		return c.api.Do(ctx, &r)
	}
	resp, err := attempt()
	if err == nil && resp.Status == 401 {
		c.tokens.Invalidate()
		resp, err = attempt()
	}
	if err != nil {
		return nil, httpx.Classify(err)
	}
	if resp.Status >= 400 {
		return nil, apiError(resp)
	}
	return resp, nil
}

// rateLimitReasons and rateLimitStatuses are the 403 markers that mean
// "slow down" rather than "not allowed".
var (
	rateLimitReasons  = map[string]bool{"rateLimitExceeded": true, "userRateLimitExceeded": true, "quotaExceeded": true, "dailyLimitExceeded": true, "RATE_LIMIT_EXCEEDED": true}
	rateLimitStatuses = map[string]bool{"RESOURCE_EXHAUSTED": true}
)

// googleError is the envelope of a Google API error body. Only the status
// and the reason tokens are read; the message is never used.
type googleError struct {
	Error struct {
		Status  string `json:"status"`
		Details []struct {
			Reason string `json:"reason"`
		} `json:"details"`
		Errors []struct {
			Reason string `json:"reason"`
		} `json:"errors"`
	} `json:"error"`
}

// apiError maps a 4xx response to an integration error. A 403 is hallpass's
// own setup (the API is not enabled, the service account lacks the role,
// the quota project is refused) unless its reason is a rate limit.
func apiError(resp *httpx.Response) *integration.Error {
	var ge googleError
	_ = json.Unmarshal(resp.Body, &ge)
	reason := authx.GoogleReasonIn(string(resp.Body))
	if reason == "" {
		for _, d := range ge.Error.Details {
			if d.Reason != "" {
				reason = d.Reason
				break
			}
		}
	}
	cause := fmt.Errorf("policy troubleshooter: HTTP %d", resp.Status)
	switch resp.Status {
	case 429:
		return integration.Wrap(integration.CodeUpstreamRateLimit, cause, "rate limited by Google")
	case 403:
		if rateLimitReasons[reason] || rateLimitStatuses[ge.Error.Status] {
			return integration.Wrap(integration.CodeUpstreamRateLimit, cause, "rate limited by Google")
		}
		if reason == "" {
			return integration.Wrap(integration.CodeCredentialRejected, cause, "the Policy Troubleshooter refused the call (HTTP 403): enable the API, grant the service account roles/iam.securityReviewer, or set quota_project")
		}
		return integration.Wrap(integration.CodeCredentialRejected, cause, "the Policy Troubleshooter refused the call (HTTP 403, %s): enable the API, grant the service account roles/iam.securityReviewer, or set quota_project", reason)
	case 401:
		return integration.Wrap(integration.CodeCredentialRejected, cause, "the Policy Troubleshooter rejected the access token twice")
	case 400:
		return integration.Wrap(integration.CodeInvalidRequest, cause, "the Policy Troubleshooter rejected the request: check the permission name, the resource and that the principal is a Google Account or service account")
	case 404:
		return integration.Wrap(integration.CodeResourceNotVisible, cause, "the Policy Troubleshooter found no such resource")
	}
	return integration.Wrap(integration.CodeUpstreamError, cause, "the Policy Troubleshooter answered HTTP %d", resp.Status)
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
	OverallAccessState    string `json:"overallAccessState"`
	DenyPolicyExplanation struct {
		DenyAccessState string `json:"denyAccessState"`
	} `json:"denyPolicyExplanation"`
}

// The v3 states.
const (
	stateCanAccess          = "CAN_ACCESS"
	stateCannotAccess       = "CANNOT_ACCESS"
	stateUnknownInfo        = "UNKNOWN_INFO"
	stateUnknownConditional = "UNKNOWN_CONDITIONAL"

	denyDenied = "DENY_ACCESS_STATE_DENIED"
)

// troubleshoot asks one question.
func (c *Connection) troubleshoot(ctx context.Context, principal, permission, resource string) (troubleshootResponse, error) {
	var out troubleshootResponse
	// The call reads policies and is safe to retry.
	idem := true
	resp, err := c.call(ctx, &httpx.Request{Method: http.MethodPost, Path: "/v3/iam:troubleshoot",
		JSON: map[string]accessTuple{"accessTuple": {Principal: principal, FullResourceName: resource, Permission: permission}}, Idempotent: &idem})
	if err != nil {
		return out, err
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
	who, err := c.whoami(ctx)
	if err != nil {
		return integration.ProbeResult{}, err
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
