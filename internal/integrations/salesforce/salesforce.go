// Package salesforce checks record, object, field and system permissions
// through the Salesforce REST API.
//
// hallpass authenticates as an External Client App with the OAuth 2.0 JWT
// bearer flow (or client credentials), acting as a read-only integration
// user. It maps the caller's email to a User row, then asks Salesforce's own
// permission objects: UserRecordAccess for one record, ObjectPermissions and
// FieldPermissions across the user's profile and permission sets,
// PermissionSet for system permissions and PermissionSetAssignment for
// permission set membership. Every query is SOQL over GET; nothing is
// written.
//
// Every Salesforce behaviour this package relies on was designed from
// secondary sources and is marked "UNVERIFIED:" until confirmed in a
// Developer Edition org. See docs/integrations/salesforce.md.
package salesforce

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/cache"
	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// Integration is the salesforce product.
type Integration struct{}

// Name is "salesforce".
func (Integration) Name() string { return "salesforce" }

const (
	flowJWTBearer         = "jwt_bearer"
	flowClientCredentials = "client_credentials"

	matchEmail        = "Email"
	matchUsername     = "Username"
	matchFederationID = "FederationIdentifier"

	defaultAudience = "https://login.salesforce.com"
	defaultTokenTTL = "15m"
	tokenPath       = "/services/oauth2/token"

	// jwtLifetime is the assertion's validity. UNVERIFIED: Salesforce is
	// reported to reject assertions whose exp is more than 3 minutes ahead.
	jwtLifetime = 3 * time.Minute
	// describeTTL is how long the PermissionSet describe and each sObject
	// existence check are cached.
	describeTTL = time.Hour
	// maxQueryPages bounds nextRecordsUrl following.
	maxQueryPages = 5
	// lowLimitPercent is the daily API allocation below which the probe warns.
	lowLimitPercent = 10
)

var apiVersionRe = regexp.MustCompile(`^v[0-9]{2,3}\.[0-9]$`)

// Fields of a salesforce connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		integration.URLField(true, "My Domain URL, e.g. https://acme.my.salesforce.com; the token endpoint is {url}/services/oauth2/token"),
		{Name: "client_id", Required: true, Validate: validateClientID,
			Description: "consumer key of the External Client App"},
		{Name: "auth_flow", Default: flowJWTBearer, Enum: []string{flowJWTBearer, flowClientCredentials},
			Description: "jwt_bearer (a private key, the integration user as JWT subject) or client_credentials (consumer secret, the app's Run As user)"},
		{Name: "username", Validate: validateUsername,
			Description: "the integration user's Username; the JWT sub claim, required for jwt_bearer"},
		integration.CredentialField(true, "PEM RSA private key for jwt_bearer, or the consumer secret for client_credentials"),
		{Name: "audience", Default: defaultAudience, Validate: integration.ValidateHTTPSURL,
			Description: "the JWT aud claim: https://login.salesforce.com, or https://test.salesforce.com for sandboxes"},
		{Name: "api_version", Required: true, Validate: validateAPIVersion,
			Description: "REST API version to pin, e.g. v66.0; never discovered automatically"},
		{Name: "match_field", Default: matchEmail, Enum: []string{matchEmail, matchUsername, matchFederationID},
			Description: "the User field the caller's email is matched against"},
		{Name: "token_ttl", Default: defaultTokenTTL, Validate: validateTokenTTL,
			Description: "how long a minted access token is reused; the token response carries no expiry"},
	}
}

func validateClientID(v string) error {
	if v == "" {
		return nil
	}
	if err := validateText(v); err != nil {
		return fmt.Errorf("client_id: %w", err)
	}
	if strings.ContainsAny(v, " \t\r\n") {
		return errors.New("client_id must not contain whitespace")
	}
	return nil
}

func validateUsername(v string) error {
	if v == "" {
		return nil
	}
	if err := validateText(v); err != nil {
		return fmt.Errorf("username: %w", err)
	}
	if strings.ContainsAny(v, " \t\r\n'\\") {
		return errors.New("username must not contain whitespace, quotes or backslashes")
	}
	return nil
}

func validateAPIVersion(v string) error {
	if !apiVersionRe.MatchString(v) {
		return fmt.Errorf("api_version %q must look like v66.0", v)
	}
	return nil
}

func validateTokenTTL(v string) error {
	d, err := time.ParseDuration(v)
	if err != nil {
		return fmt.Errorf("token_ttl %q is not a duration such as 15m", v)
	}
	if d < time.Minute || d > 24*time.Hour {
		return fmt.Errorf("token_ttl %q must be between 1m and 24h", v)
	}
	return nil
}

// Actions of the salesforce integration.
func (Integration) Actions() []catalog.Action {
	out := make([]catalog.Action, 0, len(actionList))
	for _, a := range actionList {
		out = append(out, catalog.Action{Name: a.name, Description: a.desc})
	}
	return out
}

func valueOr(s *integration.Settings, key, def string) string {
	if v := s.Get(key); v != "" {
		return v
	}
	return def
}

// New builds a connection. It touches no network; the credential is read
// each time a token is minted, so a rotated key file takes effect.
func (Integration) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	if s.Secret("credential").IsZero() {
		return nil, errors.New("credential is required")
	}
	c := &Connection{
		settings:   s,
		url:        strings.TrimRight(s.Get("url"), "/"),
		clientID:   s.Get("client_id"),
		flow:       valueOr(s, "auth_flow", flowJWTBearer),
		username:   s.Get("username"),
		audience:   valueOr(s, "audience", defaultAudience),
		version:    s.Get("api_version"),
		matchField: valueOr(s, "match_field", matchEmail),
		logger:     d.Logger,
		now:        d.Now,
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	if c.now == nil {
		c.now = time.Now
	}
	c.desc = cache.New[struct{}, map[string]bool](1)
	c.desc.SetClock(c.now)
	c.objects = cache.New[string, bool](0)
	c.objects.SetClock(c.now)
	// Describes are schema, not permission state: a fresh check does not
	// re-read them.
	c.desc.SetFreshMaxAge(describeTTL)
	c.objects.SetFreshMaxAge(describeTTL)
	if c.url == "" {
		return nil, errors.New("url is required")
	}
	if c.clientID == "" {
		return nil, errors.New("client_id is required")
	}
	if err := validateAPIVersion(c.version); err != nil {
		return nil, err
	}
	switch c.flow {
	case flowJWTBearer:
		if c.username == "" {
			return nil, errors.New("username is required for auth_flow jwt_bearer")
		}
	case flowClientCredentials:
	default:
		return nil, fmt.Errorf("auth_flow %q must be jwt_bearer or client_credentials", c.flow)
	}
	switch c.matchField {
	case matchEmail, matchUsername, matchFederationID:
	default:
		return nil, fmt.Errorf("match_field %q must be Email, Username or FederationIdentifier", c.matchField)
	}
	ttlText := valueOr(s, "token_ttl", defaultTokenTTL)
	if err := validateTokenTTL(ttlText); err != nil {
		return nil, err
	}
	ttl, _ := time.ParseDuration(ttlText)
	c.plain = &httpx.Client{HTTP: hc, Logger: d.Logger}
	c.api = &httpx.Client{HTTP: hc, Logger: d.Logger, Auth: c.bearerAuth}
	c.tokens = &authx.TokenSource{Fetch: c.fetchToken, DefaultTTL: ttl, Now: c.now}
	return c, nil
}

// Connection is one Salesforce org reached through one External Client App.
type Connection struct {
	settings   *integration.Settings
	url        string
	clientID   string
	flow       string
	username   string
	audience   string
	version    string
	matchField string
	logger     *slog.Logger
	now        func() time.Time

	plain  *httpx.Client // the token endpoint, unauthenticated
	api    *httpx.Client // REST calls with the bearer token
	tokens *authx.TokenSource

	instMu      sync.Mutex
	instanceURL string

	// desc is the PermissionSet describe's PermissionsXxx field names,
	// under the empty key; objects is whether each sObject exists, by API
	// name. Both are kept for describeTTL.
	desc    *cache.TTL[struct{}, map[string]bool]
	objects *cache.TTL[string, bool]
}

// --- authentication ---------------------------------------------------------

// assertion signs the JWT bearer assertion: RS256, iss = consumer key,
// sub = integration user, aud = login host, exp = now + 3 minutes.
func (c *Connection) assertion() (string, error) {
	pemText, err := c.settings.Secret("credential").GetString()
	if err != nil {
		return "", integration.Wrap(integration.CodeCredentialRejected, err, "the private key could not be read")
	}
	key, err := authx.ParseRSAPrivateKey([]byte(pemText))
	if err != nil {
		return "", integration.Wrap(integration.CodeCredentialRejected, err, "the credential is not a PEM RSA private key")
	}
	claims := authx.StandardClaims{
		Iss: c.clientID,
		Sub: c.username,
		Aud: c.audience,
		Exp: authx.Unix(c.now().Add(jwtLifetime)),
	}
	return authx.SignJWT(key, authx.Header{Alg: authx.RS256}, claims)
}

// tokenForm builds the token request for the configured flow, in the same
// shape authx.JWTBearer and authx.ClientCredentials would send.
func (c *Connection) tokenForm() (url.Values, error) {
	switch c.flow {
	case flowClientCredentials:
		sec, err := c.settings.Secret("credential").GetString()
		if err != nil {
			return nil, integration.Wrap(integration.CodeCredentialRejected, err, "the consumer secret could not be read")
		}
		// UNVERIFIED: the client credentials flow needs a "Run As" user on the
		// External Client App; the token then acts as that user.
		return url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {c.clientID},
			"client_secret": {sec},
		}, nil
	default:
		a, err := c.assertion()
		if err != nil {
			return nil, err
		}
		return url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":  {a},
		}, nil
	}
}

// fetchToken posts to {url}/services/oauth2/token. The response has no
// expires_in, so the TokenSource's DefaultTTL (token_ttl) applies. It is
// posted here rather than through authx.PostToken because the instance_url
// field of the response is needed.
func (c *Connection) fetchToken(ctx context.Context) (authx.Token, error) {
	form, err := c.tokenForm()
	if err != nil {
		return authx.Token{}, err
	}
	idem := false
	resp, err := c.plain.Do(ctx, &httpx.Request{Method: http.MethodPost, Path: c.url + tokenPath, Form: form, Idempotent: &idem, Accept4xx: true})
	if err != nil {
		return authx.Token{}, err
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		InstanceURL string `json:"instance_url"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
	}
	if len(resp.Body) > 0 {
		_ = json.Unmarshal(resp.Body, &tr)
	}
	if resp.Status == http.StatusTooManyRequests {
		return authx.Token{}, integration.Errorf(integration.CodeUpstreamRateLimit, "the token endpoint is rate limiting hallpass")
	}
	if resp.Status >= 400 || tr.Error != "" {
		// error_description is deliberately not kept: it can echo the request.
		return authx.Token{}, &authx.TokenError{Status: resp.Status, Code: tr.Error}
	}
	if tr.AccessToken == "" {
		return authx.Token{}, errors.New("token endpoint returned no access_token")
	}
	// UNVERIFIED: the token response's instance_url is the host that serves
	// the org's REST API and may differ from the My Domain URL. It is used
	// as the API base when it is an https URL without query or userinfo
	// whose host is the configured url's host or a Salesforce-owned domain;
	// otherwise url is used.
	c.setInstanceURL(tr.InstanceURL)
	return authx.Token{Value: tr.AccessToken}, nil
}

// instanceDomains are the domain suffixes an instance_url host may carry
// besides the configured url's own host. UNVERIFIED: every org's REST host
// is under one of these; a host elsewhere is treated as untrusted.
var instanceDomains = []string{".salesforce.com", ".force.com", ".salesforce.mil"}

// setInstanceURL records the token response's instance_url as the API base
// when it is trustworthy: https, no userinfo, query or fragment, and a host
// that either equals the configured url's host or is under a Salesforce
// domain. Anything else is ignored, so a token endpoint (or a proxy in front
// of it) cannot redirect the bearer token to a host of its choosing.
func (c *Connection) setInstanceURL(s string) {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	inst := ""
	if u, err := url.Parse(s); err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
		if c.trustedInstanceHost(u) {
			inst = s
		} else {
			c.logger.Debug("salesforce: ignoring token response instance_url with an untrusted host; using url", "host", u.Host)
		}
	}
	c.instMu.Lock()
	c.instanceURL = inst
	c.instMu.Unlock()
}

func (c *Connection) trustedInstanceHost(u *url.URL) bool {
	if cfg, err := url.Parse(c.url); err == nil && cfg.Host != "" && strings.EqualFold(cfg.Host, u.Host) {
		return true
	}
	host := strings.ToLower(u.Hostname())
	for _, d := range instanceDomains {
		if strings.HasSuffix(host, d) && len(host) > len(d) {
			return true
		}
	}
	return false
}

// apiBase is the instance URL learned from the token response, or url.
func (c *Connection) apiBase() string {
	c.instMu.Lock()
	defer c.instMu.Unlock()
	if c.instanceURL != "" {
		return c.instanceURL
	}
	return c.url
}

func (c *Connection) bearerAuth(ctx context.Context, r *http.Request) error {
	tok, err := c.tokens.Get(ctx)
	if err != nil {
		return authx.ClassifyTokenError(err)
	}
	r.Header.Set("Authorization", "Bearer "+tok)
	return nil
}

// --- transport --------------------------------------------------------------

// apiError is a 4xx answered by the REST API itself, decoded from the JSON
// array Salesforce returns: [{"message": "...", "errorCode": "..."}]. The
// messages are dropped: they can echo the query.
type apiError struct {
	status int
	codes  []string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("salesforce: HTTP %d %s", e.status, strings.Join(e.codes, ","))
}

func (e *apiError) has(code string) bool {
	for _, c := range e.codes {
		if c == code {
			return true
		}
	}
	return false
}

// errorCodeRe is the shape of a Salesforce errorCode (INVALID_FIELD,
// REQUEST_LIMIT_EXCEEDED). Anything else in that slot is not trusted into a
// decision text or a log line and is rendered as unknownErrorCode.
var errorCodeRe = regexp.MustCompile(`^[A-Z_]{1,64}$`)

const unknownErrorCode = "unknown error"

func decodeAPIError(resp *httpx.Response) *apiError {
	e := &apiError{status: resp.Status}
	var body []struct {
		ErrorCode string `json:"errorCode"`
	}
	if json.Unmarshal(resp.Body, &body) == nil {
		for _, b := range body {
			switch {
			case b.ErrorCode == "":
			case errorCodeRe.MatchString(b.ErrorCode):
				e.codes = append(e.codes, b.ErrorCode)
			case !e.has(unknownErrorCode):
				e.codes = append(e.codes, unknownErrorCode)
			}
		}
	}
	return e
}

// get performs one authenticated GET. A 401 drops the cached token and the
// call is retried once with a fresh one; a second 401 is an apiError.
func (c *Connection) get(ctx context.Context, path string, q url.Values, out any) error {
	resp, err := c.getOnce(ctx, path, q)
	if err == nil && resp.Status == http.StatusUnauthorized {
		// UNVERIFIED: an expired or revoked session answers 401 with
		// errorCode INVALID_SESSION_ID. Any 401 is treated that way: the
		// token is dropped and minted again once.
		c.tokens.Invalidate()
		resp, err = c.getOnce(ctx, path, q)
	}
	if err != nil {
		return err
	}
	if resp.Status >= 400 {
		return decodeAPIError(resp)
	}
	if out != nil {
		if err := resp.JSON(out); err != nil {
			return integration.Wrap(integration.CodeUpstreamError, err, "the Salesforce response was not JSON")
		}
	}
	return nil
}

func (c *Connection) getOnce(ctx context.Context, path string, q url.Values) (*httpx.Response, error) {
	// The token is fetched before the URL is built so the instance URL it
	// carries is the base of this very call.
	if _, err := c.tokens.Get(ctx); err != nil {
		return nil, authx.ClassifyTokenError(err)
	}
	return c.api.Do(ctx, &httpx.Request{Method: http.MethodGet, Path: c.apiBase() + path, Query: q, Accept4xx: true})
}

// classify maps a failed call to an integration error. subject names the
// object or field the call was about, for the unsupported text.
func classify(err error, subject string) error {
	var ie *integration.Error
	if errors.As(err, &ie) {
		return ie
	}
	var ae *apiError
	if errors.As(err, &ae) {
		switch ae.status {
		case http.StatusUnauthorized:
			return integration.Wrap(integration.CodeCredentialRejected, err, "the access token was rejected twice (HTTP 401)")
		case http.StatusForbidden:
			if ae.has("REQUEST_LIMIT_EXCEEDED") {
				return integration.Wrap(integration.CodeUpstreamRateLimit, err, "the org's API request allocation is exhausted")
			}
			if ae.has("API_DISABLED_FOR_ORG") {
				return integration.Wrap(integration.CodeCredentialRejected, err, "the API is disabled for the org or the integration user lacks API Enabled")
			}
			return integration.Wrap(integration.CodeCredentialRejected, err, "the integration user may not query %s (HTTP 403)", subject)
		case http.StatusNotFound:
			return integration.Wrap(integration.CodeResourceNotVisible, err, "%s was not found or is not visible to the integration user (HTTP 404)", subject)
		case http.StatusTooManyRequests:
			return integration.Wrap(integration.CodeUpstreamRateLimit, err, "rate limited by Salesforce")
		case http.StatusBadRequest:
			if ae.has("INVALID_TYPE") || ae.has("INVALID_FIELD") || ae.has("MALFORMED_QUERY") {
				return integration.Wrap(integration.CodeUnsupported, err, "%s cannot be queried in this org (%s)", subject, strings.Join(ae.codes, ","))
			}
		}
		return integration.Wrap(integration.CodeUpstreamError, err, "Salesforce returned HTTP %d for %s", ae.status, subject)
	}
	return httpx.Classify(err)
}

// apiStatus is the HTTP status of an apiError, or 0 for any other error.
func apiStatus(err error) int {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.status
	}
	return 0
}

// isQueryShapeError reports a 400 that means the object or field does not
// exist in this org.
func isQueryShapeError(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.status == http.StatusBadRequest && (ae.has("INVALID_TYPE") || ae.has("INVALID_FIELD"))
}

// queryResponse is the envelope of /query.
type queryResponse struct {
	TotalSize      json.Number       `json:"totalSize"`
	Done           bool              `json:"done"`
	NextRecordsURL string            `json:"nextRecordsUrl"`
	Records        []json.RawMessage `json:"records"`
}

// query runs one SOQL statement as GET /services/data/{v}/query?q=... and
// returns every record, following nextRecordsUrl a bounded number of times.
// The statement must have been assembled only from validated parts.
func (c *Connection) query(ctx context.Context, soql string) ([]json.RawMessage, error) {
	var records []json.RawMessage
	path := "/services/data/" + c.version + "/query"
	q := url.Values{"q": {soql}}
	for page := 0; ; page++ {
		if page >= maxQueryPages {
			return nil, integration.Errorf(integration.CodeUpstreamError, "query returned more than %d pages", maxQueryPages)
		}
		var qr queryResponse
		if err := c.get(ctx, path, q, &qr); err != nil {
			return nil, err
		}
		records = append(records, qr.Records...)
		if qr.Done || qr.NextRecordsURL == "" {
			return records, nil
		}
		// UNVERIFIED: nextRecordsUrl is a path such as
		// /services/data/v66.0/query/01gxx-2000 on the same instance.
		if !strings.HasPrefix(qr.NextRecordsURL, "/services/data/") {
			return nil, integration.Errorf(integration.CodeUpstreamError, "unexpected nextRecordsUrl shape")
		}
		path, q = qr.NextRecordsURL, nil
	}
}

// queryInto is query with the records decoded into T.
func queryInto[T any](ctx context.Context, c *Connection, soql string) ([]T, error) {
	raw, err := c.query(ctx, soql)
	if err != nil {
		return nil, err
	}
	out := make([]T, 0, len(raw))
	for _, r := range raw {
		var v T
		if err := json.Unmarshal(r, &v); err != nil {
			return nil, integration.Wrap(integration.CodeUpstreamError, err, "a query record could not be decoded")
		}
		out = append(out, v)
	}
	return out, nil
}

// permissionFields returns the PermissionsXxx field names of PermissionSet
// from its describe, cached for an hour.
func (c *Connection) permissionFields(ctx context.Context) (map[string]bool, error) {
	return c.desc.Do(ctx, struct{}{}, func(ctx context.Context) (map[string]bool, time.Duration, error) {
		var desc struct {
			Fields []struct {
				Name string `json:"name"`
			} `json:"fields"`
		}
		// UNVERIFIED: the describe lists one boolean field per system or app
		// permission, named PermissionsXxx.
		if err := c.get(ctx, "/services/data/"+c.version+"/sobjects/PermissionSet/describe", nil, &desc); err != nil {
			return nil, 0, classify(err, "the PermissionSet describe")
		}
		fields := map[string]bool{}
		for _, f := range desc.Fields {
			if permNameRe.MatchString(f.Name) {
				fields[f.Name] = true
			}
		}
		if len(fields) == 0 {
			return nil, 0, integration.Errorf(integration.CodeUpstreamError, "the PermissionSet describe listed no PermissionsXxx fields")
		}
		return fields, describeTTL, nil
	})
}

// --- identity ---------------------------------------------------------------

type userRow struct {
	ID                   string `json:"Id"`
	IsActive             bool   `json:"IsActive"`
	Username             string `json:"Username"`
	Email                string `json:"Email"`
	FederationIdentifier string `json:"FederationIdentifier"`
	UserType             string `json:"UserType"`
	Name                 string `json:"Name"`
}

const (
	attrActive   = "active"
	attrFrozen   = "frozen"
	attrUsername = "username"
	attrUserType = "user_type"
)

// ResolveIdentity finds the User row whose match_field equals the email.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	if c.matchField == matchFederationID {
		if err := validateText(u.Email); err != nil {
			return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user: %v", err)
		}
	} else if err := validateEmail(u.Email); err != nil {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user: %v", err)
	}
	row, err := c.lookupUser(ctx, u.Email)
	if err != nil {
		return integration.Identity{}, err
	}
	if err := validateID(row.ID); err != nil {
		return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "the User row carries no valid Id")
	}
	frozen, err := c.frozenState(ctx, row.ID)
	if err != nil {
		return integration.Identity{}, err
	}
	id := integration.Identity{
		ID:      row.ID,
		Display: row.Username,
		Attrs: map[string]string{
			attrActive:   fmt.Sprint(row.IsActive),
			attrFrozen:   frozen,
			attrUsername: row.Username,
			attrUserType: row.UserType,
		},
	}
	return id, nil
}

const (
	// exactUserLimit bounds a lookup by Username. UNVERIFIED: Salesforce
	// keeps Username unique per org, so a second row means the org is not
	// what hallpass assumes and the lookup is ambiguous.
	exactUserLimit = 2
	// matchUserLimit bounds the match_field lookup. Reaching it means the
	// rows are a subset of the matches, so no rule may pick from them.
	matchUserLimit = 4
)

// queryUsers runs one User lookup by field, which is one of the match_field
// constants; the literal is escaped.
func (c *Connection) queryUsers(ctx context.Context, field, value string, limit int) ([]userRow, error) {
	soql := "SELECT Id, IsActive, Username, Email, FederationIdentifier, UserType, Name FROM User WHERE " +
		field + " = '" + soqlString(value) + "' LIMIT " + fmt.Sprint(limit)
	rows, err := queryInto[userRow](ctx, c, soql)
	if err != nil {
		return nil, classify(err, "User")
	}
	return rows, nil
}

// lookupUser finds the one User row for the value. Under match_field Email
// an exact Username lookup runs first (Username is unique, and a person's
// primary account usually carries the address as its Username); only when
// that finds nothing is the Email match tried. Username is matched exactly;
// FederationIdentifier is matched with the same bound and must be unique.
func (c *Connection) lookupUser(ctx context.Context, value string) (userRow, error) {
	if c.matchField == matchEmail || c.matchField == matchUsername {
		rows, err := c.queryUsers(ctx, matchUsername, value, exactUserLimit)
		if err != nil {
			return userRow{}, err
		}
		switch {
		case len(rows) == 1:
			return rows[0], nil
		case len(rows) > 1:
			return userRow{}, integration.UserAmbiguous("%d Salesforce users have Username %q", len(rows), value)
		case c.matchField == matchUsername:
			return userRow{}, integration.UserNotFound("no Salesforce user has Username %q", value)
		}
	}
	rows, err := c.queryUsers(ctx, c.matchField, value, matchUserLimit)
	if err != nil {
		return userRow{}, err
	}
	return pickUser(rows, value, c.matchField, matchUserLimit)
}

// pickUser chooses one row of a match_field lookup. Email is not unique in
// Salesforce: several users (a person plus their community or sandbox-cloned
// accounts) can share one address, so a single active Standard user wins
// among two or three rows; when the rows hit the query limit they are only a
// subset of the matches and nothing may be picked from them. Any other
// multiplicity is ambiguous.
func pickUser(rows []userRow, value, matchField string, limit int) (userRow, error) {
	switch len(rows) {
	case 0:
		return userRow{}, integration.UserNotFound("no Salesforce user has %s %q", matchField, value)
	case 1:
		return rows[0], nil
	}
	if len(rows) >= limit {
		return userRow{}, integration.UserAmbiguous("at least %d Salesforce users have %s %q; set match_field: FederationIdentifier (or Username) to disambiguate", len(rows), matchField, value)
	}
	if matchField == matchEmail {
		var std []userRow
		for _, r := range rows {
			// UNVERIFIED: UserType "Standard" is the value for full licence
			// users, as opposed to portal, guest and community types.
			if r.IsActive && r.UserType == "Standard" {
				std = append(std, r)
			}
		}
		if len(std) == 1 {
			return std[0], nil
		}
	}
	return userRow{}, integration.UserAmbiguous("%d Salesforce users have %s %q; set match_field: FederationIdentifier (or Username) to disambiguate", len(rows), matchField, value)
}

// Values of the frozen identity attribute.
const (
	frozenTrue    = "true"
	frozenFalse   = "false"
	frozenUnknown = "unknown" // UserLogin is not queryable in this org
)

// frozenNotDetected is the probe warning and the reason recorded when
// UserLogin cannot be queried.
const frozenNotDetected = "frozen users are not detected: UserLogin not queryable"

// frozenState reads UserLogin.IsFrozen and returns frozenTrue, frozenFalse
// or, where the org or the integration user cannot query UserLogin,
// frozenUnknown. A user whose frozen state is unknown is still allowed; the
// probe reports the gap.
func (c *Connection) frozenState(ctx context.Context, userID string) (string, error) {
	// UNVERIFIED: UserLogin exposes IsFrozen per user and is queryable by
	// the integration user; where the object or field is missing the query
	// fails with INVALID_TYPE or INVALID_FIELD and freezing is not modelled.
	rows, err := queryInto[struct {
		IsFrozen bool `json:"IsFrozen"`
	}](ctx, c, "SELECT IsFrozen FROM UserLogin WHERE UserId = '"+userID+"'")
	if err != nil {
		if isQueryShapeError(err) {
			c.logger.Debug("salesforce: " + frozenNotDetected)
			return frozenUnknown, nil
		}
		return "", classify(err, "UserLogin")
	}
	for _, r := range rows {
		if r.IsFrozen {
			return frozenTrue, nil
		}
	}
	return frozenFalse, nil
}

// --- checks -----------------------------------------------------------------

// Check answers one question with one to three SOQL queries.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	act, ok := actions[r.ActionName]
	if !ok {
		if r.ActionName == "record.create" {
			return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "records are created per object: use object.create with object:<ApiName>")
		}
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "unknown action %q", r.ActionName)
	}
	t, err := parseTarget(act, r.Resource)
	if err != nil {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%v", err)
	}
	uid := r.Identity.ID
	if err := validateID(uid); err != nil {
		return integration.Decision{}, integration.Errorf(integration.CodeUpstreamError, "the resolved identity is not a Salesforce Id")
	}
	who := r.Identity.Display
	if who == "" {
		who = uid
	}
	if r.Identity.Attr(attrActive) != "true" {
		return integration.Denied("user %s is inactive", who), nil
	}
	if r.Identity.Attr(attrFrozen) == frozenTrue {
		return integration.Denied("user %s is frozen", who), nil
	}
	switch act.kind {
	case kindRecord:
		return c.checkRecord(ctx, act, uid, who, t)
	case kindObject:
		return c.checkObject(ctx, act, uid, who, t)
	case kindField:
		return c.checkField(ctx, act, uid, who, t)
	case kindSystem:
		return c.checkSystem(ctx, uid, who, t)
	case kindPermSet:
		return c.checkPermSet(ctx, uid, who, t)
	default:
		return c.checkUser(r, uid, who, t)
	}
}

type recordAccessRow struct {
	RecordID          string `json:"RecordId"`
	HasReadAccess     bool   `json:"HasReadAccess"`
	HasEditAccess     bool   `json:"HasEditAccess"`
	HasDeleteAccess   bool   `json:"HasDeleteAccess"`
	HasTransferAccess bool   `json:"HasTransferAccess"`
	HasAllAccess      bool   `json:"HasAllAccess"`
	MaxAccessLevel    string `json:"MaxAccessLevel"`
}

func (r recordAccessRow) column(name string) bool {
	switch name {
	case "HasReadAccess":
		return r.HasReadAccess
	case "HasEditAccess":
		return r.HasEditAccess
	case "HasDeleteAccess":
		return r.HasDeleteAccess
	case "HasTransferAccess":
		return r.HasTransferAccess
	case "HasAllAccess":
		return r.HasAllAccess
	}
	return false
}

// accessLevels are the values UserRecordAccess.MaxAccessLevel can take.
// UNVERIFIED: the picklist is None, Read, Edit, Delete, Transfer, All.
var accessLevels = map[string]bool{"None": true, "Read": true, "Edit": true, "Delete": true, "Transfer": true, "All": true}

// accessLevel renders MaxAccessLevel for a decision text: only a known
// picklist value is copied; anything else (an upstream surprise) is "unknown".
func accessLevel(v string) string {
	if accessLevels[v] {
		return v
	}
	return "unknown"
}

// checkRecord asks UserRecordAccess, which must be filtered by exactly one
// UserId and one RecordId.
func (c *Connection) checkRecord(ctx context.Context, act action, uid, who string, t target) (integration.Decision, error) {
	soql := "SELECT RecordId, HasReadAccess, HasEditAccess, HasDeleteAccess, HasTransferAccess, HasAllAccess, MaxAccessLevel " +
		"FROM UserRecordAccess WHERE UserId = '" + uid + "' AND RecordId = '" + t.recordID + "'"
	rows, err := queryInto[recordAccessRow](ctx, c, soql)
	if err != nil {
		return integration.Decision{}, classify(err, "UserRecordAccess for record "+t.recordID)
	}
	if len(rows) == 0 {
		// UNVERIFIED: UserRecordAccess reportedly returns no row for a
		// record the running (integration) user cannot see, and for
		// objects without sharing settings.
		return integration.UnknownDecision(integration.CodeResourceNotVisible,
			"record %s is not visible to the integration user, or its object has no sharing settings", t.recordID), nil
	}
	row := rows[0]
	level := accessLevel(row.MaxAccessLevel)
	if row.column(act.column) {
		return integration.Allowed("%s has %s on record %s (max access level %s)", who, act.column, t.recordID, level), nil
	}
	return integration.Denied("%s lacks %s on record %s (max access level %s)", who, act.column, t.recordID, level), nil
}

// parentRef is the Parent relationship of a permission row.
type parentRef struct {
	IsOwnedByProfile bool   `json:"IsOwnedByProfile"`
	Name             string `json:"Name"`
}

func (p parentRef) label() string {
	kindName := "permission set"
	if p.IsOwnedByProfile {
		kindName = "profile"
	}
	if p.Name == "" {
		return kindName
	}
	return kindName + " " + p.Name
}

type objectPermRow struct {
	PermissionsRead             bool      `json:"PermissionsRead"`
	PermissionsCreate           bool      `json:"PermissionsCreate"`
	PermissionsEdit             bool      `json:"PermissionsEdit"`
	PermissionsDelete           bool      `json:"PermissionsDelete"`
	PermissionsViewAllRecords   bool      `json:"PermissionsViewAllRecords"`
	PermissionsModifyAllRecords bool      `json:"PermissionsModifyAllRecords"`
	Parent                      parentRef `json:"Parent"`
}

func (r objectPermRow) column(name string) bool {
	switch name {
	case "PermissionsRead":
		return r.PermissionsRead
	case "PermissionsCreate":
		return r.PermissionsCreate
	case "PermissionsEdit":
		return r.PermissionsEdit
	case "PermissionsDelete":
		return r.PermissionsDelete
	case "PermissionsViewAllRecords":
		return r.PermissionsViewAllRecords
	case "PermissionsModifyAllRecords":
		return r.PermissionsModifyAllRecords
	}
	return false
}

// soqlDateTime renders t as a SOQL datetime literal (unquoted,
// YYYY-MM-DDThh:mm:ssZ).
func soqlDateTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// assignedSets is the sub-select of every permission set in force for the
// user right now. Profiles appear as permission sets with IsOwnedByProfile
// = true and permission set groups as their aggregate set. Session-based
// permission sets (HasActivationRequired) only apply during an activated
// session and time-bound assignments end at ExpirationDate, so both are
// excluded. uid is regex-validated; now is rendered by hallpass.
//
// UNVERIFIED: PermissionSet.HasActivationRequired and
// PermissionSetAssignment.ExpirationDate are filterable through the
// assignment sub-select; orgs on API versions before ExpirationDate existed
// answer INVALID_FIELD, which assignedSetsLoose handles.
func assignedSets(uid string, now time.Time) string {
	return "(SELECT PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId = '" + uid + "'" +
		" AND PermissionSet.HasActivationRequired = false" +
		" AND (ExpirationDate = null OR ExpirationDate > " + soqlDateTime(now) + "))"
}

// assignedSetsLoose is assignedSets without the activation and expiry
// filter: every assignment, including ones not in force. An allow derived
// from it is not trustworthy.
func assignedSetsLoose(uid string) string {
	return "(SELECT PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId = '" + uid + "')"
}

// looseText is the unknown answer for an allow that only the unfiltered
// sub-select produced.
const looseText = "could not exclude session-based or expired assignments"

// queryAssigned runs build(sub) with the filtered assignment sub-select. When
// the org rejects the filter fields (INVALID_FIELD), it runs once more with
// the loose sub-select and reports loose = true, in which case the caller
// may still deny (the loose set is a superset) but must not allow.
func queryAssigned[T any](ctx context.Context, c *Connection, uid string, build func(sub string) string) (rows []T, loose bool, err error) {
	rows, err = queryInto[T](ctx, c, build(assignedSets(uid, c.now())))
	if err == nil {
		return rows, false, nil
	}
	var ae *apiError
	if apiStatus(err) != http.StatusBadRequest || !errors.As(err, &ae) || !ae.has("INVALID_FIELD") {
		return nil, false, err
	}
	c.logger.Debug("salesforce: the assignment filter was rejected (INVALID_FIELD); retrying without it, allows become unknown")
	rows, err = queryInto[T](ctx, c, build(assignedSetsLoose(uid)))
	if err != nil {
		return nil, false, err
	}
	return rows, true, nil
}

// objectExists confirms the sObject through its describe, cached for an
// hour. A 404 is reported as an unknown decision; any other failure is an
// error.
func (c *Connection) objectExists(ctx context.Context, name string) (integration.Decision, bool, error) {
	exists, err := c.objects.Do(ctx, name, func(ctx context.Context) (bool, time.Duration, error) {
		// UNVERIFIED: the describe of an object that does not exist, or that
		// the integration user cannot see at all, is a 404 NOT_FOUND.
		err := c.get(ctx, "/services/data/"+c.version+"/sobjects/"+httpx.PathEscape(name)+"/describe", nil, nil)
		switch {
		case err == nil:
			return true, describeTTL, nil
		case apiStatus(err) == http.StatusNotFound:
			return false, describeTTL, nil
		default:
			return false, 0, classify(err, "the describe of "+name)
		}
	})
	if err != nil {
		return integration.Decision{}, false, err
	}
	if !exists {
		return integration.UnknownDecision(integration.CodeResourceNotVisible, "object %s does not exist or is not visible to the integration user", name), false, nil
	}
	return integration.Decision{}, true, nil
}

// checkObject ORs ObjectPermissions across the user's profile and
// permission sets. Zero rows is a deny once the object is known to exist:
// nothing grants it.
func (c *Connection) checkObject(ctx context.Context, act action, uid, who string, t target) (integration.Decision, error) {
	if d, stale, err := c.groupsRecalculated(ctx, uid); err != nil {
		return integration.Decision{}, err
	} else if stale {
		return d, nil
	}
	// UNVERIFIED: profile object permissions are rows whose Parent is the
	// profile's owned permission set, and a permission set group's rows
	// reflect its muting sets through the aggregate permission set.
	rows, loose, err := queryAssigned[objectPermRow](ctx, c, uid, func(sub string) string {
		return "SELECT PermissionsRead, PermissionsCreate, PermissionsEdit, PermissionsDelete, PermissionsViewAllRecords, PermissionsModifyAllRecords, Parent.IsOwnedByProfile, Parent.Name " +
			"FROM ObjectPermissions WHERE SobjectType = '" + t.object + "' AND ParentId IN " + sub
	})
	if err != nil {
		return integration.Decision{}, classify(err, "ObjectPermissions for "+t.object)
	}
	for _, r := range rows {
		if r.column(act.column) {
			if loose {
				return integration.Unsupported("%s may have %s on %s through %s, but hallpass %s", who, act.column, t.object, r.Parent.label(), looseText), nil
			}
			return integration.Allowed("%s has %s on %s through %s", who, act.column, t.object, r.Parent.label()), nil
		}
	}
	if len(rows) == 0 {
		if d, ok, err := c.objectExists(ctx, t.object); err != nil {
			return integration.Decision{}, err
		} else if !ok {
			return d, nil
		}
		return integration.Denied("no profile or permission set assigned to %s grants any access to %s", who, t.object), nil
	}
	return integration.Denied("%s lacks %s on %s across %d assigned profile and permission sets", who, act.column, t.object, len(rows)), nil
}

type fieldPermRow struct {
	PermissionsRead bool      `json:"PermissionsRead"`
	PermissionsEdit bool      `json:"PermissionsEdit"`
	Parent          parentRef `json:"Parent"`
}

// checkField ORs FieldPermissions. Zero rows is unknown: required and
// system fields have no FieldPermissions rows at all.
func (c *Connection) checkField(ctx context.Context, act action, uid, who string, t target) (integration.Decision, error) {
	if d, stale, err := c.groupsRecalculated(ctx, uid); err != nil {
		return integration.Decision{}, err
	} else if stale {
		return d, nil
	}
	full := t.object + "." + t.field
	rows, loose, err := queryAssigned[fieldPermRow](ctx, c, uid, func(sub string) string {
		return "SELECT PermissionsRead, PermissionsEdit, Parent.IsOwnedByProfile, Parent.Name FROM FieldPermissions " +
			"WHERE SobjectType = '" + t.object + "' AND Field = '" + full + "' AND ParentId IN " + sub
	})
	if err != nil {
		return integration.Decision{}, classify(err, "FieldPermissions for "+full)
	}
	for _, r := range rows {
		granted := r.PermissionsRead
		if act.column == "PermissionsEdit" {
			granted = r.PermissionsEdit
		}
		if granted {
			if loose {
				return integration.Unsupported("%s may have %s on %s through %s, but hallpass %s", who, act.column, full, r.Parent.label(), looseText), nil
			}
			return integration.Allowed("%s has %s on %s through %s", who, act.column, full, r.Parent.label()), nil
		}
	}
	if len(rows) == 0 {
		// UNVERIFIED: required, system and some standard fields have no
		// FieldPermissions rows; the absence is not a refusal.
		return integration.Unsupported("no FieldPermissions rows for %s: required or system fields carry none, so field-level security cannot be read", full), nil
	}
	return integration.Denied("%s lacks %s on %s across %d assigned profile and permission sets", who, act.column, full, len(rows)), nil
}

// checkSystem asks whether any assigned permission set (profile included)
// has the PermissionsXxx boolean set. The field name reaches the query only
// after the describe confirms it exists.
func (c *Connection) checkSystem(ctx context.Context, uid, who string, t target) (integration.Decision, error) {
	fields, err := c.permissionFields(ctx)
	if err != nil {
		return integration.Decision{}, err
	}
	if !fields[t.perm] {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "%s is not a permission field of PermissionSet in this org", t.perm)
	}
	if d, stale, err := c.groupsRecalculated(ctx, uid); err != nil {
		return integration.Decision{}, err
	} else if stale {
		return d, nil
	}
	type permSetRow struct {
		Name             string `json:"Name"`
		IsOwnedByProfile bool   `json:"IsOwnedByProfile"`
	}
	rows, loose, err := queryAssigned[permSetRow](ctx, c, uid, func(sub string) string {
		return "SELECT Id, Name, IsOwnedByProfile FROM PermissionSet WHERE " + t.perm + " = true AND Id IN " + sub
	})
	if err != nil {
		return integration.Decision{}, classify(err, "PermissionSet."+t.perm)
	}
	if len(rows) > 0 {
		p := parentRef{IsOwnedByProfile: rows[0].IsOwnedByProfile, Name: rows[0].Name}
		if loose {
			return integration.Unsupported("%s may hold %s through %s, but hallpass %s", who, t.perm, p.label(), looseText), nil
		}
		return integration.Allowed("%s holds %s through %s", who, t.perm, p.label()), nil
	}
	return integration.Denied("no profile or permission set assigned to %s has %s", who, t.perm), nil
}

// checkPermSet asks whether the user is assigned the permission set by API
// name. A managed package's set is permset:<ns>__<Name> and is matched on
// NamespacePrefix too; an unprefixed name matches only sets without one.
func (c *Connection) checkPermSet(ctx context.Context, uid, who string, t target) (integration.Decision, error) {
	// UNVERIFIED: PermissionSet.NamespacePrefix is null for local sets and
	// filterable through the PermissionSet relationship of the assignment.
	ns := "PermissionSet.NamespacePrefix = null"
	if t.permSetNS != "" {
		ns = "PermissionSet.NamespacePrefix = '" + t.permSetNS + "'"
	}
	soql := "SELECT Id FROM PermissionSetAssignment WHERE AssigneeId = '" + uid + "' AND PermissionSet.Name = '" + t.permSet + "' AND " + ns
	rows, err := c.query(ctx, soql)
	if err != nil {
		return integration.Decision{}, classify(err, "PermissionSetAssignment for "+t.permSetFull())
	}
	if len(rows) > 0 {
		return integration.Allowed("%s is assigned permission set %s", who, t.permSetFull()), nil
	}
	return integration.Denied("%s is not assigned permission set %s", who, t.permSetFull()), nil
}

// checkUser answers user.active from the resolved identity; an inactive or
// frozen user was already denied before dispatch.
func (c *Connection) checkUser(r integration.CheckRequest, uid, who string, t target) (integration.Decision, error) {
	switch {
	case t.recordID != "" && !strings.EqualFold(t.recordID, uid):
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "record:%s is not the user's own Id %s; user.active answers about the requesting user", t.recordID, uid)
	case t.email != "" && !strings.EqualFold(t.email, r.User.Email):
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "user:%s is not the requesting user; user.active answers about the requesting user", t.email)
	}
	if r.Identity.Attr(attrFrozen) == frozenUnknown {
		return integration.Allowed("user %s is active (%s)", who, frozenNotDetected), nil
	}
	return integration.Allowed("user %s is active and not frozen", who), nil
}

// groupsRecalculated checks that every permission set group assigned to
// the user has Status Updated. A group mid-recalculation would make the
// aggregate permission set stale, so the answer is unknown until it is.
func (c *Connection) groupsRecalculated(ctx context.Context, uid string) (integration.Decision, bool, error) {
	// UNVERIFIED: PermissionSetAssignment.PermissionSetGroupId is set on
	// assignments made through a group, and PermissionSetGroup.Status is
	// "Updated" once the aggregate set reflects its members and mutings.
	asg, err := queryInto[struct {
		PermissionSetGroupID string `json:"PermissionSetGroupId"`
	}](ctx, c, "SELECT PermissionSetGroupId FROM PermissionSetAssignment WHERE AssigneeId = '"+uid+"' AND PermissionSetGroupId != null")
	if err != nil {
		if isQueryShapeError(err) {
			c.logger.Debug("salesforce: PermissionSetGroup not queryable; group status is not checked")
			return integration.Decision{}, false, nil
		}
		return integration.Decision{}, false, classify(err, "PermissionSetAssignment")
	}
	var ids []string
	seen := map[string]bool{}
	for _, a := range asg {
		if a.PermissionSetGroupID == "" || seen[a.PermissionSetGroupID] {
			continue
		}
		if err := validateID(a.PermissionSetGroupID); err != nil {
			return integration.Decision{}, false, integration.Errorf(integration.CodeUpstreamError, "a PermissionSetGroupId is not a Salesforce Id")
		}
		seen[a.PermissionSetGroupID] = true
		ids = append(ids, a.PermissionSetGroupID)
	}
	if len(ids) == 0 {
		return integration.Decision{}, false, nil
	}
	groups, err := queryInto[struct {
		ID            string `json:"Id"`
		DeveloperName string `json:"DeveloperName"`
		Status        string `json:"Status"`
	}](ctx, c, "SELECT Id, DeveloperName, Status FROM PermissionSetGroup WHERE Id IN ("+soqlIDList(ids)+")")
	if err != nil {
		return integration.Decision{}, false, classify(err, "PermissionSetGroup")
	}
	var stale []string
	for _, g := range groups {
		if g.Status != "Updated" {
			name := g.DeveloperName
			if name == "" {
				name = g.ID
			}
			stale = append(stale, name)
		}
	}
	if len(stale) > 0 {
		return integration.Unsupported("permission set group %s not yet recalculated; retry once its status is Updated", strings.Join(stale, ", ")), true, nil
	}
	return integration.Decision{}, false, nil
}

// --- probe ------------------------------------------------------------------

// Probe mints a token, reads the org's API limits, confirms the integration
// user exists and fetches the PermissionSet describe.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	if _, err := c.tokens.Get(ctx); err != nil {
		return integration.ProbeResult{}, authx.ClassifyTokenError(err)
	}
	var res integration.ProbeResult
	// UNVERIFIED: /limits reports DailyApiRequests with Max and Remaining.
	var limits map[string]struct {
		Max       json.Number `json:"Max"`
		Remaining json.Number `json:"Remaining"`
	}
	if err := c.get(ctx, "/services/data/"+c.version+"/limits", nil, &limits); err != nil {
		return integration.ProbeResult{}, classify(err, "/limits")
	}
	summary := "authenticated against " + c.apiBase() + " with API " + c.version
	if l, ok := limits["DailyApiRequests"]; ok {
		max, _ := l.Max.Int64()
		rem, _ := l.Remaining.Int64()
		summary += fmt.Sprintf("; %d of %d daily API requests remaining", rem, max)
		if max > 0 && rem*100 < max*lowLimitPercent {
			res.Warnings = append(res.Warnings, fmt.Sprintf("under %d%% of the daily API request allocation remains (%d of %d); every check costs one to three requests", lowLimitPercent, rem, max))
		}
	}
	selfID := ""
	if c.username != "" {
		rows, err := queryInto[userRow](ctx, c, "SELECT Id, Username, IsActive FROM User WHERE Username = '"+soqlString(c.username)+"'")
		if err != nil {
			return integration.ProbeResult{}, classify(err, "User")
		}
		switch {
		case len(rows) == 0:
			res.Warnings = append(res.Warnings, "no User row has Username "+c.username+"; the integration user cannot be confirmed")
		case !rows[0].IsActive:
			res.Warnings = append(res.Warnings, "the integration user "+c.username+" is inactive")
		default:
			summary += " as " + rows[0].Username
		}
		if len(rows) > 0 && validateID(rows[0].ID) == nil {
			selfID = rows[0].ID
		}
	}
	// The frozen check is tried on the integration user itself, so an org
	// where UserLogin is not queryable is reported here rather than silently
	// answering allow for frozen users.
	if selfID != "" {
		if state, err := c.frozenState(ctx, selfID); err != nil {
			return integration.ProbeResult{}, err
		} else if state == frozenUnknown {
			res.Warnings = append(res.Warnings, frozenNotDetected)
		}
	} else {
		// UNVERIFIED: without a known user Id (client_credentials, or the
		// integration user not found) UserLogin is probed unfiltered.
		if _, err := c.query(ctx, "SELECT IsFrozen FROM UserLogin LIMIT 1"); err != nil {
			if !isQueryShapeError(err) {
				return integration.ProbeResult{}, classify(err, "UserLogin")
			}
			res.Warnings = append(res.Warnings, frozenNotDetected)
		}
	}
	fields, err := c.permissionFields(ctx)
	if err != nil {
		return integration.ProbeResult{}, err
	}
	summary += fmt.Sprintf("; %d permission fields known", len(fields))
	res.Summary = summary
	res.Warnings = append(res.Warnings,
		"UserRecordAccess reportedly omits records the integration user cannot see: record.* answers are unknown for those unless the user has View All on the object (or View All Data); confirm in a Developer Edition org before relying on record checks")
	return res, nil
}
