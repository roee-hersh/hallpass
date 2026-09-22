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
	// describeTTL is how long the PermissionSet describe is cached.
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

	descMu     sync.Mutex
	descFields map[string]bool
	descAt     time.Time
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
	// as the API base when it is an https URL without query or userinfo;
	// otherwise url is used.
	c.setInstanceURL(tr.InstanceURL)
	return authx.Token{Value: tr.AccessToken}, nil
}

func (c *Connection) setInstanceURL(s string) {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	inst := ""
	if u, err := url.Parse(s); err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
		inst = s
	}
	c.instMu.Lock()
	c.instanceURL = inst
	c.instMu.Unlock()
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

func decodeAPIError(resp *httpx.Response) *apiError {
	e := &apiError{status: resp.Status}
	var body []struct {
		ErrorCode string `json:"errorCode"`
	}
	if json.Unmarshal(resp.Body, &body) == nil {
		for _, b := range body {
			if b.ErrorCode != "" {
				e.codes = append(e.codes, b.ErrorCode)
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
	c.descMu.Lock()
	defer c.descMu.Unlock()
	if c.descFields != nil && c.now().Before(c.descAt.Add(describeTTL)) {
		return c.descFields, nil
	}
	var desc struct {
		Fields []struct {
			Name string `json:"name"`
		} `json:"fields"`
	}
	// UNVERIFIED: the describe lists one boolean field per system or app
	// permission, named PermissionsXxx.
	if err := c.get(ctx, "/services/data/"+c.version+"/sobjects/PermissionSet/describe", nil, &desc); err != nil {
		return nil, classify(err, "the PermissionSet describe")
	}
	fields := map[string]bool{}
	for _, f := range desc.Fields {
		if permNameRe.MatchString(f.Name) {
			fields[f.Name] = true
		}
	}
	if len(fields) == 0 {
		return nil, integration.Errorf(integration.CodeUpstreamError, "the PermissionSet describe listed no PermissionsXxx fields")
	}
	c.descFields, c.descAt = fields, c.now()
	return fields, nil
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
	// c.matchField is one of three constants; the literal is escaped.
	soql := "SELECT Id, IsActive, Username, Email, FederationIdentifier, UserType, Name FROM User WHERE " +
		c.matchField + " = '" + soqlString(u.Email) + "' LIMIT 3"
	rows, err := queryInto[userRow](ctx, c, soql)
	if err != nil {
		return integration.Identity{}, classify(err, "User")
	}
	row, err := pickUser(rows, u.Email, c.matchField)
	if err != nil {
		return integration.Identity{}, err
	}
	if err := validateID(row.ID); err != nil {
		return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "the User row carries no valid Id")
	}
	frozen, err := c.isFrozen(ctx, row.ID)
	if err != nil {
		return integration.Identity{}, err
	}
	id := integration.Identity{
		ID:      row.ID,
		Display: row.Username,
		Attrs: map[string]string{
			attrActive:   fmt.Sprint(row.IsActive),
			attrFrozen:   fmt.Sprint(frozen),
			attrUsername: row.Username,
			attrUserType: row.UserType,
		},
	}
	return id, nil
}

// pickUser chooses one row. Email is not unique in Salesforce: several
// users (a person plus their community or sandbox-cloned accounts) can share
// one address, so a row whose Username equals the email wins, then a single
// active Standard user, otherwise the mapping is ambiguous.
func pickUser(rows []userRow, email, matchField string) (userRow, error) {
	switch len(rows) {
	case 0:
		return userRow{}, integration.UserNotFound("no Salesforce user has %s %q", matchField, email)
	case 1:
		return rows[0], nil
	}
	if matchField == matchEmail {
		for _, r := range rows {
			if strings.EqualFold(r.Username, email) {
				return r, nil
			}
		}
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
	return userRow{}, integration.UserAmbiguous("%d Salesforce users have %s %q; set match_field: FederationIdentifier (or Username) to disambiguate", len(rows), matchField, email)
}

// isFrozen reads UserLogin.IsFrozen. Orgs or users without access to
// UserLogin skip the check.
func (c *Connection) isFrozen(ctx context.Context, userID string) (bool, error) {
	// UNVERIFIED: UserLogin exposes IsFrozen per user and is queryable by
	// the integration user; where the object or field is missing the query
	// fails with INVALID_TYPE or INVALID_FIELD and freezing is not modelled.
	rows, err := queryInto[struct {
		IsFrozen bool `json:"IsFrozen"`
	}](ctx, c, "SELECT IsFrozen FROM UserLogin WHERE UserId = '"+userID+"'")
	if err != nil {
		if isQueryShapeError(err) {
			c.logger.Debug("salesforce: UserLogin not queryable; frozen users are not detected")
			return false, nil
		}
		return false, classify(err, "UserLogin")
	}
	for _, r := range rows {
		if r.IsFrozen {
			return true, nil
		}
	}
	return false, nil
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
	if r.Identity.Attr(attrFrozen) == "true" {
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
	level := row.MaxAccessLevel
	if level == "" {
		level = "unknown"
	}
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

// assignedSets is the sub-select of every permission set assigned to the
// user. Profiles appear as permission sets with IsOwnedByProfile = true and
// permission set groups as their aggregate set. uid is regex-validated.
func assignedSets(uid string) string {
	return "(SELECT PermissionSetId FROM PermissionSetAssignment WHERE AssigneeId = '" + uid + "')"
}

// checkObject ORs ObjectPermissions across the user's profile and
// permission sets. Zero rows is a deny: nothing grants the object.
func (c *Connection) checkObject(ctx context.Context, act action, uid, who string, t target) (integration.Decision, error) {
	if d, stale, err := c.groupsRecalculated(ctx, uid); err != nil {
		return integration.Decision{}, err
	} else if stale {
		return d, nil
	}
	// UNVERIFIED: profile object permissions are rows whose Parent is the
	// profile's owned permission set, and a permission set group's rows
	// reflect its muting sets through the aggregate permission set.
	soql := "SELECT PermissionsRead, PermissionsCreate, PermissionsEdit, PermissionsDelete, PermissionsViewAllRecords, PermissionsModifyAllRecords, Parent.IsOwnedByProfile, Parent.Name " +
		"FROM ObjectPermissions WHERE SobjectType = '" + t.object + "' AND ParentId IN " + assignedSets(uid)
	rows, err := queryInto[objectPermRow](ctx, c, soql)
	if err != nil {
		return integration.Decision{}, classify(err, "ObjectPermissions for "+t.object)
	}
	for _, r := range rows {
		if r.column(act.column) {
			return integration.Allowed("%s has %s on %s through %s", who, act.column, t.object, r.Parent.label()), nil
		}
	}
	if len(rows) == 0 {
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
	soql := "SELECT PermissionsRead, PermissionsEdit, Parent.IsOwnedByProfile, Parent.Name FROM FieldPermissions " +
		"WHERE SobjectType = '" + t.object + "' AND Field = '" + full + "' AND ParentId IN " + assignedSets(uid)
	rows, err := queryInto[fieldPermRow](ctx, c, soql)
	if err != nil {
		return integration.Decision{}, classify(err, "FieldPermissions for "+full)
	}
	for _, r := range rows {
		granted := r.PermissionsRead
		if act.column == "PermissionsEdit" {
			granted = r.PermissionsEdit
		}
		if granted {
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
	soql := "SELECT Id, Name, IsOwnedByProfile FROM PermissionSet WHERE " + t.perm + " = true AND Id IN " + assignedSets(uid)
	rows, err := queryInto[struct {
		Name             string `json:"Name"`
		IsOwnedByProfile bool   `json:"IsOwnedByProfile"`
	}](ctx, c, soql)
	if err != nil {
		return integration.Decision{}, classify(err, "PermissionSet."+t.perm)
	}
	if len(rows) > 0 {
		p := parentRef{IsOwnedByProfile: rows[0].IsOwnedByProfile, Name: rows[0].Name}
		return integration.Allowed("%s holds %s through %s", who, t.perm, p.label()), nil
	}
	return integration.Denied("no profile or permission set assigned to %s has %s", who, t.perm), nil
}

// checkPermSet asks whether the user is assigned the permission set by name.
func (c *Connection) checkPermSet(ctx context.Context, uid, who string, t target) (integration.Decision, error) {
	soql := "SELECT Id FROM PermissionSetAssignment WHERE AssigneeId = '" + uid + "' AND PermissionSet.Name = '" + t.permSet + "'"
	rows, err := c.query(ctx, soql)
	if err != nil {
		return integration.Decision{}, classify(err, "PermissionSetAssignment for "+t.permSet)
	}
	if len(rows) > 0 {
		return integration.Allowed("%s is assigned permission set %s", who, t.permSet), nil
	}
	return integration.Denied("%s is not assigned permission set %s", who, t.permSet), nil
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
