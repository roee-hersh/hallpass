// Package googleworkspace checks Directory, Drive, Calendar, Gmail and
// Groups facts through the Google Workspace APIs.
//
// hallpass authenticates as a service account with domain-wide delegation.
// Directory calls impersonate an admin (admin_email) with read-only scopes;
// Drive, Calendar and Gmail calls impersonate the user being asked about,
// so Google itself evaluates the user's access. One token is minted per
// (impersonated user, scope) and cached. Nothing is persisted.
package googleworkspace

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/roee-hersh/hallpass/internal/authx"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const (
	defaultTokenURL = "https://oauth2.googleapis.com/token"
	defaultAPI      = "https://www.googleapis.com"
	defaultMetadata = "http://metadata.google.internal"
	defaultIAMCreds = "https://iamcredentials.googleapis.com"

	scopeDirectoryUser  = "https://www.googleapis.com/auth/admin.directory.user.readonly"
	scopeDirectoryGroup = "https://www.googleapis.com/auth/admin.directory.group.member.readonly"
	scopeDrive          = "https://www.googleapis.com/auth/drive.metadata.readonly"
	scopeCalendar       = "https://www.googleapis.com/auth/calendar.calendarlist.readonly"
	scopeGmailSettings  = "https://www.googleapis.com/auth/gmail.settings.basic"

	modeKey     = "key"
	modeKeyless = "keyless"

	assertionTTL = time.Hour
	// maxSources bounds the per-(sub, scope) token cache.
	maxSources = 500
)

// Integration is the googleworkspace product.
type Integration struct{}

// Name is "googleworkspace".
func (Integration) Name() string { return "googleworkspace" }

// Fields of a googleworkspace connection.
func (Integration) Fields() []integration.Field {
	return []integration.Field{
		integration.CredentialField(false, "service-account key JSON (file:); required in auth_mode key"),
		{Name: "admin_email", Required: true, Validate: validateEmail,
			Description: "Workspace admin impersonated for Directory calls; give it a custom role with Users > Read and Groups > Read only"},
		{Name: "customer_id", Default: "my_customer", Validate: validateCustomer,
			Description: "Workspace customer id; my_customer means the service account's own"},
		{Name: "auth_mode", Default: modeKey, Enum: []string{modeKey, modeKeyless},
			Description: "key: sign with the key JSON; keyless: sign with the IAM Credentials API from a GCE/GKE identity"},
		{Name: "service_account_email", Validate: validateEmail,
			Description: "service account to sign as in auth_mode keyless"},
		{Name: "enable_gmail_settings", Default: "false", Enum: []string{"true", "false"},
			Description: "evaluate mail.send_as and mail.delegate_access with the gmail.settings.basic scope, which can also write settings"},
		{Name: "token_url", Default: defaultTokenURL, Validate: integration.ValidateHTTPSURL,
			Description: "OAuth token endpoint"},
		{Name: "api_url", Default: defaultAPI, Validate: integration.ValidateHTTPSURL,
			Description: "Google APIs endpoint; the Admin SDK is addressed under it as /admin/directory/v1"},
		{Name: "metadata_url", Default: defaultMetadata, Validate: validateHTTPURL,
			Description: "GCE metadata server, auth_mode keyless only"},
		{Name: "iamcredentials_url", Default: defaultIAMCreds, Validate: integration.ValidateHTTPSURL,
			Description: "IAM Credentials API endpoint, auth_mode keyless only"},
	}
}

var customerRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func validateEmail(v string) error {
	if v == "" || emailRe.MatchString(v) {
		return nil
	}
	return errors.New("must be an email address")
}

func validateCustomer(v string) error {
	if v == "" || customerRe.MatchString(v) {
		return nil
	}
	return errors.New("must be a customer id or my_customer")
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
		admin:        strings.ToLower(s.Get("admin_email")),
		customer:     s.Get("customer_id"),
		mode:         s.Get("auth_mode"),
		saEmail:      strings.ToLower(s.Get("service_account_email")),
		gmail:        s.Bool("enable_gmail_settings", false),
		tokenURL:     strings.TrimRight(s.Get("token_url"), "/"),
		metadataURL:  strings.TrimRight(s.Get("metadata_url"), "/"),
		iamCredsURL:  strings.TrimRight(s.Get("iamcredentials_url"), "/"),
		now:          d.Now,
		sources:      map[sourceKey]*authx.TokenSource{},
		tokenURLFrom: "config",
	}
	if c.admin == "" || !emailRe.MatchString(c.admin) {
		return nil, errors.New("admin_email is required and must be an email address")
	}
	if c.customer == "" {
		c.customer = "my_customer"
	}
	if !customerRe.MatchString(c.customer) {
		return nil, errors.New("customer_id must be a customer id or my_customer")
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
		if c.saEmail == "" || !emailRe.MatchString(c.saEmail) {
			return nil, errors.New("service_account_email is required in auth_mode keyless")
		}
	default:
		return nil, fmt.Errorf("auth_mode %q must be key or keyless", c.mode)
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
	if c.iamCredsURL == "" {
		c.iamCredsURL = defaultIAMCreds
	}
	api := strings.TrimRight(s.Get("api_url"), "/")
	if api == "" {
		api = defaultAPI
	}
	c.plain = &httpx.Client{HTTP: hc, Logger: d.Logger}
	c.api = &httpx.Client{HTTP: hc, Base: api, Logger: d.Logger}
	c.metaTokens = &authx.TokenSource{Fetch: c.fetchMetadataToken, Now: c.now}
	return c, nil
}

// Connection is one Workspace customer reached through one service account.
type Connection struct {
	settings    *integration.Settings
	admin       string
	customer    string
	mode        string
	saEmail     string
	gmail       bool
	tokenURL    string
	metadataURL string
	iamCredsURL string
	now         func() time.Time

	// tokenURLFrom is "config" or "key" (use the key's token_uri).
	tokenURLFrom string

	plain *httpx.Client // token, metadata and IAM Credentials endpoints
	api   *httpx.Client // Google APIs, per-call bearer

	mu      sync.Mutex
	sources map[sourceKey]*authx.TokenSource
	order   []sourceKey

	metaTokens *authx.TokenSource
}

// --- authentication ---------------------------------------------------------

type sourceKey struct{ sub, scope string }

// source returns the cached token source for one (sub, scope).
func (c *Connection) source(sub, scope string) *authx.TokenSource {
	k := sourceKey{strings.ToLower(sub), scope}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ts, ok := c.sources[k]; ok {
		return ts
	}
	ts := &authx.TokenSource{Now: c.now, Fetch: func(ctx context.Context) (authx.Token, error) {
		return c.mint(ctx, k.sub, k.scope)
	}}
	c.sources[k] = ts
	c.order = append(c.order, k)
	for len(c.order) > maxSources {
		delete(c.sources, c.order[0])
		c.order = c.order[1:]
	}
	return ts
}

// saKey is the service-account key JSON.
type saKey struct {
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
	TokenURI     string `json:"token_uri"`
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

// claims of the JWT bearer assertion: exactly one scope, impersonating sub.
type claims struct {
	Iss   string `json:"iss"`
	Scope string `json:"scope"`
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	Sub   string `json:"sub"`
}

// mint obtains an access token for (sub, scope).
func (c *Connection) mint(ctx context.Context, sub, scope string) (authx.Token, error) {
	var iss, tokenURL string
	var sign func(ctx context.Context, payload []byte) (string, error)
	switch c.mode {
	case modeKeyless:
		iss, tokenURL = c.saEmail, c.tokenURL
		if tokenURL == "" {
			tokenURL = defaultTokenURL
		}
		sign = c.signWithIAM
	default:
		k, key, err := c.loadKey()
		if err != nil {
			return authx.Token{}, err
		}
		iss, tokenURL = k.ClientEmail, c.tokenURL
		if c.tokenURLFrom == "key" && k.TokenURI != "" {
			if err := integration.ValidateHTTPSURL(k.TokenURI); err != nil {
				return authx.Token{}, integration.Wrap(integration.CodeCredentialRejected, err, "the key's token_uri is not an https URL")
			}
			tokenURL = k.TokenURI
		}
		if tokenURL == "" {
			tokenURL = defaultTokenURL
		}
		sign = func(_ context.Context, payload []byte) (string, error) {
			return authx.SignJWT(key, authx.Header{Alg: authx.RS256, Kid: k.PrivateKeyID}, payload)
		}
	}
	now := c.now()
	payload, err := json.Marshal(claims{Iss: iss, Scope: scope, Aud: tokenURL, Iat: authx.Unix(now), Exp: authx.Unix(now.Add(assertionTTL)), Sub: sub})
	if err != nil {
		return authx.Token{}, err
	}
	fetch := authx.JWTBearer(c.plain, tokenURL, func(ctx context.Context) (string, error) { return sign(ctx, payload) }, nil)
	return fetch(ctx)
}

// fetchMetadataToken reads the attached service account's token from the
// GCE metadata server.
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

// signWithIAM signs the assertion with the IAM Credentials API.
func (c *Connection) signWithIAM(ctx context.Context, payload []byte) (string, error) {
	meta, err := c.metaTokens.Get(ctx)
	if err != nil {
		return "", err
	}
	// UNVERIFIED: signJwt takes {"payload": "<claims JSON>"} and answers
	// {"keyId", "signedJwt"}; the metadata token needs
	// roles/iam.serviceAccountTokenCreator on the signing service account.
	var out struct {
		SignedJWT string `json:"signedJwt"`
	}
	idem := true
	resp, err := c.plain.Do(ctx, &httpx.Request{Method: http.MethodPost,
		Path:       c.iamCredsURL + "/v1/projects/-/serviceAccounts/" + httpx.PathEscape(c.saEmail) + ":signJwt",
		JSON:       map[string]string{"payload": string(payload)},
		Header:     http.Header{"Authorization": {"Bearer " + meta}},
		Idempotent: &idem})
	if err != nil {
		switch httpx.Status(err) {
		case 401:
			c.metaTokens.Invalidate()
			return "", integration.Wrap(integration.CodeCredentialRejected, err, "the IAM Credentials API rejected the metadata token")
		case 403, 404:
			return "", integration.Wrap(integration.CodeCredentialRejected, err, "the IAM Credentials API refused signJwt; the runtime identity needs roles/iam.serviceAccountTokenCreator on %s", c.saEmail)
		}
		return "", httpx.Classify(err)
	}
	if err := resp.JSON(&out); err != nil || out.SignedJWT == "" {
		return "", integration.Errorf(integration.CodeUpstreamError, "signJwt returned no signedJwt")
	}
	return out.SignedJWT, nil
}

// tokenError classifies a minting failure. invalid_grant for the admin
// means delegation is misconfigured; for a user it means Google would not
// let hallpass act as that user, which is not a decision about the action.
func (c *Connection) tokenError(err error, sub string) *integration.Error {
	var te *authx.TokenError
	if errors.As(err, &te) {
		switch {
		case te.Status == 429:
			return integration.Wrap(integration.CodeUpstreamRateLimit, err, "the token endpoint rate limited hallpass")
		case te.Status >= 500:
			return integration.Wrap(integration.CodeUpstreamError, err, "the token endpoint failed (HTTP %d)", te.Status)
		case te.Code == "invalid_grant" || te.Code == "unauthorized_client":
			if strings.EqualFold(sub, c.admin) {
				return integration.Wrap(integration.CodeCredentialRejected, err, "could not act as admin_email: domain-wide delegation is missing the scope or admin_email is invalid (%s)", te.Code)
			}
			return integration.Wrap(integration.CodeUnsupported, err, "could not act as the user: suspended, or the delegation scope is missing (%s)", te.Code)
		}
	}
	return authx.ClassifyTokenError(err)
}

// --- API transport ----------------------------------------------------------

var reasonRe = regexp.MustCompile(`"reason"\s*:\s*"([A-Za-z]+)"`)

// reason extracts errors[].reason from a Google error body snippet. The
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

// call performs one API request as sub with one scope. A 401 invalidates
// the token and retries once. The returned error is the raw httpx error so
// callers can branch on 404/400; classify maps everything else.
func (c *Connection) call(ctx context.Context, sub, scope string, req *httpx.Request) (*httpx.Response, error) {
	ts := c.source(sub, scope)
	attempt := func() (*httpx.Response, error) {
		tok, err := ts.Get(ctx)
		if err != nil {
			return nil, c.tokenError(err, sub)
		}
		r := *req
		r.Header = req.Header.Clone()
		if r.Header == nil {
			r.Header = http.Header{}
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		return c.api.Do(ctx, &r)
	}
	resp, err := attempt()
	if httpx.Status(err) == 401 {
		ts.Invalidate()
		resp, err = attempt()
	}
	return resp, err
}

// classify maps an API error to an integration error.
func classify(err error) *integration.Error {
	if httpx.Status(err) == 403 {
		switch reason(err) {
		case "rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded", "dailyLimitExceeded":
			return integration.Wrap(integration.CodeUpstreamRateLimit, err, "rate limited by Google")
		case "forbidden", "insufficientPermissions", "accessNotConfigured":
			return integration.Wrap(integration.CodeCredentialRejected, err, "Google refused the call: the scope is not delegated, the API is not enabled, or the admin role lacks the privilege (%s)", reason(err))
		}
		return integration.Wrap(integration.CodeCredentialRejected, err, "Google refused the call (HTTP 403)")
	}
	return httpx.Classify(err)
}

func (c *Connection) getJSON(ctx context.Context, sub, scope, path string, q url.Values, out any) error {
	resp, err := c.call(ctx, sub, scope, &httpx.Request{Method: http.MethodGet, Path: path, Query: q})
	if err != nil {
		return err
	}
	if out != nil {
		if err := resp.JSON(out); err != nil {
			return integration.Wrap(integration.CodeUpstreamError, err, "Google returned an unreadable response")
		}
	}
	return nil
}

// --- identity ---------------------------------------------------------------

// directoryUser is the subset of the Directory user resource hallpass reads.
type directoryUser struct {
	ID           string `json:"id"`
	PrimaryEmail string `json:"primaryEmail"`
	Suspended    bool   `json:"suspended"`
	Archived     bool   `json:"archived"`
	Name         struct {
		FullName string `json:"fullName"`
	} `json:"name"`
}

// ResolveIdentity looks the email up in the Directory as the admin. The
// primary email becomes the identity, and the sub for user-scoped calls.
func (c *Connection) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	email := strings.ToLower(strings.TrimSpace(u.Email))
	if !emailRe.MatchString(email) {
		return integration.Identity{}, integration.Errorf(integration.CodeInvalidRequest, "user email %q is not an address", email)
	}
	var du directoryUser
	q := url.Values{"projection": {"basic"}, "viewType": {"admin_view"}}
	err := c.getJSON(ctx, c.admin, scopeDirectoryUser, "/admin/directory/v1/users/"+httpx.PathEscape(email), q, &du)
	if err != nil {
		if httpx.Status(err) == 404 {
			return integration.Identity{}, integration.UserNotFound("no Workspace account for %s (aliases resolve; external accounts do not)", email)
		}
		return integration.Identity{}, classify(err)
	}
	primary := strings.ToLower(du.PrimaryEmail)
	if !emailRe.MatchString(primary) {
		return integration.Identity{}, integration.Errorf(integration.CodeUpstreamError, "the Directory returned a user without a primary email")
	}
	return integration.Identity{
		ID:      primary,
		Display: primary,
		Attrs: map[string]string{
			"id":        du.ID,
			"suspended": fmt.Sprint(du.Suspended),
			"archived":  fmt.Sprint(du.Archived),
		},
		Native: du,
	}, nil
}

// --- checks -----------------------------------------------------------------

// Check answers one question.
func (c *Connection) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	id, err := parseRef(r.ActionName, r.Resource)
	if err != nil {
		return integration.Decision{}, err
	}
	user := strings.ToLower(r.Identity.ID)
	if !emailRe.MatchString(user) {
		return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "identity is not a Workspace primary email")
	}
	if r.Identity.Attr("suspended") == "true" {
		return integration.Denied("%s is suspended", user), nil
	}
	if r.Identity.Attr("archived") == "true" {
		return integration.Denied("%s is archived", user), nil
	}
	switch {
	case r.ActionName == "user.active":
		if id != user && id != strings.ToLower(r.User.Email) {
			return integration.Unsupported("user.active is evaluated for the caller's own account only; %s is another account", id), nil
		}
		return integration.Allowed("%s is active", user), nil
	case strings.HasPrefix(r.ActionName, "drive."):
		return c.checkDrive(ctx, r.ActionName, user, id)
	case strings.HasPrefix(r.ActionName, "calendar."):
		return c.checkCalendar(ctx, r.ActionName, user, id)
	case r.ActionName == "mail.send_as":
		return c.checkSendAs(ctx, user, id)
	case r.ActionName == "mail.delegate_access":
		return c.checkDelegate(ctx, user, id)
	case r.ActionName == "group.member":
		return c.checkGroup(ctx, user, id)
	}
	return integration.Decision{}, integration.Errorf(integration.CodeInvalidRequest, "unknown action %q", r.ActionName)
}

// driveFile is what the files.get call returns.
type driveFile struct {
	Capabilities map[string]*bool `json:"capabilities"`
	Trashed      *bool            `json:"trashed"`
}

const capabilityFields = "capabilities(canDownload,canEdit,canComment,canShare,canTrash,canDelete,canRename,canCopy,canAddChildren,canListChildren),trashed"

func (c *Connection) checkDrive(ctx context.Context, action, user, fileID string) (integration.Decision, error) {
	var f driveFile
	q := url.Values{"supportsAllDrives": {"true"}, "fields": {capabilityFields}}
	err := c.getJSON(ctx, user, scopeDrive, "/drive/v3/files/"+httpx.PathEscape(fileID), q, &f)
	if err != nil {
		if httpx.Status(err) == 404 {
			return integration.Denied("%s has no access to file %s, or the file does not exist: Drive does not distinguish", user, fileID), nil
		}
		return integration.Decision{}, classify(err)
	}
	suffix := ""
	if f.Trashed != nil && *f.Trashed {
		suffix = " (the file is in the trash)"
	}
	capName := actionList[actionIndex[action]].capability
	if capName == "" {
		return integration.Allowed("%s can see file %s%s", user, fileID, suffix), nil
	}
	v, ok := f.Capabilities[capName]
	if !ok || v == nil {
		return integration.Unsupported("Drive did not report %s for file %s", capName, fileID), nil
	}
	if *v {
		return integration.Allowed("%s has %s on file %s%s", user, capName, fileID, suffix), nil
	}
	return integration.Denied("%s lacks %s on file %s%s", user, capName, fileID, suffix), nil
}

// accessRank orders calendarList accessRole values.
var accessRank = map[string]int{
	"freeBusyReader":             1,
	"reader":                     2,
	"writerWithoutPrivateAccess": 3,
	"writer":                     4,
	"owner":                      5,
}

func (c *Connection) checkCalendar(ctx context.Context, action, user, calID string) (integration.Decision, error) {
	role := "owner"
	if calID != "primary" && !strings.EqualFold(calID, user) {
		var cl struct {
			AccessRole string `json:"accessRole"`
		}
		err := c.getJSON(ctx, user, scopeCalendar, "/calendar/v3/users/me/calendarList/"+httpx.PathEscape(calID), nil, &cl)
		if err != nil {
			if httpx.Status(err) == 404 {
				return integration.Unsupported("calendar %s is not in %s's calendar list; ACL access may still exist", calID, user), nil
			}
			return integration.Decision{}, classify(err)
		}
		role = cl.AccessRole
	}
	rank, known := accessRank[role]
	if !known {
		return integration.Unsupported("calendar %s reports access role %q, which hallpass does not model", calID, role), nil
	}
	var need int
	switch action {
	case "calendar.read":
		need = accessRank["reader"]
	case "calendar.event.write":
		// UNVERIFIED: writerWithoutPrivateAccess is assumed to allow creating
		// and changing non-private events.
		need = accessRank["writerWithoutPrivateAccess"]
	default: // calendar.share
		need = accessRank["owner"]
	}
	if rank >= need {
		return integration.Allowed("%s has role %s on calendar %s", user, role, calID), nil
	}
	return integration.Denied("%s has role %s on calendar %s, which does not allow %s", user, role, calID, strings.TrimPrefix(action, "calendar.")), nil
}

func (c *Connection) checkSendAs(ctx context.Context, user, mailbox string) (integration.Decision, error) {
	if mailbox == user {
		// UNVERIFIED: isMailboxSetup is not consulted; an active account
		// without a Gmail licence would be a false allow.
		return integration.Allowed("%s may send from their own mailbox", user), nil
	}
	if !c.gmail {
		return integration.Unsupported("send-as addresses are read with the gmail.settings.basic scope; set enable_gmail_settings to evaluate mail.send_as for %s", mailbox), nil
	}
	var out struct {
		SendAs []struct {
			SendAsEmail        string `json:"sendAsEmail"`
			VerificationStatus string `json:"verificationStatus"`
		} `json:"sendAs"`
	}
	if err := c.getJSON(ctx, user, scopeGmailSettings, "/gmail/v1/users/me/settings/sendAs", nil, &out); err != nil {
		return integration.Decision{}, classify(err)
	}
	for _, s := range out.SendAs {
		if strings.EqualFold(s.SendAsEmail, mailbox) {
			if s.VerificationStatus == "accepted" || s.VerificationStatus == "" {
				return integration.Allowed("%s has %s as a verified send-as address", user, mailbox), nil
			}
			return integration.Denied("%s has %s as a send-as address but it is not verified (%s)", user, mailbox, s.VerificationStatus), nil
		}
	}
	return integration.Denied("%s has no send-as address %s", user, mailbox), nil
}

func (c *Connection) checkDelegate(ctx context.Context, user, mailbox string) (integration.Decision, error) {
	if mailbox == user {
		return integration.Allowed("%s owns mailbox %s", user, mailbox), nil
	}
	if !c.gmail {
		return integration.Unsupported("delegates are read with the gmail.settings.basic scope; set enable_gmail_settings to evaluate mail.delegate_access for %s", mailbox), nil
	}
	var out struct {
		Delegates []struct {
			DelegateEmail      string `json:"delegateEmail"`
			VerificationStatus string `json:"verificationStatus"`
		} `json:"delegates"`
	}
	// The list is read as the mailbox owner, so the mailbox must be a
	// Workspace account hallpass may impersonate.
	if err := c.getJSON(ctx, mailbox, scopeGmailSettings, "/gmail/v1/users/me/settings/delegates", nil, &out); err != nil {
		var ie *integration.Error
		if errors.As(err, &ie) && ie.Code == integration.CodeUnsupported {
			return integration.Unsupported("could not act as mailbox %s to read its delegates: not a Workspace account, suspended, or the scope is missing", mailbox), nil
		}
		if httpx.Status(err) == 404 {
			return integration.Unsupported("mailbox %s has no Gmail settings; it may not be a Gmail mailbox", mailbox), nil
		}
		return integration.Decision{}, classify(err)
	}
	for _, d := range out.Delegates {
		if strings.EqualFold(d.DelegateEmail, user) {
			if d.VerificationStatus == "accepted" {
				return integration.Allowed("%s is an accepted delegate of mailbox %s", user, mailbox), nil
			}
			return integration.Denied("%s is a delegate of mailbox %s but the delegation is %s", user, mailbox, d.VerificationStatus), nil
		}
	}
	return integration.Denied("%s is not a delegate of mailbox %s", user, mailbox), nil
}

func (c *Connection) checkGroup(ctx context.Context, user, group string) (integration.Decision, error) {
	var out struct {
		IsMember *bool `json:"isMember"`
	}
	path := "/admin/directory/v1/groups/" + httpx.PathEscape(group) + "/hasMember/" + httpx.PathEscape(user)
	if err := c.getJSON(ctx, c.admin, scopeDirectoryGroup, path, nil, &out); err != nil {
		switch httpx.Status(err) {
		case 400, 404:
			return integration.Unsupported("group %s is unknown or outside the domain, so membership of %s cannot be checked", group, user), nil
		}
		return integration.Decision{}, classify(err)
	}
	if out.IsMember == nil {
		return integration.Unsupported("the Directory did not report membership of %s in %s", user, group), nil
	}
	if *out.IsMember {
		return integration.Allowed("%s is a member of group %s (directly or through nested groups)", user, group), nil
	}
	return integration.Denied("%s is not a member of group %s", user, group), nil
}

// --- probe ------------------------------------------------------------------

// Probe mints the admin Directory token, lists one user, and mints a token
// per user scope as the admin to prove each scope is delegated.
func (c *Connection) Probe(ctx context.Context) (integration.ProbeResult, error) {
	q := url.Values{"customer": {c.customer}, "maxResults": {"1"}}
	var users struct {
		Users []directoryUser `json:"users"`
	}
	if err := c.getJSON(ctx, c.admin, scopeDirectoryUser, "/admin/directory/v1/users", q, &users); err != nil {
		if httpx.Status(err) == 404 || httpx.Status(err) == 400 {
			return integration.ProbeResult{}, integration.Wrap(integration.CodeInvalidRequest, err, "the Directory rejected customer_id %s", c.customer)
		}
		return integration.ProbeResult{}, classify(err)
	}
	who := c.saEmail
	if c.mode == modeKey {
		if k, _, err := c.loadKey(); err == nil {
			who = k.ClientEmail
		}
	}
	res := integration.ProbeResult{Summary: fmt.Sprintf("service account %s reads the directory as %s (customer %s)", who, c.admin, c.customer)}
	if len(users.Users) == 0 {
		res.Warnings = append(res.Warnings, "the Directory listed no users; check customer_id and the admin's role")
	}
	scopes := []string{scopeDirectoryGroup, scopeDrive, scopeCalendar}
	if c.gmail {
		scopes = append(scopes, scopeGmailSettings)
		res.Warnings = append(res.Warnings, "enable_gmail_settings is on: gmail.settings.basic has no read-only variant and can change users' Gmail settings")
	}
	for _, sc := range scopes {
		if _, err := c.source(c.admin, sc).Get(ctx); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("scope %s could not be minted as %s: add it to the domain-wide delegation allowlist (%s)", sc, c.admin, c.tokenError(err, c.admin).Code))
		}
	}
	res.Warnings = append(res.Warnings, "domain-wide delegation lets this credential act as any user within the allowlisted scopes; keep the key tightly held")
	return res, nil
}
