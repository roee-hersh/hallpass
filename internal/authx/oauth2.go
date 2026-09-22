package authx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// tokenResponse is the OAuth 2.0 token endpoint response.
type tokenResponse struct {
	AccessToken string          `json:"access_token"`
	TokenType   string          `json:"token_type"`
	ExpiresIn   json.RawMessage `json:"expires_in"`
	Scope       string          `json:"scope"`
	Error       string          `json:"error"`
	ErrorDesc   string          `json:"error_description"`
}

// TokenError is a token endpoint failure.
type TokenError struct {
	Status int
	Code   string // OAuth error code such as invalid_grant, invalid_client
	// Desc is error_description, truncated. Never put it in a decision text.
	Desc string
}

// Error names the status and OAuth error code only. The description is an
// upstream string that may echo request data, so it stays out of messages
// and logs; integrations that need it read Desc.
func (e *TokenError) Error() string {
	s := fmt.Sprintf("token endpoint: HTTP %d", e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	return s
}

// IsCredentialError reports whether the failure means the client credential
// itself was rejected (as opposed to a transient failure).
func (e *TokenError) IsCredentialError() bool {
	switch e.Code {
	case "invalid_client", "invalid_grant", "unauthorized_client", "invalid_request", "access_denied":
		return true
	}
	return e.Status == 400 || e.Status == 401 || e.Status == 403
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// TokenRequest is one call to a token endpoint.
type TokenRequest struct {
	// URL is the token endpoint, absolute or relative to the client's Base.
	URL string
	// Form is the URL-encoded body OAuth 2.0 specifies. JSON is a JSON body
	// for endpoints that take one instead (Atlassian). Exactly one is set.
	Form url.Values
	JSON any
	// Header holds extra request headers, such as a client Authorization.
	Header http.Header
	// Now is the clock the token's expiry is computed from (default
	// time.Now). A connection passes its injected clock so the expiry and
	// the TokenSource that checks it agree.
	Now func() time.Time
}

// FetchToken posts a token request and decodes the OAuth 2.0 token
// response, whichever body encoding the endpoint takes. A failure is a
// *TokenError (an error code or a 4xx status) or a transport error. The
// expiry is req.Now plus expires_in; a response without expires_in leaves
// it zero so the TokenSource's default TTL applies.
func FetchToken(ctx context.Context, c *httpx.Client, req TokenRequest) (Token, error) {
	if (req.Form == nil) == (req.JSON == nil) {
		return Token{}, errors.New("token request must carry exactly one of a form or a JSON body")
	}
	now := req.Now
	if now == nil {
		now = time.Now
	}
	idem := false
	resp, err := c.Do(ctx, &httpx.Request{Method: http.MethodPost, Path: req.URL, Form: req.Form, JSON: req.JSON, Header: req.Header, Idempotent: &idem, Accept4xx: true})
	if err != nil {
		return Token{}, err
	}
	var tr tokenResponse
	if len(resp.Body) > 0 {
		_ = json.Unmarshal(resp.Body, &tr)
	}
	if resp.Status >= 400 || tr.Error != "" {
		return Token{}, &TokenError{Status: resp.Status, Code: tr.Error, Desc: truncate(tr.ErrorDesc, 200)}
	}
	if tr.AccessToken == "" {
		return Token{}, errors.New("token endpoint returned no access_token")
	}
	t := Token{Value: tr.AccessToken}
	if secs := parseExpiresIn(tr.ExpiresIn); secs > 0 {
		t.Expiry = now().Add(time.Duration(secs) * time.Second)
	}
	return t, nil
}

// PostToken posts form parameters to a token endpoint and decodes the
// response with FetchToken, using the wall clock for the expiry.
func PostToken(ctx context.Context, c *httpx.Client, tokenURL string, form url.Values, header http.Header) (Token, error) {
	return FetchToken(ctx, c, TokenRequest{URL: tokenURL, Form: form, Header: header})
}

// parseExpiresIn accepts a number or a numeric string (Salesforce and some
// Microsoft endpoints send strings).
func parseExpiresIn(raw json.RawMessage) int64 {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" {
		return 0
	}
	var n int64
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int64(ch-'0')
	}
	return n
}

// ClientCredentials returns a fetch function for the OAuth 2.0 client
// credentials grant with a client secret.
func ClientCredentials(c *httpx.Client, tokenURL, clientID string, secret func(context.Context) (string, error), scope string) func(context.Context) (Token, error) {
	return func(ctx context.Context) (Token, error) {
		s, err := secret(ctx)
		if err != nil {
			return Token{}, err
		}
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {clientID},
			"client_secret": {s},
		}
		if scope != "" {
			form.Set("scope", scope)
		}
		return PostToken(ctx, c, tokenURL, form, nil)
	}
}

// ClientAssertion returns a fetch function for the client credentials grant
// authenticated with a signed JWT (RFC 7523 section 2.2). assertion builds
// the JWT at fetch time so its timestamps are fresh.
func ClientAssertion(c *httpx.Client, tokenURL, clientID string, assertion func(ctx context.Context) (string, error), scope string) func(context.Context) (Token, error) {
	return func(ctx context.Context) (Token, error) {
		a, err := assertion(ctx)
		if err != nil {
			return Token{}, err
		}
		form := url.Values{
			"grant_type":            {"client_credentials"},
			"client_id":             {clientID},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {a},
		}
		if scope != "" {
			form.Set("scope", scope)
		}
		return PostToken(ctx, c, tokenURL, form, nil)
	}
}

// JWTBearer returns a fetch function for the JWT bearer grant (RFC 7523
// section 2.1), used by Google service accounts and Salesforce.
func JWTBearer(c *httpx.Client, tokenURL string, assertion func(ctx context.Context) (string, error), extra url.Values) func(context.Context) (Token, error) {
	return func(ctx context.Context) (Token, error) {
		a, err := assertion(ctx)
		if err != nil {
			return Token{}, err
		}
		form := url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":  {a},
		}
		for k, vs := range extra {
			form[k] = vs
		}
		return PostToken(ctx, c, tokenURL, form, nil)
	}
}

// ClassifyTokenError maps a token fetch failure to an integration error:
// credential rejections become credential_rejected, everything else goes
// through httpx.Classify.
func ClassifyTokenError(err error) *integration.Error {
	var te *TokenError
	if errors.As(err, &te) {
		if te.IsCredentialError() {
			return integration.Wrap(integration.CodeCredentialRejected, err, "the token endpoint rejected hallpass's credential (%s)", te.Code)
		}
		return integration.Wrap(integration.CodeUpstreamError, err, "the token endpoint failed (HTTP %d)", te.Status)
	}
	return httpx.Classify(err)
}
