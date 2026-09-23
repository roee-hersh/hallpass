package authx

// Google service-account plumbing shared by the googleworkspace and
// googlecloud integrations: the key JSON, the GCE metadata token and the
// reason field of a Google API error.

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// GoogleServiceAccountKey is the part of a service-account key JSON that
// signing an assertion needs.
type GoogleServiceAccountKey struct {
	ClientEmail  string
	PrivateKeyID string
	// TokenURI is the key's token endpoint, usually
	// https://oauth2.googleapis.com/token; it may be empty.
	TokenURI string
	Key      *rsa.PrivateKey
}

var googleEmailRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+/=?^_{|}~.-]{1,64}@[A-Za-z0-9.-]{1,255}$`)

// ParseGoogleServiceAccountKey decodes a service-account key JSON. Every
// failure is a credential_rejected error whose text never quotes the key.
func ParseGoogleServiceAccountKey(raw string) (GoogleServiceAccountKey, error) {
	var k struct {
		ClientEmail  string `json:"client_email"`
		PrivateKey   string `json:"private_key"`
		PrivateKeyID string `json:"private_key_id"`
		TokenURI     string `json:"token_uri"`
	}
	if err := json.Unmarshal([]byte(raw), &k); err != nil {
		return GoogleServiceAccountKey{}, integration.Wrap(integration.CodeCredentialRejected, err, "credential is not a service-account key JSON")
	}
	if !googleEmailRe.MatchString(k.ClientEmail) || k.PrivateKey == "" {
		return GoogleServiceAccountKey{}, integration.Errorf(integration.CodeCredentialRejected, "the service-account key JSON lacks client_email or private_key")
	}
	key, err := ParseRSAPrivateKey([]byte(k.PrivateKey))
	if err != nil {
		return GoogleServiceAccountKey{}, integration.Wrap(integration.CodeCredentialRejected, err, "the service-account private_key is not a PEM RSA key")
	}
	return GoogleServiceAccountKey{ClientEmail: k.ClientEmail, PrivateKeyID: k.PrivateKeyID, TokenURI: k.TokenURI, Key: key}, nil
}

// GoogleMetadataToken reads the attached service account's access token
// from the GCE metadata server at metadataURL (http://metadata.google.internal
// in production). now is the clock the expiry is computed from.
func GoogleMetadataToken(ctx context.Context, c *httpx.Client, metadataURL string, now func() time.Time) (Token, error) {
	if now == nil {
		now = time.Now
	}
	var out struct {
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
	}
	resp, err := c.Do(ctx, &httpx.Request{Method: http.MethodGet,
		Path:   metadataURL + "/computeMetadata/v1/instance/service-accounts/default/token",
		Header: http.Header{"Metadata-Flavor": {"Google"}}})
	if err != nil {
		return Token{}, integration.Wrap(integration.CodeCredentialRejected, err, "the metadata server gave no token; auth_mode keyless needs a GCE or GKE Workload Identity")
	}
	if err := resp.JSON(&out); err != nil || out.AccessToken == "" {
		return Token{}, integration.Errorf(integration.CodeCredentialRejected, "the metadata server returned no access_token")
	}
	t := Token{Value: out.AccessToken}
	if secs := parseExpiresIn(out.ExpiresIn); secs > 0 {
		t.Expiry = now().Add(time.Duration(secs) * time.Second)
	}
	return t, nil
}

var googleReasonRe = regexp.MustCompile(`"reason"\s*:\s*"([A-Za-z_]+)"`)

// GoogleErrorReason extracts the first errors[].reason or details[].reason
// from the body snippet of a Google API error, or "" when there is none.
// Only the reason token is returned; the message is never used.
func GoogleErrorReason(err error) string {
	var se *httpx.StatusError
	if !errors.As(err, &se) {
		return ""
	}
	return GoogleReasonIn(se.Snippet)
}

// GoogleReasonIn extracts the first reason token from a Google error body.
func GoogleReasonIn(body string) string {
	if m := googleReasonRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}
