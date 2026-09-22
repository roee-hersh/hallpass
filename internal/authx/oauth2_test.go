package authx

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integration/itest"
)

func TestClientCredentialsAndAssertion(t *testing.T) {
	srv := itest.NewServer(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv.Handle("POST", "/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch {
		case r.Form.Get("grant_type") == "client_credentials" && r.Form.Get("client_secret") == itest.Canary+"secret":
			json.NewEncoder(w).Encode(map[string]any{"access_token": itest.Canary + "access", "expires_in": 3600, "token_type": "Bearer"})
		case r.Form.Get("grant_type") == "client_credentials" && r.Form.Get("client_assertion") != "":
			parts := strings.Split(r.Form.Get("client_assertion"), ".")
			if len(parts) != 3 {
				w.WriteHeader(400)
				return
			}
			var claims StandardClaims
			DecodeJWTClaims(r.Form.Get("client_assertion"), &claims)
			if claims.Iss != "app" || claims.Aud != srv.URL+"/token" {
				w.WriteHeader(400)
				w.Write([]byte(`{"error":"invalid_client","error_description":"bad assertion"}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "assert-tok", "expires_in": "1800"})
		case r.Form.Get("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer":
			json.NewEncoder(w).Encode(map[string]any{"access_token": "bearer-tok"})
		default:
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"invalid_client","error_description":"` + itest.Canary + `bad"}`))
		}
	})
	deps, logs := itest.Deps(t, srv)
	hc, _ := deps.HTTPClient(itest.Settings("x", "x", nil, nil))
	c := &httpx.Client{HTTP: hc, Base: srv.URL, Logger: deps.Logger}
	ctx := context.Background()

	fetch := ClientCredentials(c, srv.URL+"/token", "cid", func(context.Context) (string, error) { return itest.Canary + "secret", nil }, "api://x/.default")
	tok, err := fetch(ctx)
	if err != nil || tok.Value != itest.Canary+"access" || time.Until(tok.Expiry) < 59*time.Minute {
		t.Fatalf("%+v %v", tok, err)
	}
	call := srv.LastCall()
	if call.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || call.Query.Get("client_secret") != "" {
		t.Errorf("form encoding: %+v", call.Header)
	}

	fetch = ClientCredentials(c, srv.URL+"/token", "cid", func(context.Context) (string, error) { return "wrong", nil }, "")
	_, err = fetch(ctx)
	if ie := ClassifyTokenError(err); ie.Code != integration.CodeCredentialRejected {
		t.Fatalf("wrong secret -> %v", ie)
	}
	if strings.Contains(err.Error(), itest.Canary) {
		t.Error("token error leaked the description containing the canary")
	}

	fetch = ClientAssertion(c, srv.URL+"/token", "app", func(context.Context) (string, error) {
		return SignJWT(key, Header{Alg: PS256, X5tS: "thumb"}, StandardClaims{Iss: "app", Sub: "app", Aud: srv.URL + "/token", Exp: time.Now().Add(5 * time.Minute).Unix()})
	}, "")
	tok, err = fetch(ctx)
	if err != nil || tok.Value != "assert-tok" || time.Until(tok.Expiry) < 29*time.Minute {
		t.Fatalf("assertion: %+v %v", tok, err)
	}

	fetch = JWTBearer(c, srv.URL+"/token", func(context.Context) (string, error) { return "a.b.c", nil }, url.Values{"extra": {"1"}})
	tok, err = fetch(ctx)
	if err != nil || tok.Value != "bearer-tok" || !tok.Expiry.IsZero() {
		t.Fatalf("bearer: %+v %v", tok, err)
	}
	if !strings.Contains(string(srv.LastCall().Body), "extra=1") {
		t.Error("extra form values")
	}
	srv.Fail(itest.FailServerError)
	_, err = fetch(ctx)
	if ClassifyTokenError(err).Code != integration.CodeUpstreamError {
		t.Errorf("500 -> %v", ClassifyTokenError(err))
	}
	srv.Fail(itest.FailNone)
	_ = logs
}

// TestFetchTokenJSONAndClock: FetchToken posts a JSON body when asked,
// decodes the standard response, computes the expiry from the injected
// clock, and keeps error_description out of the error message.
func TestFetchTokenJSONAndClock(t *testing.T) {
	srv := itest.NewServer(t)
	srv.Handle("POST", "/json-token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(415)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["grant_type"] != "client_credentials" || body["audience"] != "api.example" {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"invalid_request"}`))
			return
		}
		switch body["client_secret"] {
		case itest.Canary + "secret":
			json.NewEncoder(w).Encode(map[string]any{"access_token": itest.Canary + "access", "expires_in": "3600", "token_type": "Bearer"})
		case "no-expiry":
			json.NewEncoder(w).Encode(map[string]any{"access_token": "short"})
		default:
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"invalid_client","error_description":"` + itest.Canary + `bad"}`))
		}
	})
	deps, _ := itest.Deps(t, srv)
	hc, _ := deps.HTTPClient(itest.Settings("x", "x", nil, nil))
	c := &httpx.Client{HTTP: hc, Base: srv.URL, Logger: deps.Logger}
	ctx := context.Background()
	fixed := time.Date(2031, 3, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixed }
	body := func(secret string) map[string]string {
		return map[string]string{"grant_type": "client_credentials", "client_id": "cid", "client_secret": secret, "audience": "api.example"}
	}

	tok, err := FetchToken(ctx, c, TokenRequest{URL: srv.URL + "/json-token", JSON: body(itest.Canary + "secret"), Now: clock})
	if err != nil || tok.Value != itest.Canary+"access" {
		t.Fatalf("%+v %v", tok, err)
	}
	if !tok.Expiry.Equal(fixed.Add(time.Hour)) {
		t.Errorf("expiry %v, want the injected clock plus 3600 s (%v)", tok.Expiry, fixed.Add(time.Hour))
	}
	if ct := srv.LastCall().Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type %q", ct)
	}

	tok, err = FetchToken(ctx, c, TokenRequest{URL: srv.URL + "/json-token", JSON: body("no-expiry"), Now: clock})
	if err != nil || tok.Value != "short" || !tok.Expiry.IsZero() {
		t.Errorf("no expires_in: %+v %v", tok, err)
	}

	_, err = FetchToken(ctx, c, TokenRequest{URL: srv.URL + "/json-token", JSON: body("wrong"), Now: clock})
	var te *TokenError
	if !errors.As(err, &te) || te.Status != 401 || te.Code != "invalid_client" {
		t.Fatalf("wrong secret: %v", err)
	}
	if strings.Contains(err.Error(), itest.Canary) || strings.Contains(ClassifyTokenError(err).Error(), itest.Canary) {
		t.Error("the error message carries error_description")
	}
	if te.Desc != itest.Canary+"bad" {
		t.Errorf("Desc %q", te.Desc)
	}
	if ClassifyTokenError(err).Code != integration.CodeCredentialRejected {
		t.Errorf("classified as %v", ClassifyTokenError(err))
	}

	// Exactly one body encoding.
	for _, req := range []TokenRequest{{URL: srv.URL + "/json-token"}, {URL: srv.URL + "/json-token", Form: url.Values{"a": {"b"}}, JSON: body("x")}} {
		if _, err := FetchToken(ctx, c, req); err == nil {
			t.Errorf("accepted %+v", req)
		}
	}
	if n := len(srv.Calls()); n != 3 {
		t.Errorf("%d calls, want 3: a malformed request must not reach the endpoint", n)
	}

	// The wall clock applies when no clock is injected, and to PostToken.
	srv.Handle("POST", "/form-token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "form-tok", "expires_in": 600})
	})
	before := time.Now()
	tok, err = PostToken(ctx, c, srv.URL+"/form-token", url.Values{"grant_type": {"client_credentials"}}, nil)
	if err != nil || tok.Value != "form-tok" || tok.Expiry.Before(before.Add(10*time.Minute)) || tok.Expiry.After(time.Now().Add(10*time.Minute)) {
		t.Errorf("PostToken: %+v %v", tok, err)
	}
}
