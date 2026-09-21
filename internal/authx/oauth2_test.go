package authx

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
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
