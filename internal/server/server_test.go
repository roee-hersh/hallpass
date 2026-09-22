package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/roee-hersh/hallpass/internal/engine"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/secret"
)

const key = "CANARY-SECRET-apikey"

type stubChecker struct{ last engine.Request }

func (s *stubChecker) Check(_ context.Context, req engine.Request) engine.Result {
	s.last = req
	if req.User == "a@x.com" {
		return engine.Result{Decision: integration.Allowed("ok"), Status: 200}
	}
	return engine.Result{Decision: integration.Denied("no"), Status: 200}
}

func post(t *testing.T, h http.Handler, auth, body string, ct string) (*http.Response, map[string]string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/check", strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	var out map[string]string
	b, _ := io.ReadAll(res.Body)
	_ = json.Unmarshal(b, &out)
	return res, out
}

func TestCheck(t *testing.T) {
	var logs bytes.Buffer
	c := &stubChecker{}
	h := New(c, secret.Literal(key), slog.New(slog.NewJSONHandler(&logs, nil)))

	res, out := post(t, h, "Bearer "+key, `{"user":"a@x.com","groups":["g1"],"connection":"c","action":"thing.read","resource":"thing:1"}`, "application/json")
	if res.StatusCode != 200 || out["decision"] != "allow" || out["reason"] != "allowed: ok" {
		t.Fatalf("%d %v", res.StatusCode, out)
	}
	if c.last.Groups[0] != "g1" || c.last.Connection != "c" {
		t.Fatalf("%+v", c.last)
	}
	if res.Header.Get("Content-Type") != "application/json" {
		t.Error("content type")
	}
	if strings.Contains(logs.String(), key) || strings.Contains(logs.String(), "a@x.com") {
		t.Fatalf("log leaked: %s", logs.String())
	}

	res, out = post(t, h, "Bearer "+key, `{"user":"b@x.com","connection":"c","action":"thing.read","resource":"thing:1"}`, "application/x-www-form-urlencoded")
	if res.StatusCode != 200 || out["decision"] != "deny" {
		t.Fatalf("%d %v", res.StatusCode, out)
	}
}

func TestAuth(t *testing.T) {
	h := New(&stubChecker{}, secret.Literal(key), nil)
	for _, auth := range []string{"", "Bearer wrong", "Basic abc", "Bearer " + key + "x", "Bearer " + key[:len(key)-1]} {
		res, out := post(t, h, auth, `{}`, "")
		if res.StatusCode != 401 || out["decision"] != "unknown" || !strings.HasPrefix(out["reason"], "unauthorized") {
			t.Errorf("auth %q: %d %v", auth, res.StatusCode, out)
		}
		if res.Header.Get("WWW-Authenticate") == "" {
			t.Error("missing WWW-Authenticate")
		}
	}
	res, _ := post(t, h, "bearer "+key, `{"user":"a@x.com"}`, "")
	if res.StatusCode != 200 {
		t.Errorf("case-insensitive scheme: %d", res.StatusCode)
	}
	t.Setenv("HALLPASS_TEST_KEY", "")
	h2 := New(&stubChecker{}, secret.MustParse("env:HALLPASS_TEST_KEY"), nil)
	if res, _ := post(t, h2, "Bearer ", `{}`, ""); res.StatusCode != 401 {
		t.Errorf("empty key must not authorize: %d", res.StatusCode)
	}
}

func TestBadRequests(t *testing.T) {
	h := New(&stubChecker{}, secret.Literal(key), nil)
	cases := []struct {
		body, ct string
		status   int
		reason   string
	}{
		{`{"user":1}`, "", 400, "wrong type for field user"},
		{`{"usr":"a"}`, "", 400, `unknown field "usr"`},
		{`{`, "", 400, "syntax error"},
		{``, "", 400, "empty body"},
		{`{} {}`, "", 400, "trailing data"},
		{`{"user":"` + strings.Repeat("x", MaxRequestBody) + `"}`, "", 413, "larger than"},
	}
	for _, c := range cases {
		res, out := post(t, h, "Bearer "+key, c.body, c.ct)
		if res.StatusCode != c.status || out["decision"] != "unknown" || !strings.Contains(out["reason"], c.reason) {
			t.Errorf("%.30q: %d %v", c.body, res.StatusCode, out)
		}
	}
	req := httptest.NewRequest("GET", "/check", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 405 {
		t.Errorf("GET /check = %d", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	h := New(&stubChecker{}, secret.Literal(key), nil)
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatal(rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest("POST", "/healthz", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 405 {
		t.Fatal(rec.Code)
	}
	req = httptest.NewRequest("GET", "/nope", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatal(rec.Code)
	}
}
