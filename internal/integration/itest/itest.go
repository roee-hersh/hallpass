// Package itest is the shared test harness for integrations: a fake
// upstream over TLS with recorded calls and failure injection, Deps wired
// to it, and a canary check that fails a test when a secret shows up in logs.
package itest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/secret"
)

// Canary is the substring every test secret must contain. Any log line that
// contains it fails the test.
const Canary = "CANARY-SECRET-"

// Call is one recorded upstream request.
type Call struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   []byte
}

// JSON decodes the recorded body.
func (c Call) JSON(t testing.TB, v any) {
	t.Helper()
	if err := json.Unmarshal(c.Body, v); err != nil {
		t.Fatalf("decode body of %s %s: %v\n%s", c.Method, c.Path, err, c.Body)
	}
}

// Failure is an injected upstream failure mode.
type Failure string

// Failure modes every integration is tested against.
const (
	FailNone         Failure = ""
	FailServerError  Failure = "500"
	FailRateLimited  Failure = "429"
	FailTimeout      Failure = "timeout"
	FailUnauthorized Failure = "401"
)

// Server is the fake upstream.
type Server struct {
	*httptest.Server
	t      testing.TB
	mu     sync.Mutex
	routes []route
	calls  []Call
	fail   Failure
	// Unmatched is called for requests no route matches (default 404).
	Unmatched http.HandlerFunc
}

type route struct {
	method string
	path   string // exact, or prefix when ending in "*"
	h      http.HandlerFunc
}

// NewServer starts a TLS server. It is closed when the test ends.
func NewServer(t testing.TB) *Server {
	s := &Server{t: t}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.calls = append(s.calls, Call{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), Body: body})
	fail := s.fail
	routes := append([]route(nil), s.routes...)
	s.mu.Unlock()

	switch fail {
	case FailServerError:
		w.WriteHeader(500)
		return
	case FailRateLimited:
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(429)
		return
	case FailUnauthorized:
		w.WriteHeader(401)
		return
	case FailTimeout:
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	for i := len(routes) - 1; i >= 0; i-- {
		rt := routes[i]
		if rt.method != "" && rt.method != r.Method {
			continue
		}
		if strings.HasSuffix(rt.path, "*") {
			if !strings.HasPrefix(r.URL.Path, strings.TrimSuffix(rt.path, "*")) {
				continue
			}
		} else if rt.path != r.URL.Path {
			continue
		}
		rt.h(w, r)
		return
	}
	if s.Unmatched != nil {
		s.Unmatched(w, r)
		return
	}
	w.WriteHeader(404)
	_, _ = w.Write([]byte(`{"message":"no route in test server for ` + r.Method + ` ` + r.URL.Path + `"}`))
}

// Handle registers a handler. Later registrations win. A path ending in "*"
// matches by prefix. An empty method matches any.
func (s *Server) Handle(method, path string, h http.HandlerFunc) {
	s.mu.Lock()
	s.routes = append(s.routes, route{method: method, path: path, h: h})
	s.mu.Unlock()
}

// JSON registers a static JSON response.
func (s *Server) JSON(method, path string, status int, body any) {
	var b []byte
	switch v := body.(type) {
	case string:
		b = []byte(v)
	case []byte:
		b = v
	default:
		var err error
		b, err = json.Marshal(body)
		if err != nil {
			s.t.Fatal(err)
		}
	}
	s.Handle(method, path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(b)
	})
}

// Fail sets the failure mode for every following request.
func (s *Server) Fail(f Failure) {
	s.mu.Lock()
	s.fail = f
	s.mu.Unlock()
}

// Calls returns the recorded requests.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// Reset forgets recorded calls.
func (s *Server) Reset() {
	s.mu.Lock()
	s.calls = nil
	s.mu.Unlock()
}

// LastCall returns the most recent request or fails the test.
func (s *Server) LastCall() Call {
	calls := s.Calls()
	if len(calls) == 0 {
		s.t.Fatal("no upstream calls recorded")
	}
	return calls[len(calls)-1]
}

// Logs captures slog output for canary checks.
type Logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *Logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// String returns everything logged so far.
func (l *Logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Deps returns Deps whose HTTP clients trust the server certificate and
// whose logger writes to the returned Logs at debug level. AssertNoCanary
// is registered as a cleanup.
func Deps(t testing.TB, srv *Server) (integration.Deps, *Logs) {
	t.Helper()
	logs := &Logs{}
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	d := integration.Deps{
		Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:    time.Now,
		Connection: func(id string) (integration.Connection, error) {
			t.Fatalf("Connection(%q) called but no connections wired", id)
			return nil, nil
		},
		HTTPClient: func(s *integration.Settings) (*http.Client, error) {
			return httpx.NewHTTPClient(httpx.Options{RootCAs: pool, Timeout: s.EffectiveTimeout(), TLSServerName: s.TLSServerName})
		},
	}
	t.Cleanup(func() { AssertNoCanary(t, logs.String()) })
	return d, logs
}

// AssertNoCanary fails if text contains the canary.
func AssertNoCanary(t testing.TB, text string) {
	t.Helper()
	if strings.Contains(text, Canary) {
		i := strings.Index(text, Canary)
		lo, hi := i-120, i+60
		if lo < 0 {
			lo = 0
		}
		if hi > len(text) {
			hi = len(text)
		}
		t.Errorf("a secret leaked into the logs: ...%s...", text[lo:hi])
	}
}

// Settings builds settings with a short timeout for tests. Secrets are
// given as references; use Literal for values.
func Settings(id, integ string, values map[string]string, secrets map[string]secret.Secret) *integration.Settings {
	s := integration.NewSettings(id, integ, values, secrets)
	s.Timeout = 2 * time.Second
	return s
}

// Literal is a test secret carrying the canary.
func Literal(suffix string) secret.Secret { return secret.Literal(Canary + suffix) }

// Check runs ResolveIdentity then Check the way the engine does and returns
// the decision, converting errors with integration.ToDecision.
func Check(t testing.TB, c integration.Connection, integ integration.Integration, u integration.User, action, resource string) integration.Decision {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	id, err := c.ResolveIdentity(ctx, u)
	if err != nil {
		return integration.ToDecision(err)
	}
	res, err := catalog.ParseResource(resource)
	if err != nil {
		t.Fatalf("resource %q: %v", resource, err)
	}
	act, ok := integration.FindAction(integ, action)
	if !ok {
		t.Fatalf("integration %s has no action %q", integ.Name(), action)
	}
	d, err := c.Check(ctx, integration.CheckRequest{User: u, Identity: id, Action: act, ActionName: action, Resource: res})
	if err != nil {
		return integration.ToDecision(err)
	}
	d.Outcome = integration.OutcomeOf(d.Code)
	return d
}

// ExpectCode fails unless the decision has the code.
func ExpectCode(t testing.TB, d integration.Decision, code integration.Code) {
	t.Helper()
	if d.Code != code {
		t.Errorf("decision = %s (%s), want code %s", d.Code, d.Text, code)
	}
	if d.Outcome != integration.OutcomeOf(d.Code) {
		t.Errorf("outcome %s does not match code %s", d.Outcome, d.Code)
	}
}

// FailureCases runs check under every injected failure mode and asserts the
// matching unknown code. The check must make at least one upstream call.
func FailureCases(t *testing.T, srv *Server, check func() integration.Decision) {
	t.Helper()
	cases := []struct {
		f    Failure
		code integration.Code
	}{
		{FailServerError, integration.CodeUpstreamError},
		{FailRateLimited, integration.CodeUpstreamRateLimit},
		{FailUnauthorized, integration.CodeCredentialRejected},
		{FailTimeout, integration.CodeUpstreamTimeout},
	}
	for _, c := range cases {
		t.Run(string(c.f), func(t *testing.T) {
			srv.Fail(c.f)
			defer srv.Fail(FailNone)
			d := check()
			if d.Outcome != integration.Unknown {
				t.Fatalf("failure %s: outcome %s, want unknown (%s: %s)", c.f, d.Outcome, d.Code, d.Text)
			}
			if d.Code != c.code {
				t.Errorf("failure %s: code %s, want %s (%s)", c.f, d.Code, c.code, d.Text)
			}
		})
	}
}
