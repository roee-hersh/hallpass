package engine

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/config"
	"github.com/roee-hersh/hallpass/internal/declog"
	"github.com/roee-hersh/hallpass/internal/evidence"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

const canary = "CANARY-SECRET-engine"

// upstream is a fake system behind an HTTP server: it answers a token
// exchange, a user lookup with an ETag, and a permission read whose answer
// the test flips. It counts the calls so the tests can see the caches work.
type upstream struct {
	srv     *httptest.Server
	allow   atomic.Bool
	users   atomic.Int32
	perms   atomic.Int32
	tokens  atomic.Int32
	etag    atomic.Value // string
	handler http.HandlerFunc
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	u.allow.Store(true)
	u.etag.Store(`"user-v1"`)
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/users/") {
			if r.Header.Get("Authorization") != "Bearer "+canary+"-token" {
				w.WriteHeader(401)
				return
			}
			u.users.Add(1)
			w.Header().Set("ETag", u.etag.Load().(string))
			w.Write([]byte(`{"id":"u1","secret":"` + canary + `-userbody"}`))
			return
		}
		switch r.URL.Path {
		case "/token":
			u.tokens.Add(1)
			w.Write([]byte(`{"access_token":"` + canary + `-token"}`))
		case "/perm":
			u.perms.Add(1)
			w.Write([]byte(`{"allow":` + map[bool]string{true: "true", false: "false"}[u.allow.Load()] + `}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// web is the integration that talks to upstream through httpx, the way a
// real integration does: a plain client for the token, an authenticated
// one for the lookups.
type web struct{}

func (web) Name() string { return "web" }
func (web) Fields() []integration.Field {
	return []integration.Field{integration.URLField(true, "base url")}
}
func (web) Actions() []catalog.Action {
	return []catalog.Action{{Name: "thing.write", Description: "write"}}
}
func (web) New(_ context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	hc, err := d.HTTPClient(s)
	if err != nil {
		return nil, err
	}
	plain := &httpx.Client{HTTP: hc, Base: s.Get("url"), Logger: d.Logger}
	api := &httpx.Client{HTTP: hc, Base: s.Get("url"), Logger: d.Logger}
	api.Auth = httpx.BearerAuth(func(ctx context.Context) (string, error) {
		var tok struct {
			AccessToken string `json:"access_token"`
		}
		if _, err := plain.PostJSON(ctx, "/token", map[string]string{"grant": canary + "-secret"}, &tok, true); err != nil {
			return "", err
		}
		return tok.AccessToken, nil
	})
	return &webConn{api: api}, nil
}

type webConn struct{ api *httpx.Client }

// lastFresh is whether the last Check ran under a fresh context, which is
// what an integration's own cache.TTL looks at.
var lastFresh atomic.Bool

func (c *webConn) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	var out struct{ ID string }
	if _, err := c.api.GetJSON(ctx, "/users/"+httpx.PathEscape(u.Email), nil, &out); err != nil {
		return integration.Identity{}, httpx.Classify(err)
	}
	return integration.Identity{ID: out.ID, Display: u.Email}, nil
}

func (c *webConn) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	lastFresh.Store(evidence.Fresh(ctx))
	var out struct{ Allow bool }
	q := url.Values{"user": {r.Identity.ID}, "token": {canary + "-query"}}
	if _, err := c.api.GetJSON(ctx, "/perm", q, &out); err != nil {
		return integration.Decision{}, httpx.Classify(err)
	}
	if out.Allow {
		return integration.Allowed("%s may write", r.Identity.Display), nil
	}
	return integration.Denied("%s may not write", r.Identity.Display), nil
}

func (c *webConn) Probe(context.Context) (integration.ProbeResult, error) {
	return integration.ProbeResult{Summary: "ok"}, nil
}

func buildWeb(t *testing.T, u *upstream, o Options) (*Engine, *strings.Builder) {
	t.Helper()
	reg := integration.NewRegistry()
	reg.Register(web{})
	cfg, err := config.Parse("t.yaml", []byte("api_key: env:K\nconnections:\n  - id: w\n    integration: web\n    url: "+u.srv.URL+"\n"), reg)
	if err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	o.DecisionLog = declog.New(&logs)
	o.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e, err := Build(context.Background(), cfg, o)
	if err != nil {
		t.Fatal(err)
	}
	return e, &logs
}

// entries returns the decision log entries written so far.
func entries(t *testing.T, logs *strings.Builder) []declog.Entry {
	t.Helper()
	var out []declog.Entry
	for _, l := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var ent declog.Entry
		if json.Unmarshal([]byte(l), &ent) == nil && ent.Decision != "" {
			out = append(out, ent)
		}
	}
	return out
}

func webReq(resource string, fresh bool) Request {
	return Request{User: "a@x.com", Connection: "w", Action: "thing.write", Resource: resource, Fresh: fresh}
}

func TestEvidenceInDecisionLog(t *testing.T) {
	u := newUpstream(t)
	e, logs := buildWeb(t, u, Options{DecisionCache: 30 * time.Second, IdentityCache: 15 * time.Minute})
	ctx := context.Background()

	r := e.Check(ctx, webReq("thing:1", false))
	if r.Decision.Outcome != integration.Allow || r.Cached {
		t.Fatalf("%+v", r)
	}
	ev := r.Decision.Evidence
	if ev == nil || len(ev.Calls()) != 2 || ev.Truncated() {
		t.Fatalf("evidence: %+v", ev)
	}
	// The identity lookup: ETag kept, no hash. Made by this check.
	if c := ev.Calls()[0]; c.Method != "GET" || c.Path != "/users/a@x.com" || c.Status != 200 || c.ETag != `"user-v1"` || c.SHA256 != "" || c.Cached {
		t.Errorf("identity call: %+v", c)
	}
	// The permission read: no ETag, so the body hash; the query is not there.
	if c := ev.Calls()[1]; c.Method != "GET" || c.Path != "/perm" || c.Status != 200 || c.ETag != "" || len(c.SHA256) != 64 || c.Cached {
		t.Errorf("permission call: %+v", c)
	}
	// The token exchange is not evidence.
	if u.tokens.Load() == 0 {
		t.Fatal("no token exchange happened")
	}

	// A cached decision logs the evidence that produced it.
	r = e.Check(ctx, webReq("thing:1", false))
	if !r.Cached || r.Decision.Evidence == nil || len(r.Decision.Evidence.Calls()) != 2 {
		t.Fatalf("cached: %+v", r)
	}
	// Another resource: the identity comes from the cache and says so, the
	// permission read is live.
	r = e.Check(ctx, webReq("thing:2", false))
	if r.Cached || u.users.Load() != 1 {
		t.Fatalf("%+v users=%d", r, u.users.Load())
	}
	if c := r.Decision.Evidence.Calls()[0]; !c.Cached || c.ETag != `"user-v1"` {
		t.Errorf("cached identity call: %+v", c)
	}
	if c := r.Decision.Evidence.Calls()[1]; c.Cached || c.Path != "/perm" {
		t.Errorf("live permission call: %+v", c)
	}

	ents := entries(t, logs)
	if len(ents) != 3 {
		t.Fatalf("entries = %d", len(ents))
	}
	if ents[0].Cached || ents[0].Evidence == nil || len(ents[0].Evidence.Calls()) != 2 {
		t.Errorf("entry 0: %+v", ents[0])
	}
	if !ents[1].Cached || ents[1].Evidence == nil || ents[1].Evidence.Calls()[0].ETag != `"user-v1"` {
		t.Errorf("entry 1: %+v", ents[1])
	}
	if ents[2].Cached || !ents[2].Evidence.Calls()[0].Cached || ents[2].Evidence.Calls()[1].Cached {
		t.Errorf("entry 2: %+v", ents[2])
	}
	// Nothing secret-shaped reaches a decision log line: not the token,
	// the query, the grant, the bodies, nor the token exchange itself.
	for _, ent := range ents {
		b, _ := json.Marshal(ent)
		if s := string(b); strings.Contains(s, canary) || strings.Contains(s, "/token") || strings.Contains(s, "?") {
			t.Fatalf("decision log leaked: %s", s)
		}
	}
	if strings.Contains(logs.String(), canary) {
		t.Fatalf("log leaked: %s", logs.String())
	}
}

// A cached allow, then the upstream answer changes: a fresh check sees the
// new answer, bypassing the decision cache and the identity cache, and
// what it learns replaces both entries.
func TestFreshCheck(t *testing.T) {
	u := newUpstream(t)
	e, logs := buildWeb(t, u, Options{DecisionCache: 30 * time.Second, IdentityCache: 15 * time.Minute})
	ctx := context.Background()

	if r := e.Check(ctx, webReq("thing:1", false)); r.Decision.Outcome != integration.Allow || lastFresh.Load() {
		t.Fatalf("%+v fresh=%v", r, lastFresh.Load())
	}
	u.allow.Store(false)
	u.etag.Store(`"user-v2"`)
	// The cache still says allow.
	if r := e.Check(ctx, webReq("thing:1", false)); !r.Cached || r.Decision.Outcome != integration.Allow {
		t.Fatalf("cached: %+v", r)
	}
	// Fresh sees the change and re-resolves the identity.
	r := e.Check(ctx, webReq("thing:1", true))
	if r.Cached || r.Decision.Outcome != integration.Deny || u.users.Load() != 2 || u.perms.Load() != 2 {
		t.Fatalf("fresh: %+v users=%d perms=%d", r, u.users.Load(), u.perms.Load())
	}
	if c := r.Decision.Evidence.Calls()[0]; c.Cached || c.ETag != `"user-v2"` {
		t.Errorf("fresh identity call: %+v", c)
	}
	if !lastFresh.Load() {
		t.Error("the integration did not see a fresh context")
	}
	// The fresh answer is what the caches now hold.
	r = e.Check(ctx, webReq("thing:1", false))
	if !r.Cached || r.Decision.Outcome != integration.Deny {
		t.Fatalf("after fresh: %+v", r)
	}
	r = e.Check(ctx, webReq("thing:2", false))
	if u.users.Load() != 2 || r.Decision.Evidence.Calls()[0].ETag != `"user-v2"` || !r.Decision.Evidence.Calls()[0].Cached {
		t.Fatalf("identity cache not refreshed: users=%d %+v", u.users.Load(), r.Decision.Evidence)
	}
	ents := entries(t, logs)
	if len(ents) != 5 {
		t.Fatalf("entries = %d", len(ents))
	}
	for i, ent := range ents {
		if ent.Fresh != (i == 2) {
			t.Errorf("entry %d fresh = %v", i, ent.Fresh)
		}
	}
	if ents[2].Cached || ents[2].Decision != "deny" {
		t.Errorf("fresh entry: %+v", ents[2])
	}
	// The fresh flag is honoured with the caches off too, and the fresh
	// entry is not written to a cache that is off.
	e2, _ := buildWeb(t, u, Options{})
	if r := e2.Check(ctx, webReq("thing:1", true)); r.Cached || r.Decision.Outcome != integration.Deny {
		t.Fatalf("no caches: %+v", r)
	}
	if e2.decs.Len() != 0 || e2.idCache.Len() != 0 {
		t.Fatal("fresh check stored into a disabled cache")
	}
}

// A failed identity lookup still leaves its evidence on the unknown
// decision, and an unknown decision is never cached, fresh or not.
func TestEvidenceOnFailedLookup(t *testing.T) {
	u := newUpstream(t)
	e, _ := buildWeb(t, u, Options{DecisionCache: 30 * time.Second, IdentityCache: 15 * time.Minute})
	u.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Write([]byte(`{"access_token":"t"}`))
			return
		}
		w.WriteHeader(503)
	})
	for _, fresh := range []bool{false, true} {
		r := e.Check(context.Background(), webReq("thing:1", fresh))
		if r.Decision.Outcome != integration.Unknown || r.Decision.Code != integration.CodeUpstreamError {
			t.Fatalf("fresh=%v: %+v", fresh, r)
		}
		ev := r.Decision.Evidence
		if ev == nil || len(ev.Calls()) == 0 || ev.Calls()[0].Path != "/users/a@x.com" || ev.Calls()[0].Status != 503 || ev.Calls()[0].Cached {
			t.Fatalf("fresh=%v evidence: %+v", fresh, ev)
		}
	}
	if e.decs.Len() != 0 || e.idCache.Len() != 0 {
		t.Fatal("a failed lookup was cached")
	}
}
