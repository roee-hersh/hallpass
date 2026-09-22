package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/config"
	"github.com/roee-hersh/hallpass/internal/declog"
	"github.com/roee-hersh/hallpass/internal/integration"
	"github.com/roee-hersh/hallpass/internal/integrations/fake"
)

// counting wraps the fake to count upstream calls and to inject behaviour.
type counting struct {
	integration.Integration
	resolves atomic.Int32
	checks   atomic.Int32
	slow     time.Duration
	badAllow bool
	// echoGroups copies the caller's groups into the identity, as
	// integrations without a user directory do, and allows a check only
	// when the identity carries the admin group.
	echoGroups bool
}

type countingConn struct {
	integration.Connection
	p *counting
}

func (c *counting) Name() string { return "counting" }
func (c *counting) Fields() []integration.Field {
	return append(c.Integration.Fields(), integration.ConnectionRefField("fake_connection", "fake", false, ""))
}
func (c *counting) New(ctx context.Context, s *integration.Settings, d integration.Deps) (integration.Connection, error) {
	if s.Get("fake_connection") != "" {
		if _, err := d.Connection(s.Get("fake_connection")); err != nil {
			return nil, err
		}
		if _, err := d.Connection("not-referenced"); err == nil {
			return nil, errors.New("unreferenced connection resolvable")
		}
	}
	inner, err := c.Integration.New(ctx, s, d)
	if err != nil {
		return nil, err
	}
	return &countingConn{Connection: inner, p: c}, nil
}

func (c *countingConn) ResolveIdentity(ctx context.Context, u integration.User) (integration.Identity, error) {
	c.p.resolves.Add(1)
	if c.p.echoGroups {
		return integration.Identity{ID: u.Email, Display: u.Email, Groups: append([]string(nil), u.Groups...)}, nil
	}
	return c.Connection.ResolveIdentity(ctx, u)
}

func (c *countingConn) Check(ctx context.Context, r integration.CheckRequest) (integration.Decision, error) {
	c.p.checks.Add(1)
	if c.p.slow > 0 {
		select {
		case <-ctx.Done():
			return integration.Decision{}, ctx.Err()
		case <-time.After(c.p.slow):
		}
	}
	if c.p.badAllow {
		return integration.Decision{Outcome: integration.Allow, Code: integration.CodeUnsupported, Text: "bug"}, nil
	}
	if c.p.echoGroups {
		for _, g := range r.Identity.Groups {
			if g == "admin" {
				return integration.Allowed("admin group"), nil
			}
		}
		return integration.Denied("not an admin"), nil
	}
	return c.Connection.Check(ctx, r)
}

const cfgYAML = `
api_key: env:K
connections:
  - id: f
    integration: fake
    users: u@x.com
    admins: a@x.com
  - id: c
    integration: counting
    fake_connection: f
    users: u@x.com
    admins: a@x.com
    timeout: 300ms
`

func build(t *testing.T, c *counting, o Options) (*Engine, *bytes.Buffer) {
	t.Helper()
	reg := integration.NewRegistry()
	reg.Register(fake.Integration{})
	reg.Register(c)
	cfg, err := config.Parse("t.yaml", []byte(cfgYAML), reg)
	if err != nil {
		t.Fatal(err)
	}
	var logbuf bytes.Buffer
	o.DecisionLog = declog.New(&logbuf)
	o.Logger = slog.New(slog.NewJSONHandler(&logbuf, nil))
	e, err := Build(context.Background(), cfg, o)
	if err != nil {
		t.Fatal(err)
	}
	return e, &logbuf
}

func req(user, action, resource string) Request {
	return Request{User: user, Groups: []string{"g"}, Connection: "c", Action: action, Resource: resource}
}

func TestFlowAndCaches(t *testing.T) {
	c := &counting{Integration: fake.Integration{}}
	e, logs := build(t, c, Options{DecisionCache: 30 * time.Second, IdentityCache: 15 * time.Minute})
	ctx := context.Background()

	r := e.Check(ctx, req("a@x.com", "thing.write", "thing:1"))
	if r.Status != 200 || r.Decision.Outcome != integration.Allow || r.Cached {
		t.Fatalf("%+v", r)
	}
	r = e.Check(ctx, req("a@x.com", "thing.write", "thing:1"))
	if !r.Cached || r.Decision.Outcome != integration.Allow {
		t.Fatalf("decision not cached: %+v", r)
	}
	if c.checks.Load() != 1 {
		t.Fatalf("checks = %d", c.checks.Load())
	}
	// Same user, different resource: identity cached, check runs.
	r = e.Check(ctx, req("a@x.com", "thing.write", "thing:2"))
	if r.Cached || c.resolves.Load() != 1 || c.checks.Load() != 2 {
		t.Fatalf("identity cache: resolves=%d checks=%d", c.resolves.Load(), c.checks.Load())
	}
	// Unknown decisions are not cached.
	r = e.Check(ctx, req("u@x.com", "thing.read", "thing:hidden"))
	if r.Decision.Code != integration.CodeResourceNotVisible {
		t.Fatal(r)
	}
	r = e.Check(ctx, req("u@x.com", "thing.read", "thing:hidden"))
	if r.Cached {
		t.Fatal("unknown was cached")
	}
	// Negative identity is cached.
	before := c.resolves.Load()
	e.Check(ctx, req("nobody@x.com", "thing.read", "thing:1"))
	r = e.Check(ctx, req("nobody@x.com", "thing.read", "thing:1"))
	if r.Decision.Code != integration.CodeUserNotFound || r.Decision.Outcome != integration.Deny || c.resolves.Load() != before+1 {
		t.Fatalf("negative identity: %+v resolves=%d", r, c.resolves.Load())
	}
	// Decision log has one line per check with the right fields.
	lines := 0
	for _, l := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var ent map[string]any
		if json.Unmarshal([]byte(l), &ent) == nil && ent["decision"] != nil {
			lines++
			if ent["connection"] != "c" || ent["action"] == nil || ent["status"] == nil {
				t.Errorf("bad log entry: %s", l)
			}
		}
	}
	if lines != 7 {
		t.Errorf("decision log lines = %d", lines)
	}
}

// TestCachesKeyOnGroups: an identity that carries the caller's groups must
// not be served to a later request for the same email with other groups,
// and two group lists that differ only in where their boundaries fall must
// not share a decision cache entry.
func TestCachesKeyOnGroups(t *testing.T) {
	c := &counting{Integration: fake.Integration{}, echoGroups: true}
	e, _ := build(t, c, Options{DecisionCache: 30 * time.Second, IdentityCache: 15 * time.Minute})
	ctx := context.Background()
	with := func(groups ...string) Request {
		return Request{User: "a@x.com", Groups: groups, Connection: "c", Action: "thing.write", Resource: "thing:1"}
	}

	r := e.Check(ctx, with("admin"))
	if r.Decision.Outcome != integration.Allow || c.resolves.Load() != 1 {
		t.Fatalf("admin: %+v resolves=%d", r, c.resolves.Load())
	}
	// Same email, different groups: the identity is resolved again and the
	// cached admin groups are not reused.
	r = e.Check(ctx, with("staff"))
	if r.Cached || r.Decision.Outcome != integration.Deny || c.resolves.Load() != 2 {
		t.Fatalf("staff after admin: %+v resolves=%d", r, c.resolves.Load())
	}
	// No groups at all after a request with groups.
	r = e.Check(ctx, with())
	if r.Cached || r.Decision.Outcome != integration.Deny || c.resolves.Load() != 3 {
		t.Fatalf("no groups after admin: %+v resolves=%d", r, c.resolves.Load())
	}
	// The same groups again hit both caches.
	r = e.Check(ctx, with("admin"))
	if !r.Cached || r.Decision.Outcome != integration.Allow || c.resolves.Load() != 3 {
		t.Fatalf("admin again: %+v resolves=%d", r, c.resolves.Load())
	}
	// Group boundaries are part of the key: ["a","b,c"] and ["a,b","c"]
	// are different requests.
	r = e.Check(ctx, with("a", "b,c"))
	if r.Cached {
		t.Fatalf("first partition cached: %+v", r)
	}
	r = e.Check(ctx, with("a,b", "c"))
	if r.Cached {
		t.Fatalf("second partition served from the first's entry: %+v", r)
	}
	r = e.Check(ctx, with("a", "b,c"))
	if !r.Cached {
		t.Fatalf("first partition not cached on repeat: %+v", r)
	}
}

func TestNoCaches(t *testing.T) {
	c := &counting{Integration: fake.Integration{}}
	e, _ := build(t, c, Options{})
	ctx := context.Background()
	e.Check(ctx, req("a@x.com", "thing.write", "thing:1"))
	r := e.Check(ctx, req("a@x.com", "thing.write", "thing:1"))
	if r.Cached || c.checks.Load() != 2 || c.resolves.Load() != 2 {
		t.Fatalf("caches disabled: %+v %d %d", r, c.checks.Load(), c.resolves.Load())
	}
}

func TestBadRequests(t *testing.T) {
	c := &counting{Integration: fake.Integration{}}
	e, _ := build(t, c, Options{})
	ctx := context.Background()
	cases := []struct {
		r    Request
		code integration.Code
	}{
		{Request{User: "", Connection: "c", Action: "thing.read", Resource: "thing:1"}, integration.CodeInvalidRequest},
		{Request{User: "not-an-email", Connection: "c", Action: "thing.read", Resource: "thing:1"}, integration.CodeInvalidRequest},
		{Request{User: "a@x.com", Groups: []string{""}, Connection: "c", Action: "thing.read", Resource: "thing:1"}, integration.CodeInvalidRequest},
		{Request{User: "a@x.com", Connection: "", Action: "thing.read", Resource: "thing:1"}, integration.CodeInvalidRequest},
		{Request{User: "a@x.com", Connection: "c", Action: "", Resource: "thing:1"}, integration.CodeInvalidRequest},
		{Request{User: "a@x.com", Connection: "c", Action: "thing.read", Resource: ""}, integration.CodeInvalidRequest},
		{Request{User: "a@x.com", Connection: "c", Action: "thing.read", Resource: "Thing:1"}, integration.CodeInvalidRequest},
		{Request{User: "a@x.com", Connection: "zzz", Action: "thing.read", Resource: "thing:1"}, integration.CodeUnknownConnection},
		{Request{User: "a@x.com", Connection: "c", Action: "thing.fly", Resource: "thing:1"}, integration.CodeUnknownAction},
	}
	for _, cs := range cases {
		r := e.Check(ctx, cs.r)
		if r.Status != 400 || r.Decision.Code != cs.code || r.Decision.Outcome != integration.Unknown {
			t.Errorf("%+v -> %+v", cs.r, r)
		}
	}
	if c.checks.Load() != 0 {
		t.Error("bad requests reached the integration")
	}
}

func TestTimeoutAndBadAllow(t *testing.T) {
	c := &counting{Integration: fake.Integration{}, slow: 2 * time.Second}
	e, _ := build(t, c, Options{})
	start := time.Now()
	r := e.Check(context.Background(), req("a@x.com", "thing.read", "thing:1"))
	if r.Decision.Code != integration.CodeUpstreamTimeout || r.Decision.Outcome != integration.Unknown {
		t.Fatalf("%+v", r)
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout not enforced")
	}
	c2 := &counting{Integration: fake.Integration{}, badAllow: true}
	e2, _ := build(t, c2, Options{})
	r = e2.Check(context.Background(), req("a@x.com", "thing.read", "thing:1"))
	if r.Decision.Outcome != integration.Unknown {
		t.Fatalf("allow with a non-allow code got through: %+v", r)
	}
}

func TestProbeAndConnections(t *testing.T) {
	c := &counting{Integration: fake.Integration{}}
	e, _ := build(t, c, Options{})
	if got := e.Connections(); len(got) != 2 || got[0] != "f" {
		t.Fatal(got)
	}
	reps := e.Probe(context.Background())
	if len(reps) != 2 || reps[0].Err != nil || reps[1].Err != nil {
		t.Fatalf("%+v", reps)
	}
	reps = e.Probe(context.Background(), "nope")
	if len(reps) != 1 || reps[0].Err == nil {
		t.Fatal(reps)
	}
	if _, ok := e.Connection("c"); !ok {
		t.Fatal("Connection")
	}
}

func TestValidateUser(t *testing.T) {
	for _, ok := range []string{"a@b", "dana@example.com", "o'neil+x@ex.co.uk"} {
		if err := ValidateUser(ok); err != nil {
			t.Error(ok, err)
		}
	}
	for _, bad := range []string{"", "a", "@b", "a@", "a b@c", "a@b@c", "a\n@b", strings.Repeat("a", 320) + "@b"} {
		if err := ValidateUser(bad); err == nil {
			t.Error(bad, "accepted")
		}
	}
}

func TestBuildErrors(t *testing.T) {
	reg := integration.NewRegistry()
	reg.Register(failing{})
	cfg, err := config.Parse("t.yaml", []byte("api_key: env:K\nconnections:\n  - id: a\n    integration: failing\n"), reg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(context.Background(), cfg, Options{}); err == nil || !strings.Contains(err.Error(), `connection "a" (failing)`) {
		t.Fatalf("err = %v", err)
	}
}

type failing struct{}

func (failing) Name() string                { return "failing" }
func (failing) Fields() []integration.Field { return nil }
func (failing) Actions() []catalog.Action   { return nil }
func (failing) New(context.Context, *integration.Settings, integration.Deps) (integration.Connection, error) {
	return nil, errors.New("cannot build")
}
