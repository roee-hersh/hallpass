// Package engine runs the check flow:
//
//	validate request -> find connection -> find action -> decision cache ->
//	resolve identity (cached) -> Check under a timeout -> cache allow/deny ->
//	decision log.
//
// A fresh request skips both cache lookups and stores what it learns as
// usual. Every upstream call httpx completes during identity resolution and
// Check is recorded as evidence on the decision and in the log.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/roee-hersh/hallpass/internal/cache"
	"github.com/roee-hersh/hallpass/internal/catalog"
	"github.com/roee-hersh/hallpass/internal/config"
	"github.com/roee-hersh/hallpass/internal/declog"
	"github.com/roee-hersh/hallpass/internal/evidence"
	"github.com/roee-hersh/hallpass/internal/httpx"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// Request is one /check call after JSON decoding.
type Request struct {
	User       string
	Groups     []string
	Connection string
	Action     string
	Resource   string
	// Fresh asks for an answer straight from the upstream system: the
	// decision cache, the identity cache and the lookups integrations
	// cache themselves are not consulted, and what the request learns
	// replaces their entries. For a caller about to do something
	// destructive.
	Fresh bool
	// Remote is the caller's address, for the decision log only.
	Remote string
}

// Result is the answer plus the HTTP status the server should use.
type Result struct {
	Decision integration.Decision
	Status   int
	Cached   bool
}

// Options tune the engine.
type Options struct {
	Logger        *slog.Logger
	DecisionLog   *declog.Logger
	DecisionCache time.Duration
	IdentityCache time.Duration
	// NegativeIdentityCache is how long user_not_found / user_ambiguous are
	// remembered (default 60 s).
	NegativeIdentityCache time.Duration
	Now                   func() time.Time
}

type conn struct {
	settings *integration.Settings
	integ    integration.Integration
	c        integration.Connection
}

// Engine holds built connections and caches.
type Engine struct {
	logger  *slog.Logger
	declog  *declog.Logger
	conns   map[string]*conn
	order   []string
	idCache *cache.TTL[string, idEntry]
	decs    *cache.TTL[string, integration.Decision]
	idTTL   time.Duration
	negTTL  time.Duration
	decTTL  time.Duration
	now     func() time.Time
}

type idEntry struct {
	id  integration.Identity
	err *integration.Error
}

// Build constructs every connection in dependency order.
func Build(ctx context.Context, cfg *config.Config, o Options) (*Engine, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.NegativeIdentityCache == 0 {
		o.NegativeIdentityCache = time.Minute
	}
	e := &Engine{
		logger:  o.Logger,
		declog:  o.DecisionLog,
		conns:   map[string]*conn{},
		idCache: cache.New[string, idEntry](0),
		decs:    cache.New[string, integration.Decision](0),
		idTTL:   o.IdentityCache,
		negTTL:  o.NegativeIdentityCache,
		decTTL:  o.DecisionCache,
		now:     o.Now,
	}
	for _, s := range cfg.Connections {
		integ := cfg.Integrations[s.ID]
		if integ == nil {
			return nil, fmt.Errorf("connection %q: no integration", s.ID)
		}
		settings := s
		deps := integration.Deps{
			Logger: o.Logger.With("connection", s.ID, "integration", s.Integration),
			Now:    o.Now,
			Connection: func(id string) (integration.Connection, error) {
				if !refersTo(integ, settings, id) {
					return nil, fmt.Errorf("connection %q does not reference %q", settings.ID, id)
				}
				c, ok := e.conns[id]
				if !ok {
					return nil, fmt.Errorf("connection %q is not built", id)
				}
				return c.c, nil
			},
			HTTPClient: func(s *integration.Settings) (*http.Client, error) {
				return httpx.NewHTTPClient(httpx.Options{
					CAFile:        s.CAFile,
					TLSServerName: s.TLSServerName,
					ProxyURL:      s.ProxyURL,
					Timeout:       s.EffectiveTimeout(),
				})
			},
		}
		c, err := integ.New(ctx, s, deps)
		if err != nil {
			return nil, fmt.Errorf("connection %q (%s): %w", s.ID, s.Integration, err)
		}
		if c == nil {
			return nil, fmt.Errorf("connection %q (%s): integration returned no connection", s.ID, s.Integration)
		}
		e.conns[s.ID] = &conn{settings: s, integ: integ, c: c}
		e.order = append(e.order, s.ID)
	}
	return e, nil
}

// refersTo reports whether settings name id in one of the integration's
// connection reference fields.
func refersTo(i integration.Integration, s *integration.Settings, id string) bool {
	for _, f := range i.Fields() {
		if f.Ref != "" && s.Get(f.Name) == id {
			return true
		}
	}
	return false
}

// Connections lists connection ids in build order.
func (e *Engine) Connections() []string { return append([]string(nil), e.order...) }

// Connection returns a built connection, for tests and probe.
func (e *Engine) Connection(id string) (integration.Connection, bool) {
	c, ok := e.conns[id]
	if !ok {
		return nil, false
	}
	return c.c, true
}

// ProbeReport is one connection's probe outcome.
type ProbeReport struct {
	ID          string
	Integration string
	Result      integration.ProbeResult
	Err         error
}

// Probe checks every connection (or the listed ones). A failure never stops
// the others.
func (e *Engine) Probe(ctx context.Context, ids ...string) []ProbeReport {
	if len(ids) == 0 {
		ids = e.order
	}
	var out []ProbeReport
	for _, id := range ids {
		c, ok := e.conns[id]
		if !ok {
			out = append(out, ProbeReport{ID: id, Err: errors.New("unknown connection")})
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, 2*c.settings.EffectiveTimeout())
		r, err := c.c.Probe(pctx)
		cancel()
		out = append(out, ProbeReport{ID: id, Integration: c.settings.Integration, Result: r, Err: err})
	}
	return out
}

func invalid(format string, args ...any) Result {
	return Result{Decision: integration.UnknownDecision(integration.CodeInvalidRequest, format, args...), Status: http.StatusBadRequest}
}

const (
	maxEmail  = 320
	maxGroups = 200
	maxGroup  = 256
)

// ValidateUser checks the shape of the caller's user string.
func ValidateUser(u string) error {
	if u == "" {
		return errors.New("user is empty")
	}
	if len(u) > maxEmail {
		return fmt.Errorf("user is longer than %d bytes", maxEmail)
	}
	for _, c := range u {
		if c <= 0x20 || c == 0x7f {
			return errors.New("user contains whitespace or a control character")
		}
	}
	local, domain, ok := strings.Cut(u, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return errors.New("user must be an email address")
	}
	return nil
}

func validateGroups(gs []string) error {
	if len(gs) > maxGroups {
		return fmt.Errorf("more than %d groups", maxGroups)
	}
	for _, g := range gs {
		if g == "" {
			return errors.New("groups contains an empty entry")
		}
		if len(g) > maxGroup {
			return fmt.Errorf("group longer than %d bytes", maxGroup)
		}
		for _, c := range g {
			if c < 0x20 || c == 0x7f {
				return errors.New("group contains a control character")
			}
		}
	}
	return nil
}

// Check answers one request.
func (e *Engine) Check(ctx context.Context, req Request) Result {
	start := e.now()
	res := e.check(ctx, req)
	d := res.Decision
	// Safety: the outcome always follows the code. An allow needs CodeAllowed.
	d.Outcome = integration.OutcomeOf(d.Code)
	res.Decision = d
	if e.declog != nil {
		e.declog.Log(declog.Entry{
			Connection: req.Connection,
			User:       req.User,
			Groups:     req.Groups,
			Action:     req.Action,
			Resource:   req.Resource,
			Decision:   string(d.Outcome),
			Code:       string(d.Code),
			Reason:     d.Text,
			Cached:     res.Cached,
			Fresh:      req.Fresh,
			DurationMS: e.now().Sub(start).Milliseconds(),
			Status:     res.Status,
			Remote:     req.Remote,
			Evidence:   d.Evidence,
		})
	}
	return res
}

func (e *Engine) check(ctx context.Context, req Request) Result {
	if err := ValidateUser(req.User); err != nil {
		return invalid("%v", err)
	}
	if err := validateGroups(req.Groups); err != nil {
		return invalid("%v", err)
	}
	if req.Connection == "" {
		return invalid("connection is empty")
	}
	if err := catalog.ValidateActionName(req.Action); err != nil {
		return invalid("%v", err)
	}
	resource, err := catalog.ParseResource(req.Resource)
	if err != nil {
		return invalid("%v", err)
	}
	c, ok := e.conns[req.Connection]
	if !ok {
		return Result{Decision: integration.UnknownDecision(integration.CodeUnknownConnection, "no connection with id %q", req.Connection), Status: http.StatusBadRequest}
	}
	action, ok := integration.FindAction(c.integ, req.Action)
	if !ok {
		return Result{Decision: integration.UnknownDecision(integration.CodeUnknownAction, "integration %s has no action %q", c.settings.Integration, req.Action), Status: http.StatusBadRequest}
	}

	groups := normalizeGroups(req.Groups)
	user := integration.User{Email: req.User, Groups: groups}
	decKey := strings.Join([]string{req.Connection, req.User, groupsKey(groups), req.Action, req.Resource}, "\x00")
	started := e.now()
	if e.decTTL > 0 && !req.Fresh {
		if d, ok := e.decs.Get(decKey); ok {
			d.Evidence = d.Evidence.AsCached()
			return Result{Decision: d, Status: http.StatusOK, Cached: true}
		}
	}

	ctx, cancel := context.WithTimeout(ctx, c.settings.EffectiveTimeout())
	defer cancel()
	ctx, rec := evidence.WithRecorder(ctx)
	if req.Fresh {
		// Every cache.TTL on the way, the identity cache and the ones
		// integrations keep, looks up again under a fresh context.
		ctx = evidence.WithFresh(ctx)
	}

	identity, err := e.identity(ctx, c, user)
	if err != nil {
		d := integration.ToDecision(err)
		d.Evidence = rec.Evidence()
		return Result{Decision: d, Status: http.StatusOK}
	}
	d, err := c.c.Check(ctx, integration.CheckRequest{
		User:       user,
		Identity:   identity,
		Action:     action,
		ActionName: req.Action,
		Resource:   resource,
	})
	if err != nil {
		d = integration.ToDecision(err)
		e.logger.Debug("check failed", "connection", req.Connection, "action", req.Action, "code", d.Code, "error", err.Error())
	}
	if d.Code == "" {
		d = integration.Unsupported("integration returned no reason code")
	}
	d.Outcome = integration.OutcomeOf(d.Code)
	d.Evidence = rec.Evidence()
	if e.decTTL > 0 && d.Outcome != integration.Unknown {
		// Store, not Set: a check that began earlier must not replace the
		// answer of a later one (a fresh check's, in particular).
		e.decs.Store(decKey, d, e.decTTL, started)
	}
	return Result{Decision: d, Status: http.StatusOK}
}

// groupsKey encodes a normalized group list for a cache key. Groups are
// joined with \x01 and the surrounding fields with \x00; validation rejects
// both bytes everywhere, so two different lists never share a key (a bare
// comma would let ["a","b,c"] and ["a,b","c"] collide).
func groupsKey(groups []string) string {
	return strings.Join(groups, "\x01")
}

// normalizeGroups returns the caller's groups sorted and deduplicated, so
// that two requests naming the same set of groups look the same to the
// integration and to both caches.
func normalizeGroups(gs []string) []string {
	out := slices.Clone(gs)
	slices.Sort(out)
	return slices.Compact(out)
}

// identityKey keys the identity cache. Integrations such as kubernetes and
// argocd embed the request's groups in the Identity, so the same email with
// different groups is a different identity: the key is the connection, the
// email and the normalized groups. The separator cannot appear in any part
// (validateGroups rejects control characters, ValidateUser rejects them in
// the email).
func identityKey(connID string, u integration.User) string {
	parts := make([]string, 0, 2+len(u.Groups))
	parts = append(parts, connID, strings.ToLower(u.Email))
	parts = append(parts, u.Groups...)
	return strings.Join(parts, "\x00")
}

// identity resolves u through the identity cache, which also carries the
// evidence of the lookup to every check it serves and looks up again under
// a fresh context.
func (e *Engine) identity(ctx context.Context, c *conn, u integration.User) (integration.Identity, error) {
	key := identityKey(c.settings.ID, u)
	fill := func(ctx context.Context) (idEntry, time.Duration, error) {
		id, err := c.c.ResolveIdentity(ctx, u)
		if err == nil {
			return idEntry{id: id}, e.idTTL, nil
		}
		var ie *integration.Error
		if errors.As(err, &ie) && (ie.Code == integration.CodeUserNotFound || ie.Code == integration.CodeUserAmbiguous) {
			return idEntry{err: ie}, e.negTTL, nil
		}
		return idEntry{}, 0, err
	}
	var ent idEntry
	var err error
	if e.idTTL > 0 {
		ent, err = e.idCache.Do(ctx, key, fill)
	} else {
		ent, _, err = fill(ctx)
	}
	if err != nil {
		return integration.Identity{}, err
	}
	if ent.err != nil {
		return integration.Identity{}, ent.err
	}
	return ent.id, nil
}

// Flush empties both caches. Tests and future admin endpoints use it.
func (e *Engine) Flush() {
	e.idCache = cache.New[string, idEntry](0)
	e.decs = cache.New[string, integration.Decision](0)
}
