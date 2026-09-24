// Package evidence ties a decision to the upstream state it was computed
// from: what each check asked the upstream and what the upstream answered,
// carried on the context so httpx and the caches can record and replay it.
package evidence

import (
	"context"
	"slices"
	"sync"
)

// Evidence is the calls a decision was based on and, for each, what
// identifies the version of the response (an ETag when the upstream sent
// one, otherwise a hash of the body). It goes into the decision log so an
// auditor can tell what the upstream system said when hallpass answered,
// not only the outcome. Most vendor APIs expose no policy version, so this
// is the closest thing available.
type Evidence struct {
	// Upstream lists the calls in the order they completed.
	Upstream []Call `json:"upstream"`
	// Truncated is set when more than MaxCalls completed and the
	// rest were dropped.
	Truncated bool `json:"truncated,omitempty"`
}

// Call is one completed upstream request.
type Call struct {
	Method string `json:"method"`
	// Path is the request path as sent. Never the query string, which may
	// carry user data or a token.
	Path string `json:"path"`
	// Host is set only when the call went to a host other than the
	// connection's own base URL: some vendors spread an API over several
	// hosts, and a path alone would not say which answered.
	Host   string `json:"host,omitempty"`
	Status int    `json:"status"`
	// ETag is the response's ETag header, when it sent one.
	ETag string `json:"etag,omitempty"`
	// SHA256 is the hex SHA-256 of the response body, when there was no
	// ETag and the body was not empty.
	SHA256 string `json:"sha256,omitempty"`
	// Cached marks a call that was not made for this check: its result was
	// served from a stored cache entry (the identity cache, or one an
	// integration keeps), and this is the evidence recorded when the call
	// was made.
	Cached bool `json:"cached,omitempty"`
	// Shared marks a call made by a concurrent check whose lookup this
	// check joined: the response was live during this check, but this
	// check did not ask for it itself.
	Shared bool `json:"shared,omitempty"`
}

// MaxCalls bounds the calls one Recorder keeps, so a paginated
// lookup cannot grow a log line without limit. Calls made for the check
// take precedence over replayed ones, and among those the latest are
// kept: the call that decided a check is the last one it made.
const MaxCalls = 100

// Origin says how a check came by a call's response.
type Origin int

const (
	// Own: the check made the call.
	Own Origin = iota
	// Shared: a concurrent check made the call and this check joined it.
	Shared
	// Cached: the call was made earlier and its result served from a cache.
	Cached
)

// Recorder collects the evidence of one check. It is safe for concurrent
// use: a shared fill may still be running on a detached context after the
// check that started it has returned.
//
// The engine gives every check a Recorder through its context; httpx
// records each response it returns on it, and cache.TTL.Do replays the
// evidence of a cached fill on it, marked cached.
type Recorder struct {
	mu        sync.Mutex
	calls     []Call
	truncated bool
}

// Record adds one call. A nil Recorder records nothing. Past the cap a
// cached call is dropped and a live one takes the place of the oldest
// cached call, or of the oldest live one when none is cached: the calls
// the check made last are the ones that decided it.
func (r *Recorder) Record(c Call) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) >= MaxCalls {
		r.truncated = true
		if c.Cached {
			return
		}
		i := slices.IndexFunc(r.calls, func(c Call) bool { return c.Cached })
		if i < 0 {
			i = 0
		}
		r.calls = slices.Delete(r.calls, i, i+1)
	}
	r.calls = append(r.calls, c)
}

// Add adds ev's calls, marked by how this check came by them, and carries
// ev's truncation over. A call already marked cached stays cached. A nil
// ev adds nothing.
func (r *Recorder) Add(ev *Evidence, by Origin) {
	if r == nil || ev == nil {
		return
	}
	for _, c := range ev.Upstream {
		switch by {
		case Cached:
			c.Cached, c.Shared = true, false
		case Shared:
			c.Shared = !c.Cached
		}
		r.Record(c)
	}
	if ev.Truncated {
		r.mu.Lock()
		r.truncated = true
		r.mu.Unlock()
	}
}

// AsCached returns a copy of ev with every call marked cached, for a
// decision served from a cache. A nil ev gives nil.
func (ev *Evidence) AsCached() *Evidence {
	if ev == nil {
		return nil
	}
	r := &Recorder{}
	r.Add(ev, Cached)
	return r.Evidence()
}

// Evidence returns a snapshot of what was recorded, or nil when nothing
// was. The snapshot is not affected by later calls to Record.
func (r *Recorder) Evidence() *Evidence {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		return nil
	}
	return &Evidence{Upstream: append([]Call(nil), r.calls...), Truncated: r.truncated}
}

type recorderKey struct{}

// WithRecorder returns a context carrying a new Recorder. The engine sets
// one up for every check.
func WithRecorder(ctx context.Context) (context.Context, *Recorder) {
	r := &Recorder{}
	return context.WithValue(ctx, recorderKey{}, r), r
}

// WithoutRecorder returns a context whose RecorderFrom is nil. httpx runs
// Auth funcs on it and authx fetches tokens on it: a token exchange is not
// what a decision was based on, and its response carries the credential.
func WithoutRecorder(ctx context.Context) context.Context {
	if ctx.Value(recorderKey{}) == nil {
		return ctx
	}
	return context.WithValue(ctx, recorderKey{}, (*Recorder)(nil))
}

// RecorderFrom returns the context's Recorder, or nil when the context has
// none or recording is suppressed. Every Recorder method accepts nil.
func RecorderFrom(ctx context.Context) *Recorder {
	r, _ := ctx.Value(recorderKey{}).(*Recorder)
	return r
}

type freshKey struct{}

// WithFresh marks a context as belonging to a fresh check: every cache.TTL
// consulted under it looks the value up again instead of serving a cached
// or in-flight one, and replaces its entry with the answer. The engine sets
// it for a request with "fresh": true.
func WithFresh(ctx context.Context) context.Context {
	return context.WithValue(ctx, freshKey{}, true)
}

// Fresh reports whether ctx belongs to a fresh check.
func Fresh(ctx context.Context) bool {
	v, _ := ctx.Value(freshKey{}).(bool)
	return v
}
