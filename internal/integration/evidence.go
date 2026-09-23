package integration

import (
	"context"
	"sync"
)

// Evidence ties a decision to the upstream state it was computed from: the
// calls the decision was based on and, for each, what identifies the
// version of the response (an ETag when the upstream sent one, otherwise a
// hash of the body). It goes into the decision log so an auditor can tell
// what the upstream system said when hallpass answered, not only the
// outcome. Most vendor APIs expose no policy version, so this is the closest
// thing available.
type Evidence struct {
	// Upstream lists the calls in the order they completed.
	Upstream []Call `json:"upstream"`
	// Truncated is set when more than MaxEvidenceCalls completed and the
	// rest were dropped.
	Truncated bool `json:"truncated,omitempty"`
}

// Call is one completed upstream request.
type Call struct {
	Method string `json:"method"`
	// Path is the request path as sent. Never the query string, which may
	// carry user data or a token, and never the host, which is the
	// connection's own.
	Path   string `json:"path"`
	Status int    `json:"status"`
	// ETag is the response's ETag header, when it sent one.
	ETag string `json:"etag,omitempty"`
	// SHA256 is the hex SHA-256 of the response body, when there was no
	// ETag and the body was not empty.
	SHA256 string `json:"sha256,omitempty"`
	// Cached marks a call that was not made for this check: its result was
	// served from a cache (the identity cache, or one an integration keeps),
	// and this is the evidence recorded when the call was made.
	Cached bool `json:"cached,omitempty"`
}

// MaxEvidenceCalls bounds the calls one Recorder keeps, so a paginated
// lookup cannot grow a log line without limit.
const MaxEvidenceCalls = 100

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

// Record adds one call. A nil Recorder records nothing.
func (r *Recorder) Record(c Call) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) >= MaxEvidenceCalls {
		r.truncated = true
		return
	}
	r.calls = append(r.calls, c)
}

// Add adds ev's calls, marked as served from a cache when cached is set,
// and carries ev's truncation over. A nil ev adds nothing.
func (r *Recorder) Add(ev *Evidence, cached bool) {
	if r == nil || ev == nil {
		return
	}
	for _, c := range ev.Upstream {
		c.Cached = c.Cached || cached
		r.Record(c)
	}
	if ev.Truncated {
		r.mu.Lock()
		r.truncated = true
		r.mu.Unlock()
	}
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
