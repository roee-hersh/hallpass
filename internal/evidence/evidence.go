// Package evidence ties a decision to the upstream state it was computed
// from: what each check asked the upstream and what the upstream answered,
// carried on the context so httpx and the caches can record and replay it.
// It also holds the other per-check context marks (fresh) and the one
// predicate for a context having ended, so the packages on a check's way
// share them without depending on each other.
package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"
)

// ContextEnded reports whether err is a context ending (cancelled or past
// its deadline), as opposed to a failure of the work itself.
func ContextEnded(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
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

// MaxCalls bounds the calls one Evidence reports, so a paginated lookup
// cannot grow a log line without limit. Calls made for the check take
// precedence over replayed ones, and among those the latest are kept: the
// call that decided a check is the last one it made.
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

// Evidence is the calls a decision was based on and, for each, what
// identifies the version of the response (an ETag when the upstream sent
// one, otherwise a hash of the body). It goes into the decision log so an
// auditor can tell what the upstream system said when hallpass answered,
// not only the outcome. Most vendor APIs expose no policy version, so this
// is the closest thing available.
//
// An Evidence is immutable once built. The calls a check got from a cache
// are held by reference to the evidence recorded when they were made, so a
// cached lookup's pages are stored once however many decisions replay
// them; Calls flattens them on demand, marked by origin.
type Evidence struct {
	items []item
	// truncated is set when own calls were dropped at the cap.
	truncated bool

	// flat is the flattened form, computed once: an Evidence is immutable.
	flatOnce  sync.Once
	flat      []Call
	flatTrunc bool
	// cached is the AsCached view, built once for the same reason.
	cachedOnce sync.Once
	cached     *Evidence
}

// item is one own call or a reference to another Evidence's calls.
type item struct {
	call Call
	src  *Evidence
	by   Origin
}

// Of builds an Evidence of the given calls, as recorded.
func Of(calls ...Call) *Evidence {
	if len(calls) == 0 {
		return nil
	}
	e := &Evidence{items: make([]item, 0, len(calls))}
	for _, c := range calls {
		e.items = append(e.items, item{call: c})
	}
	return e
}

// Calls returns the calls in the order they completed, marked by how the
// check came by them, at most MaxCalls of them. Past the cap the oldest
// calls are dropped, cached ones first. A nil Evidence has none. The
// slice is shared: read-only.
func (e *Evidence) Calls() []Call {
	calls, _ := e.flatten()
	return calls
}

// Truncated reports whether calls were dropped at the cap.
func (e *Evidence) Truncated() bool {
	_, truncated := e.flatten()
	return truncated
}

func (e *Evidence) flatten() ([]Call, bool) {
	if e == nil {
		return nil, false
	}
	e.flatOnce.Do(func() { e.flat, e.flatTrunc = e.flattenOnce() })
	return e.flat, e.flatTrunc
}

func (e *Evidence) flattenOnce() ([]Call, bool) {
	// A counting pass decides what the cap drops (the oldest cached calls
	// first, then the oldest of the rest); the second pass keeps only the
	// survivors, so nothing beyond the cap is ever materialized.
	total, cached := 0, 0
	truncated := e.walk(Own, func(c Call) {
		total++
		if c.Cached {
			cached++
		}
	})
	dropCached, dropLive := 0, 0
	if excess := total - MaxCalls; excess > 0 {
		truncated = true
		dropCached = min(excess, cached)
		dropLive = excess - dropCached
	}
	out := make([]Call, 0, min(total, MaxCalls))
	e.walk(Own, func(c Call) {
		switch {
		case c.Cached && dropCached > 0:
			dropCached--
		case !c.Cached && dropLive > 0:
			dropLive--
		default:
			out = append(out, c)
		}
	})
	return out, truncated
}

// walk visits e's calls in order with by applied, and reports whether any
// segment on the way was truncated.
func (e *Evidence) walk(by Origin, visit func(Call)) bool {
	if e == nil {
		return false
	}
	truncated := e.truncated
	for _, it := range e.items {
		if it.src != nil {
			inner := it.by
			if by == Cached {
				inner = Cached
			} else if by == Shared && inner == Own {
				inner = Shared
			}
			if it.src.walk(inner, visit) {
				truncated = true
			}
			continue
		}
		c := it.call
		switch by {
		case Cached:
			c.Cached, c.Shared = true, false
		case Shared:
			c.Shared = !c.Cached
		}
		visit(c)
	}
	return truncated
}

// AsCached returns e's calls as served from a cache, for a decision served
// from the decision cache. A nil e gives nil; the same e gives the same
// view, so a decision served many times flattens it once.
func (e *Evidence) AsCached() *Evidence {
	if e == nil {
		return nil
	}
	e.cachedOnce.Do(func() { e.cached = &Evidence{items: []item{{src: e, by: Cached}}} })
	return e.cached
}

// wire is the JSON shape: the flattened calls.
type wire struct {
	Upstream  []Call `json:"upstream"`
	Truncated bool   `json:"truncated,omitempty"`
}

// MarshalJSON writes {"upstream": [...], "truncated": true}.
func (e *Evidence) MarshalJSON() ([]byte, error) {
	calls, truncated := e.flatten()
	if calls == nil {
		calls = []Call{}
	}
	return json.Marshal(wire{Upstream: calls, Truncated: truncated})
}

// UnmarshalJSON reads what MarshalJSON wrote, keeping each call's marks.
func (e *Evidence) UnmarshalJSON(b []byte) error {
	var w wire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*e = Evidence{truncated: w.Truncated}
	for _, c := range w.Upstream {
		e.items = append(e.items, item{call: c})
	}
	return nil
}

// Recorder collects the evidence of one check. It is safe for concurrent
// use: a shared fill may still be running on a detached context after the
// check that started it has returned.
//
// The engine gives every check a Recorder through its context; httpx
// records each response it returns on it, and cache.TTL.Do adds the
// evidence of a fill, by reference, marked by how the check came by it.
type Recorder struct {
	mu  sync.Mutex
	ev  Evidence
	own int
	// oldest is when the oldest read added with AddAt began; zero when
	// none was.
	oldest time.Time
}

// Record adds one call the check made. A nil Recorder records nothing.
// Past MaxCalls own calls the oldest own call is dropped: the calls the
// check made last are the ones that decided it.
func (r *Recorder) Record(c Call) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.own >= MaxCalls {
		r.ev.truncated = true
		i := slices.IndexFunc(r.ev.items, func(it item) bool { return it.src == nil })
		r.ev.items = slices.Delete(r.ev.items, i, i+1)
		r.own--
	}
	r.ev.items = append(r.ev.items, item{call: c})
	r.own++
}

// Add adds ev's calls, by reference, marked by how this check came by
// them. A nil ev adds nothing. Past MaxCalls references the rest are
// dropped: they are replayed calls, the first to go at the cap anyway.
func (r *Recorder) Add(ev *Evidence, by Origin) {
	r.AddAt(ev, by, time.Time{})
}

// AddAt is Add for a read that began at readAt: the calls came from a
// cache entry or a fill that started then. The oldest such time is what
// Oldest reports, so a decision can be dated by its oldest input. A nil
// ev still dates the record: an entry with no calls is still a read.
func (r *Recorder) AddAt(ev *Evidence, by Origin, readAt time.Time) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !readAt.IsZero() && (r.oldest.IsZero() || readAt.Before(r.oldest)) {
		r.oldest = readAt
	}
	if ev == nil {
		return
	}
	if len(r.ev.items)-r.own >= MaxCalls {
		r.ev.truncated = true
		return
	}
	r.ev.items = append(r.ev.items, item{src: ev, by: by})
}

// Oldest returns when the oldest read behind the record began, and false
// when every call was the check's own. A decision rests on nothing older
// than its inputs, so a cache orders it by this rather than by when the
// check began.
func (r *Recorder) Oldest() (time.Time, bool) {
	if r == nil {
		return time.Time{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.oldest, !r.oldest.IsZero()
}

// Evidence returns a snapshot of what was recorded, or nil when nothing
// was. The snapshot is not affected by later calls to Record or Add.
func (r *Recorder) Evidence() *Evidence {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.ev.items) == 0 {
		return nil
	}
	return &Evidence{items: slices.Clone(r.ev.items), truncated: r.ev.truncated}
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
