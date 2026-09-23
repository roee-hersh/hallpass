// Package cache is a small generic TTL cache with singleflight: concurrent
// callers for the same missing key share one fill.
package cache

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/roee-hersh/hallpass/internal/integration"
)

// TTL is a bounded, time-limited map. Zero or negative TTLs disable storage
// but Do still collapses concurrent fills.
type TTL[K comparable, V any] struct {
	mu       sync.Mutex
	items    map[K]entry[V]
	inflight map[K]*call[V]
	max      int
	now      func() time.Time
}

type entry[V any] struct {
	v   V
	exp time.Time
	// ev is the evidence of the fill that produced v, replayed on hits.
	ev *integration.Evidence
}

type call[V any] struct {
	done chan struct{}
	v    V
	err  error
	// rec is the fill's own Recorder; its Evidence is final once done is
	// closed.
	rec *integration.Recorder
}

// New creates a cache holding at most max entries (0 means 10000).
func New[K comparable, V any](max int) *TTL[K, V] {
	if max <= 0 {
		max = 10000
	}
	return &TTL[K, V]{
		items:    make(map[K]entry[V]),
		inflight: make(map[K]*call[V]),
		max:      max,
		now:      time.Now,
	}
}

// SetClock replaces the time source. Tests use it.
func (c *TTL[K, V]) SetClock(now func() time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

// Get returns the cached value when present and not expired.
func (c *TTL[K, V]) Get(k K) (V, bool) {
	v, _, ok := c.get(k)
	return v, ok
}

// Set stores v for ttl. A ttl <= 0 removes the key.
func (c *TTL[K, V]) Set(k K, v V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl <= 0 {
		delete(c.items, k)
		return
	}
	c.evictLocked()
	c.items[k] = entry[V]{v: v, exp: c.now().Add(ttl)}
}

// Delete removes one key.
func (c *TTL[K, V]) Delete(k K) {
	c.mu.Lock()
	delete(c.items, k)
	c.mu.Unlock()
}

// Len reports the number of stored entries, expired ones included.
func (c *TTL[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// evictLocked drops expired entries and, if still full, arbitrary ones.
func (c *TTL[K, V]) evictLocked() {
	if len(c.items) < c.max {
		return
	}
	now := c.now()
	for k, e := range c.items {
		if !now.Before(e.exp) {
			delete(c.items, k)
		}
	}
	for k := range c.items {
		if len(c.items) < c.max {
			break
		}
		delete(c.items, k)
	}
}

// DefaultFillTimeout bounds a fill whose caller's context carries no
// deadline. See Detach.
const DefaultFillTimeout = 30 * time.Second

// PanicError is returned by Do to every caller when the fill panicked. The
// panic is not re-raised: net/http would only recover it in the leader and
// the waiters would still need an answer.
type PanicError struct {
	Value any    // the value passed to panic
	Stack []byte // the fill goroutine's stack at the time of the panic
}

func (e *PanicError) Error() string { return fmt.Sprintf("fill panicked: %v", e.Value) }

// Detach derives the context a shared fill runs on: it keeps ctx's values
// (loggers, trace ids) but not its cancellation, so one caller
// disconnecting does not abort the lookup for the others, and it carries
// ctx's remaining deadline (or fallback when ctx has none) so an abandoned
// fill still ends.
func Detach(ctx context.Context, fallback time.Duration) (context.Context, context.CancelFunc) {
	timeout := fallback
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
	}
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

// Do returns the cached value for k or calls fill once, sharing the result
// with concurrent callers. The fill decides the TTL by returning it; a TTL
// of 0 means "do not store". Errors are never stored.
//
// The upstream calls a fill makes are its evidence (see
// integration.Recorder). The fill runs on its own Recorder; the caller
// that ran it gets the calls on its context's Recorder as its own, a
// caller that waited for another's fill or hit the cache gets them marked
// cached. So a decision served from a cached lookup still shows what the
// upstream said when the lookup was made.
//
// Under a fresh context (integration.WithFresh) Do neither reads the cache
// nor joins a fill in flight: it runs fill itself, on ctx, and stores the
// answer for the callers after it.
//
// The fill runs in its own goroutine on a context detached from the first
// caller's cancellation (see Detach) rather than on ctx itself: otherwise
// that caller going away would abort the fill and hand every waiter a
// context.Canceled that is not theirs. Each caller, the first included,
// stops waiting when its own ctx is done. A panic in fill becomes a
// *PanicError for everyone waiting on it.
func (c *TTL[K, V]) Do(ctx context.Context, k K, fill func(ctx context.Context) (V, time.Duration, error)) (V, error) {
	rec := integration.RecorderFrom(ctx)
	if integration.Fresh(ctx) {
		return c.fresh(ctx, k, fill, rec)
	}
	if v, ev, ok := c.get(k); ok {
		rec.Add(ev, true)
		return v, nil
	}
	c.mu.Lock()
	cl, ok := c.inflight[k]
	leader := !ok
	if leader {
		cl = &call[V]{done: make(chan struct{})}
		c.inflight[k] = cl
		fctx, cancel := Detach(ctx, DefaultFillTimeout)
		fctx, cl.rec = integration.WithRecorder(fctx)
		go func() {
			defer cancel()
			c.fill(k, cl, fctx, fill)
		}()
	}
	c.mu.Unlock()
	select {
	case <-cl.done:
		// cl is complete: the fill's goroutine closed done after its
		// last write.
		rec.Add(cl.rec.Evidence(), !leader)
		return cl.v, cl.err
	case <-ctx.Done():
		var zero V
		return zero, ctx.Err()
	}
}

// get is Get that also returns the entry's evidence.
func (c *TTL[K, V]) get(k K) (V, *integration.Evidence, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[k]
	if !ok || !c.now().Before(e.exp) {
		if ok {
			delete(c.items, k)
		}
		var zero V
		return zero, nil, false
	}
	return e.v, e.ev, true
}

// fresh runs fill for k now, on the caller's own context, and stores the
// answer (with its evidence) in place of whatever the cache held. Nobody
// waits on it, so a panic propagates to the caller like any other.
func (c *TTL[K, V]) fresh(ctx context.Context, k K, fill func(ctx context.Context) (V, time.Duration, error), rec *integration.Recorder) (V, error) {
	fctx, own := integration.WithRecorder(ctx)
	v, ttl, err := fill(fctx)
	ev := own.Evidence()
	rec.Add(ev, false)
	if err != nil {
		var zero V
		return zero, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl <= 0 {
		delete(c.items, k)
		return v, nil
	}
	c.evictLocked()
	c.items[k] = entry[V]{v: v, exp: c.now().Add(ttl), ev: ev}
	return v, nil
}

// fill runs one fill for k, then always removes the inflight entry and
// closes cl.done, whether fill returned, panicked or called runtime.Goexit.
func (c *TTL[K, V]) fill(k K, cl *call[V], ctx context.Context, fill func(ctx context.Context) (V, time.Duration, error)) {
	var ttl time.Duration
	returned := false
	defer func() {
		if r := recover(); r != nil {
			var zero V
			cl.v, cl.err = zero, &PanicError{Value: r, Stack: debug.Stack()}
		} else if !returned {
			var zero V
			cl.v, cl.err = zero, errors.New("fill exited without returning")
		}
		c.mu.Lock()
		delete(c.inflight, k)
		if cl.err == nil && ttl > 0 {
			c.evictLocked()
			c.items[k] = entry[V]{v: cl.v, exp: c.now().Add(ttl), ev: cl.rec.Evidence()}
		}
		c.mu.Unlock()
		close(cl.done)
	}()
	cl.v, ttl, cl.err = fill(ctx)
	returned = true
}
