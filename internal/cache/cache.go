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

	"github.com/roee-hersh/hallpass/internal/evidence"
)

// TTL is a bounded, time-limited map. Zero or negative TTLs disable storage
// but Do still collapses concurrent fills.
type TTL[K comparable, V any] struct {
	mu       sync.Mutex
	items    map[K]entry[V]
	inflight map[K]*call[V]
	// fresh holds the fills started for fresh checks, apart from the
	// ordinary ones: a fresh caller never waits on an ordinary fill.
	fresh       map[K]*call[V]
	max         int
	now         func() time.Time
	freshMaxAge time.Duration
	// joined, when set, is told under mu of every caller that joins a
	// fill rather than starting one. Tests set it to wait for the callers
	// they want on a fill.
	joined func(k K, fresh bool)
	joins  func(k K, fresh bool) int
}

type entry[V any] struct {
	v   V
	exp time.Time
	// started is when the read that produced v began, or the oldest
	// cached read it rests on; a read that began earlier does not
	// replace it.
	started time.Time
	// ev is the evidence of the fill that produced v, replayed on hits.
	ev *evidence.Evidence
}

type call[V any] struct {
	done chan struct{}
	v    V
	err  error
	// started is when the fill began, for the newer-entry check on store.
	started time.Time
	// fresh marks a fill started for a fresh check: an answer it may not
	// store still removes the older entry, which it has just superseded.
	fresh bool
	// rec is the fill's own Recorder, and ev its evidence, snapshotted
	// once by the fill before done is closed; readAt is the fill's date,
	// its start or the oldest cached read it rested on, whichever is
	// earlier. ended is set when the fill's own context had ended by the
	// time it returned: it ran out of its leader's time, not of luck with
	// the upstream.
	rec    *evidence.Recorder
	ev     *evidence.Evidence
	readAt time.Time
	ended  bool
}

// FreshJoinWindow is how recently an entry must have been read for a
// fresh caller to take it rather than read again: a fresh answer is one
// from a read still in flight when the caller asked, or that began no
// earlier than this before, so back-to-back fresh checks share one read.
const FreshJoinWindow = time.Second

// New creates a cache holding at most max entries (0 means 10000).
func New[K comparable, V any](max int) *TTL[K, V] {
	if max <= 0 {
		max = 10000
	}
	return &TTL[K, V]{
		items:    make(map[K]entry[V]),
		inflight: make(map[K]*call[V]),
		fresh:    make(map[K]*call[V]),
		max:      max,
		now:      time.Now,
	}
}

// SetFreshMaxAge lets a fresh check take a read that began less than d
// ago, an entry or a fill in flight, instead of reading again, when d is
// longer than FreshJoinWindow. For a bulk listing (an organization's whole
// identity index) that a fresh check has no business re-paging every time.
func (c *TTL[K, V]) SetFreshMaxAge(d time.Duration) {
	c.mu.Lock()
	c.freshMaxAge = d
	c.mu.Unlock()
}

// SetClock replaces the time source. Tests use it.
func (c *TTL[K, V]) SetClock(now func() time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

// Get returns the cached value when present and not expired.
func (c *TTL[K, V]) Get(k K) (V, bool) {
	e, ok := c.entry(k)
	return e.v, ok
}

// entry returns k's entry when present and not expired.
func (c *TTL[K, V]) entry(k K) (entry[V], bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getLocked(k, c.now())
}

// Set stores v for ttl, as a value read now. A ttl <= 0 removes the key.
func (c *TTL[K, V]) Set(k K, v V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.storeLocked(k, v, ttl, nil, now, now)
}

// Store is Set for a value read from the upstream at started: it is
// skipped when the entry already there came from a read that began later,
// which saw the upstream more recently. A fresh check's answer in
// particular must not be replaced by an older read that finished after it.
func (c *TTL[K, V]) Store(k K, v V, ttl time.Duration, started time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.storeLocked(k, v, ttl, nil, started, c.now())
}

// storeLocked stores the result of a read that began at started, unless
// the entry already there came from a read that began later. A ttl <= 0
// stores nothing and removes such an older entry.
func (c *TTL[K, V]) storeLocked(k K, v V, ttl time.Duration, ev *evidence.Evidence, started, now time.Time) {
	// An expired resident is no resident: getLocked drops it.
	if e, ok := c.getLocked(k, now); ok && e.started.After(started) {
		return
	}
	if ttl <= 0 {
		delete(c.items, k)
		return
	}
	c.evictLocked(now)
	c.items[k] = entry[V]{v: v, exp: now.Add(ttl), started: started, ev: ev}
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
func (c *TTL[K, V]) evictLocked(now time.Time) {
	if len(c.items) < c.max {
		return
	}
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
// evidence.Recorder). The fill runs on its own Recorder; the caller
// that started it gets the calls on its context's Recorder as its own,
// one that waited for it gets them marked shared, and a later hit on the
// stored entry gets them marked cached. So a decision served from a
// cached lookup still shows what the upstream said when the lookup was
// made.
//
// Under a fresh context (evidence.WithFresh) Do takes an entry only when
// it was read within FreshJoinWindow (or the fresh max age, when longer),
// joins the fresh fill in flight if there is one, and otherwise starts a
// fresh fill of its own, kept apart from the ordinary one so neither
// displaces the other; its answer replaces the entry unless an even later
// read stored one first. A fresh read that fails leaves the entry as it
// was. An ordinary caller takes the entry, else joins the ordinary fill,
// else the fresh one.
//
// The fill runs in its own goroutine on a context detached from the first
// caller's cancellation (see Detach) rather than on ctx itself: otherwise
// that caller going away would abort the fill and hand every waiter a
// context.Canceled that is not theirs. Each caller, the first included,
// stops waiting when its own ctx is done; a waiter whose leader's deadline
// ended the fill fills again with its own. A panic in fill becomes a
// *PanicError for everyone waiting on it.
func (c *TTL[K, V]) Do(ctx context.Context, k K, fill func(ctx context.Context) (V, time.Duration, error)) (V, error) {
	rec := evidence.RecorderFrom(ctx)
	fresh := evidence.Fresh(ctx)
	for {
		v, err, again := c.do(ctx, k, fill, rec, fresh)
		if !again {
			return v, err
		}
		// The fill this caller waited on ended with its leader's
		// deadline; the caller has time, so it goes round again, on
		// whatever fill is in flight by now or one of its own.
	}
}

// do is one round of Do. again asks for another round: the caller waited
// on a fill that ended with its leader's context, not with the upstream,
// and its own context still lives.
func (c *TTL[K, V]) do(ctx context.Context, k K, fill func(ctx context.Context) (V, time.Duration, error), rec *evidence.Recorder, fresh bool) (v V, err error, again bool) {
	c.mu.Lock()
	now := c.now()
	// The entry answers an ordinary caller; a fresh caller takes it only
	// while it is younger than the join window (or the cache's fresh max
	// age, when longer).
	if e, hit := c.getLocked(k, now); hit && (!fresh || c.youngLocked(e, now)) {
		c.mu.Unlock()
		// An entry a fresh caller takes counts as read now: the
		// staleness is accepted, and must not date the fresh decision
		// older than an ordinary one that rests on the same entry.
		readAt := e.started
		if fresh {
			readAt = now
		}
		rec.AddAt(e.ev, evidence.Cached, readAt)
		return e.v, nil, false
	}
	// A fresh caller shares a fresh fill still in flight (its answer is
	// no older than that fill's start, which the caller would otherwise
	// reproduce) and an ordinary fill that began within the window;
	// otherwise it reads on its own. An ordinary caller joins the
	// ordinary fill in flight, or, when there is none, a fresh one.
	var cl *call[V]
	if fresh {
		if fc, ok := c.fresh[k]; ok {
			cl = fc
		} else if oc, ok := c.inflight[k]; ok && now.Sub(oc.started) < c.freshWindow() {
			cl = oc
		}
	} else if oc, ok := c.inflight[k]; ok {
		cl = oc
	} else if fc, ok := c.fresh[k]; ok {
		cl = fc
	}
	leader := cl == nil
	if leader {
		cl = &call[V]{done: make(chan struct{}), started: now, fresh: fresh}
		if fresh {
			c.fresh[k] = cl
		} else {
			c.inflight[k] = cl
		}
		fctx, cancel := Detach(ctx, DefaultFillTimeout)
		fctx, cl.rec = evidence.WithRecorder(fctx)
		go func() {
			defer cancel()
			c.fill(k, cl, fctx, fill)
		}()
	} else if c.joined != nil {
		c.joined(k, fresh)
	}
	c.mu.Unlock()
	select {
	case <-cl.done:
		// cl is complete: the fill's goroutine closed done after its
		// last write.
		by := evidence.Own
		if !leader {
			by = evidence.Shared
		}
		if cl.err != nil {
			if !fresh {
				// The fill failed; an entry may have landed meanwhile
				// (another fill's, a fresh read's), and answers an
				// ordinary caller, leader or not. What the failed fill
				// did complete stays on the record, undated: the answer
				// is the entry's.
				if e, ok := c.entry(k); ok {
					rec.Add(cl.ev, by)
					rec.AddAt(e.ev, evidence.Cached, e.started)
					return e.v, nil, false
				}
			}
			if !leader && cl.ended && ctx.Err() == nil {
				// The fill ran on the leader's remaining deadline and
				// ended because of it; this caller still has time. What
				// the ended fill did complete stays on the record,
				// undated likewise.
				rec.Add(cl.ev, evidence.Shared)
				return v, nil, true
			}
		}
		// A fresh caller that joined a read accepted it as current, like
		// an entry it takes under the window: dated by its arrival.
		readAt := cl.readAt
		if fresh && !leader {
			readAt = now
		}
		rec.AddAt(cl.ev, by, readAt)
		return cl.v, cl.err, false
	case <-ctx.Done():
		return v, ctx.Err(), false
	}
}

// youngLocked reports whether e is young enough for a fresh check to take:
// read within the join window, or the cache's fresh max age when longer.
func (c *TTL[K, V]) youngLocked(e entry[V], now time.Time) bool {
	return now.Sub(e.started) < c.freshWindow()
}

// freshWindow is how far back a read may have begun for a fresh caller
// to take it.
func (c *TTL[K, V]) freshWindow() time.Duration {
	return max(FreshJoinWindow, c.freshMaxAge)
}

// getLocked returns k's entry when present and not expired at now,
// dropping an expired one.
func (c *TTL[K, V]) getLocked(k K, now time.Time) (entry[V], bool) {
	e, ok := c.items[k]
	if !ok || !now.Before(e.exp) {
		if ok {
			delete(c.items, k)
		}
		return entry[V]{}, false
	}
	return e, true
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
		cl.ev = cl.rec.Evidence()
		cl.ended = ctx.Err() != nil
		// The fill is as old as the oldest cached read it rested on, so
		// an entry or a decision built on older inputs does not replace
		// a newer one.
		cl.readAt = cl.started
		if o, ok := cl.rec.Oldest(); ok && o.Before(cl.readAt) {
			cl.readAt = o
		}
		c.mu.Lock()
		inflight := c.inflight
		if cl.fresh {
			inflight = c.fresh
		}
		if inflight[k] == cl {
			delete(inflight, k)
		}
		if cl.err == nil && (ttl > 0 || cl.fresh) {
			// A fresh answer that may not be stored still removes the
			// older entry it has just superseded.
			c.storeLocked(k, cl.v, ttl, cl.ev, cl.readAt, c.now())
		}
		c.mu.Unlock()
		close(cl.done)
	}()
	cl.v, ttl, cl.err = fill(ctx)
	returned = true
}
