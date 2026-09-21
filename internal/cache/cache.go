// Package cache is a small generic TTL cache with singleflight: concurrent
// callers for the same missing key share one fill.
package cache

import (
	"context"
	"sync"
	"time"
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
}

type call[V any] struct {
	done chan struct{}
	v    V
	err  error
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
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[k]
	if !ok {
		var zero V
		return zero, false
	}
	if !c.now().Before(e.exp) {
		delete(c.items, k)
		var zero V
		return zero, false
	}
	return e.v, true
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

// Do returns the cached value for k or calls fill once, sharing the result
// with concurrent callers. The fill decides the TTL by returning it; a TTL
// of 0 means "do not store". Errors are never stored.
func (c *TTL[K, V]) Do(ctx context.Context, k K, fill func(ctx context.Context) (V, time.Duration, error)) (V, error) {
	if v, ok := c.Get(k); ok {
		return v, nil
	}
	c.mu.Lock()
	if cl, ok := c.inflight[k]; ok {
		c.mu.Unlock()
		select {
		case <-cl.done:
			return cl.v, cl.err
		case <-ctx.Done():
			var zero V
			return zero, ctx.Err()
		}
	}
	cl := &call[V]{done: make(chan struct{})}
	c.inflight[k] = cl
	c.mu.Unlock()

	v, ttl, err := fill(ctx)
	cl.v, cl.err = v, err
	c.mu.Lock()
	delete(c.inflight, k)
	if err == nil && ttl > 0 {
		c.evictLocked()
		c.items[k] = entry[V]{v: v, exp: c.now().Add(ttl)}
	}
	c.mu.Unlock()
	close(cl.done)
	return v, err
}
