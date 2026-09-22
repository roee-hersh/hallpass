package authx

import (
	"context"
	"errors"
	"runtime/debug"
	"sync"
	"time"

	"github.com/roee-hersh/hallpass/internal/cache"
)

// Token is a bearer token with its expiry.
type Token struct {
	Value  string
	Expiry time.Time // zero means unknown; the source's TTL applies
}

// TokenSource obtains and caches a token, refreshing it shortly before it
// expires. Concurrent callers share one refresh.
type TokenSource struct {
	// Fetch obtains a fresh token.
	Fetch func(ctx context.Context) (Token, error)
	// Early is how long before expiry a refresh starts (default 5 min).
	Early time.Duration
	// DefaultTTL applies when a token has no known expiry (default 15 min).
	DefaultTTL time.Duration
	// Now is the clock (default time.Now).
	Now func() time.Time

	mu      sync.Mutex
	tok     Token
	exp     time.Time
	inflght *fetchCall
}

// fetchCall is one shared Fetch; done closes once tok and err are set.
type fetchCall struct {
	done chan struct{}
	tok  Token
	err  error
}

// defaultFetchTimeout bounds a Fetch whose caller's context has no deadline.
const defaultFetchTimeout = 30 * time.Second

// Get returns a valid token, fetching one if needed.
//
// The shared Fetch runs in its own goroutine on a context detached from the
// first caller's cancellation (cache.Detach): otherwise that caller going
// away would abort the fetch and hand every waiter a context.Canceled that
// is not theirs. Each caller stops waiting when its own ctx is done. A
// panic in Fetch becomes a *cache.PanicError for everyone waiting on it.
func (s *TokenSource) Get(ctx context.Context) (string, error) {
	if s.Fetch == nil {
		return "", errors.New("token source has no fetch function")
	}
	now := s.now()
	s.mu.Lock()
	if s.tok.Value != "" && now.Before(s.exp) {
		v := s.tok.Value
		s.mu.Unlock()
		return v, nil
	}
	fc := s.inflght
	if fc == nil {
		fc = &fetchCall{done: make(chan struct{})}
		s.inflght = fc
		fctx, cancel := cache.Detach(ctx, defaultFetchTimeout)
		go func() {
			defer cancel()
			s.fetch(fc, fctx, now)
		}()
	}
	s.mu.Unlock()
	select {
	case <-fc.done:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if fc.err != nil {
		return "", fc.err
	}
	return fc.tok.Value, nil
}

// fetch runs one Fetch for fc, then always clears the inflight call and
// closes fc.done, whether Fetch returned, panicked or called runtime.Goexit.
func (s *TokenSource) fetch(fc *fetchCall, ctx context.Context, now time.Time) {
	returned := false
	defer func() {
		if r := recover(); r != nil {
			fc.tok, fc.err = Token{}, &cache.PanicError{Value: r, Stack: debug.Stack()}
		} else if !returned {
			fc.tok, fc.err = Token{}, errors.New("token fetch exited without returning")
		}
		s.mu.Lock()
		s.inflght = nil
		if fc.err == nil {
			s.tok = fc.tok
			s.exp = s.expiryOf(fc.tok, now)
		}
		s.mu.Unlock()
		close(fc.done)
	}()
	fc.tok, fc.err = s.Fetch(ctx)
	returned = true
}

// Invalidate drops the cached token so the next Get fetches again. Call it
// when the upstream rejected the token.
func (s *TokenSource) Invalidate() {
	s.mu.Lock()
	s.tok = Token{}
	s.exp = time.Time{}
	s.mu.Unlock()
}

func (s *TokenSource) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *TokenSource) expiryOf(t Token, now time.Time) time.Time {
	early := s.Early
	if early == 0 {
		early = 5 * time.Minute
	}
	exp := t.Expiry
	if exp.IsZero() {
		ttl := s.DefaultTTL
		if ttl == 0 {
			ttl = 15 * time.Minute
		}
		exp = now.Add(ttl)
	}
	refreshAt := exp.Add(-early)
	// Very short-lived tokens: refresh at half life rather than immediately.
	if !refreshAt.After(now) {
		half := exp.Sub(now) / 2
		if half <= 0 {
			half = time.Second
		}
		refreshAt = now.Add(half)
	}
	return refreshAt
}
