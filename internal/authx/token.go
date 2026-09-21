package authx

import (
	"context"
	"errors"
	"sync"
	"time"
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
	inflght chan struct{}
	err     error
}

// Get returns a valid token, fetching one if needed.
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
	if s.inflght != nil {
		ch := s.inflght
		s.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return "", ctx.Err()
		}
		s.mu.Lock()
		v, err := s.tok.Value, s.err
		s.mu.Unlock()
		if err != nil {
			return "", err
		}
		return v, nil
	}
	ch := make(chan struct{})
	s.inflght = ch
	s.mu.Unlock()

	tok, err := s.Fetch(ctx)
	s.mu.Lock()
	s.inflght = nil
	s.err = err
	if err == nil {
		s.tok = tok
		s.exp = s.expiryOf(tok, now)
	}
	s.mu.Unlock()
	close(ch)
	if err != nil {
		return "", err
	}
	return tok.Value, nil
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
