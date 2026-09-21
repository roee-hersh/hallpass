package authx

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenSourceCachesAndRefreshesEarly(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	var fetches atomic.Int32
	src := &TokenSource{
		Now: func() time.Time { return now },
		Fetch: func(context.Context) (Token, error) {
			n := fetches.Add(1)
			return Token{Value: "tok" + string(rune('0'+n)), Expiry: now.Add(time.Hour)}, nil
		},
	}
	ctx := context.Background()
	v, err := src.Get(ctx)
	if err != nil || v != "tok1" {
		t.Fatal(v, err)
	}
	now = now.Add(50 * time.Minute)
	if v, _ := src.Get(ctx); v != "tok1" {
		t.Fatal("refetched too early")
	}
	now = now.Add(6 * time.Minute) // 56 min: within 5 min of expiry
	if v, _ := src.Get(ctx); v != "tok2" {
		t.Fatalf("not refreshed early: %s", v)
	}
	src.Invalidate()
	if v, _ := src.Get(ctx); v != "tok3" {
		t.Fatalf("invalidate: %s", v)
	}
}

func TestTokenSourceDefaultTTLAndShortTokens(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	var fetches atomic.Int32
	src := &TokenSource{
		Now: func() time.Time { return now },
		Fetch: func(context.Context) (Token, error) {
			fetches.Add(1)
			return Token{Value: "t"}, nil
		},
	}
	src.Get(context.Background())
	now = now.Add(9 * time.Minute)
	src.Get(context.Background())
	if fetches.Load() != 1 {
		t.Fatal("default ttl 15m minus 5m early should still be cached at 9m")
	}
	now = now.Add(2 * time.Minute)
	src.Get(context.Background())
	if fetches.Load() != 2 {
		t.Fatal("should refresh at 10m")
	}
	// A 2-minute token refreshes at its half life, not immediately.
	src2 := &TokenSource{Now: func() time.Time { return now }, Fetch: func(context.Context) (Token, error) {
		fetches.Add(1)
		return Token{Value: "s", Expiry: now.Add(2 * time.Minute)}, nil
	}}
	fetches.Store(0)
	src2.Get(context.Background())
	now = now.Add(30 * time.Second)
	src2.Get(context.Background())
	if fetches.Load() != 1 {
		t.Fatal("short token refetched before half life")
	}
	now = now.Add(45 * time.Second)
	src2.Get(context.Background())
	if fetches.Load() != 2 {
		t.Fatal("short token not refreshed after half life")
	}
}

func TestTokenSourceSingleflightAndErrors(t *testing.T) {
	var fetches atomic.Int32
	release := make(chan struct{})
	src := &TokenSource{Fetch: func(context.Context) (Token, error) {
		fetches.Add(1)
		<-release
		return Token{Value: "t"}, nil
	}}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, err := src.Get(context.Background()); err != nil || v != "t" {
				t.Error(v, err)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if fetches.Load() != 1 {
		t.Fatalf("fetches = %d", fetches.Load())
	}
	failing := &TokenSource{Fetch: func(context.Context) (Token, error) { return Token{}, errors.New("nope") }}
	if _, err := failing.Get(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if _, err := (&TokenSource{}).Get(context.Background()); err == nil {
		t.Fatal("no fetch")
	}
}
