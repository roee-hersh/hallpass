package authx

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/cache"
	"github.com/roee-hersh/hallpass/internal/integration"
)

// A token fetch is never evidence: the Fetch runs without the caller's
// Recorder, whether the caller is the one that triggered it or a waiter.
func TestTokenSourceFetchIsNotEvidence(t *testing.T) {
	var sawRecorder atomic.Bool
	src := &TokenSource{Fetch: func(ctx context.Context) (Token, error) {
		if integration.RecorderFrom(ctx) != nil {
			sawRecorder.Store(true)
		}
		return Token{Value: "t"}, nil
	}}
	ctx, rec := integration.WithRecorder(context.Background())
	if _, err := src.Get(ctx); err != nil {
		t.Fatal(err)
	}
	if sawRecorder.Load() || rec.Evidence() != nil {
		t.Fatal("token fetch ran with the check's recorder")
	}
	p := &CachedProvider{Fetch: func(ctx context.Context) (AWSCredentials, error) {
		if integration.RecorderFrom(ctx) != nil {
			sawRecorder.Store(true)
		}
		return AWSCredentials{AccessKeyID: "a", SecretAccessKey: "s"}, nil
	}}
	if _, err := p.Credentials(ctx); err != nil {
		t.Fatal(err)
	}
	if sawRecorder.Load() {
		t.Fatal("credential fetch ran with the check's recorder")
	}
}

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

func TestTokenSourceFetchPanicDoesNotWedge(t *testing.T) {
	var fetches atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	src := &TokenSource{Fetch: func(context.Context) (Token, error) {
		if fetches.Add(1) == 1 {
			close(entered)
			<-release
			panic("boom")
		}
		return Token{Value: "ok"}, nil
	}}
	leaderErr := make(chan error, 1)
	go func() {
		_, err := src.Get(context.Background())
		leaderErr <- err
	}()
	<-entered
	waiterErr := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() {
			_, err := src.Get(context.Background())
			waiterErr <- err
		}()
	}
	time.Sleep(10 * time.Millisecond)
	close(release)
	var pe *cache.PanicError
	if err := <-leaderErr; !errors.As(err, &pe) || pe.Value != "boom" {
		t.Fatalf("leader err = %v", err)
	}
	for i := 0; i < 3; i++ {
		select {
		case err := <-waiterErr:
			if !errors.As(err, &pe) {
				t.Fatalf("waiter err = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("waiter wedged after fetch panic")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	v, err := src.Get(ctx)
	if err != nil || v != "ok" {
		t.Fatalf("after panic: %q %v", v, err)
	}
	if fetches.Load() != 2 {
		t.Fatalf("fetches = %d, want 2", fetches.Load())
	}
}

func TestTokenSourceLeaderCancelDoesNotAbortWaiters(t *testing.T) {
	var fetches atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	src := &TokenSource{Fetch: func(ctx context.Context) (Token, error) {
		fetches.Add(1)
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
		if err := ctx.Err(); err != nil {
			return Token{}, err
		}
		return Token{Value: "t"}, nil
	}}
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := src.Get(leaderCtx)
		leaderErr <- err
	}()
	<-entered
	waiterDone := make(chan struct{})
	var wv string
	var werr error
	go func() {
		defer close(waiterDone)
		wv, werr = src.Get(context.Background())
	}()
	time.Sleep(10 * time.Millisecond)
	cancelLeader()
	if err := <-leaderErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader err = %v", err)
	}
	select {
	case <-waiterDone:
		t.Fatal("waiter returned before the fetch finished")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-waiterDone
	if werr != nil || wv != "t" {
		t.Fatalf("waiter got %q %v; the leader's cancellation aborted the shared fetch", wv, werr)
	}
	if fetches.Load() != 1 {
		t.Fatalf("fetches = %d", fetches.Load())
	}
	if v, err := src.Get(context.Background()); err != nil || v != "t" {
		t.Fatalf("token not cached: %q %v", v, err)
	}
}
