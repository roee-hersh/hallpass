package cache

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/integration"
)

func TestGetSetExpiry(t *testing.T) {
	c := New[string, int](0)
	now := time.Unix(1000, 0)
	c.SetClock(func() time.Time { return now })
	c.Set("a", 1, time.Minute)
	if v, ok := c.Get("a"); !ok || v != 1 {
		t.Fatal("miss")
	}
	now = now.Add(61 * time.Second)
	if _, ok := c.Get("a"); ok {
		t.Fatal("expired entry returned")
	}
	c.Set("b", 2, 0)
	if _, ok := c.Get("b"); ok {
		t.Fatal("zero ttl stored")
	}
}

func TestEvictAtMax(t *testing.T) {
	c := New[int, int](3)
	for i := 0; i < 10; i++ {
		c.Set(i, i, time.Hour)
	}
	if c.Len() > 3 {
		t.Fatalf("len %d", c.Len())
	}
}

func TestDoSingleflight(t *testing.T) {
	c := New[string, int](0)
	var calls atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := c.Do(context.Background(), "k", func(context.Context) (int, time.Duration, error) {
				calls.Add(1)
				<-release
				return 7, time.Minute, nil
			})
			if err != nil || v != 7 {
				t.Errorf("got %d %v", v, err)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("fill called %d times", calls.Load())
	}
	if v, ok := c.Get("k"); !ok || v != 7 {
		t.Fatal("not stored")
	}
}

func TestDoErrorNotStored(t *testing.T) {
	c := New[string, int](0)
	_, err := c.Do(context.Background(), "k", func(context.Context) (int, time.Duration, error) {
		return 0, time.Minute, errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := c.Get("k"); ok {
		t.Fatal("error stored")
	}
	v, err := c.Do(context.Background(), "k", func(context.Context) (int, time.Duration, error) {
		return 1, 0, nil
	})
	if err != nil || v != 1 {
		t.Fatal(v, err)
	}
	if _, ok := c.Get("k"); ok {
		t.Fatal("zero ttl stored")
	}
}

func TestDoContextCancelWhileWaiting(t *testing.T) {
	c := New[string, int](0)
	release := make(chan struct{})
	go c.Do(context.Background(), "k", func(context.Context) (int, time.Duration, error) {
		<-release
		return 1, time.Minute, nil
	})
	time.Sleep(10 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Do(ctx, "k", func(context.Context) (int, time.Duration, error) { return 2, 0, nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	close(release)
}

func TestDoFillPanicDoesNotWedgeKey(t *testing.T) {
	c := New[string, int](0)
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	fill := func(context.Context) (int, time.Duration, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			panic("boom")
		}
		return 9, time.Minute, nil
	}
	var wg sync.WaitGroup
	wg.Add(1)
	var leaderErr error
	go func() {
		defer wg.Done()
		_, leaderErr = c.Do(context.Background(), "k", fill)
	}()
	<-entered
	waiterErrs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() {
			_, err := c.Do(context.Background(), "k", fill)
			waiterErrs <- err
		}()
	}
	time.Sleep(10 * time.Millisecond)
	close(release)
	wg.Wait()
	var pe *PanicError
	if !errors.As(leaderErr, &pe) || pe.Value != "boom" || !strings.Contains(leaderErr.Error(), "boom") {
		t.Fatalf("leader err = %v", leaderErr)
	}
	for i := 0; i < 3; i++ {
		select {
		case err := <-waiterErrs:
			if !errors.As(err, &pe) {
				t.Fatalf("waiter err = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("waiter wedged after fill panic")
		}
	}
	if _, ok := c.Get("k"); ok {
		t.Fatal("panic stored a value")
	}
	// The key is not wedged: the next call runs fill again and succeeds.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	v, err := c.Do(ctx, "k", fill)
	if err != nil || v != 9 {
		t.Fatalf("after panic: %d %v", v, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("fill called %d times, want 2", calls.Load())
	}
}

func TestDoLeaderCancelDoesNotAbortWaiters(t *testing.T) {
	c := New[string, int](0)
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	var fillCtxErr error
	fill := func(ctx context.Context) (int, time.Duration, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
		fillCtxErr = ctx.Err()
		if fillCtxErr != nil {
			return 0, 0, fillCtxErr
		}
		return 7, time.Minute, nil
	}
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := c.Do(leaderCtx, "k", fill)
		leaderDone <- err
	}()
	<-entered
	waiterDone := make(chan struct{})
	var wv int
	var werr error
	go func() {
		defer close(waiterDone)
		wv, werr = c.Do(context.Background(), "k", fill)
	}()
	time.Sleep(10 * time.Millisecond)
	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader err = %v", err)
	}
	select {
	case <-waiterDone:
		t.Fatal("waiter returned before the fill finished")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-waiterDone
	if werr != nil || wv != 7 {
		t.Fatalf("waiter got %d %v; the leader's cancellation aborted the shared fill", wv, werr)
	}
	if fillCtxErr != nil {
		t.Fatalf("fill context was cancelled: %v", fillCtxErr)
	}
	if calls.Load() != 1 {
		t.Fatalf("fill called %d times", calls.Load())
	}
	if v, ok := c.Get("k"); !ok || v != 7 {
		t.Fatal("not stored")
	}
}

type ctxKey struct{}

func TestDetach(t *testing.T) {
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), ctxKey{}, "v"))
	d, dcancel := Detach(parent, time.Minute)
	defer dcancel()
	if d.Value(ctxKey{}) != "v" {
		t.Fatal("value not kept")
	}
	dl, ok := d.Deadline()
	if !ok || time.Until(dl) > time.Minute || time.Until(dl) < 50*time.Second {
		t.Fatalf("fallback deadline %v", dl)
	}
	cancel()
	if d.Err() != nil {
		t.Fatalf("cancellation propagated: %v", d.Err())
	}
	parent2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	d2, dcancel2 := Detach(parent2, time.Minute)
	defer dcancel2()
	dl2, _ := d2.Deadline()
	if time.Until(dl2) > 5*time.Second {
		t.Fatalf("leader deadline not carried: %v", dl2)
	}
}

// Do carries the evidence of a fill to every caller it serves: the leader
// and a waiter get the calls as their own, a later hit gets them marked
// cached, and a fill that failed still reports what it saw to its leader.
func TestDoEvidence(t *testing.T) {
	c := New[string, int](0)
	call := func(p string) integration.Call { return integration.Call{Method: "GET", Path: p, Status: 200} }
	fill := func(ctx context.Context) (int, time.Duration, error) {
		integration.RecorderFrom(ctx).Record(call("/lookup"))
		return 1, time.Minute, nil
	}
	ctx, rec := integration.WithRecorder(context.Background())
	if _, err := c.Do(ctx, "k", fill); err != nil {
		t.Fatal(err)
	}
	if ev := rec.Evidence(); ev == nil || len(ev.Upstream) != 1 || ev.Upstream[0].Cached || ev.Upstream[0].Path != "/lookup" {
		t.Fatalf("leader: %+v", ev)
	}
	// A hit replays the fill's evidence, marked cached.
	ctx2, rec2 := integration.WithRecorder(context.Background())
	if _, err := c.Do(ctx2, "k", fill); err != nil {
		t.Fatal(err)
	}
	if ev := rec2.Evidence(); ev == nil || len(ev.Upstream) != 1 || !ev.Upstream[0].Cached {
		t.Fatalf("hit: %+v", ev)
	}
	// A context without a recorder is fine.
	if _, err := c.Do(context.Background(), "k", fill); err != nil {
		t.Fatal(err)
	}

	// A waiter on another caller's fill gets the calls marked cached; the
	// leader gets them as its own.
	started := make(chan struct{})
	release := make(chan struct{})
	slow := func(ctx context.Context) (int, time.Duration, error) {
		integration.RecorderFrom(ctx).Record(call("/slow"))
		close(started)
		<-release
		return 2, time.Minute, nil
	}
	lctx, lrec := integration.WithRecorder(context.Background())
	wctx, wrec := integration.WithRecorder(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.Do(lctx, "slow", slow) }()
	<-started
	// The waiter joins the in-flight call: its own fill never runs (it
	// would close started twice and panic).
	go func() { defer wg.Done(); c.Do(wctx, "slow", slow) }()
	for c.inflightCount() != 1 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // let the waiter reach Do's select
	close(release)
	wg.Wait()
	// Both saw a call made during their own check: neither is cached.
	if ev := lrec.Evidence(); ev == nil || len(ev.Upstream) != 1 || ev.Upstream[0].Cached {
		t.Fatalf("leader of shared fill: %+v", ev)
	}
	if ev := wrec.Evidence(); ev == nil || len(ev.Upstream) != 1 || ev.Upstream[0].Cached {
		t.Fatalf("waiter: %+v", ev)
	}

	// A failed fill is not stored but its leader still sees the evidence;
	// a fill that asks not to be stored (ttl 0) is live evidence too.
	ectx, erec := integration.WithRecorder(context.Background())
	_, err := c.Do(ectx, "err", func(ctx context.Context) (int, time.Duration, error) {
		integration.RecorderFrom(ctx).Record(integration.Call{Method: "GET", Path: "/err", Status: 503})
		return 0, 0, errors.New("upstream")
	})
	if err == nil {
		t.Fatal("no error")
	}
	if ev := erec.Evidence(); ev == nil || len(ev.Upstream) != 1 || ev.Upstream[0].Status != 503 || ev.Upstream[0].Cached {
		t.Fatalf("failed fill: %+v", ev)
	}
	zctx, zrec := integration.WithRecorder(context.Background())
	c.Do(zctx, "zero", func(ctx context.Context) (int, time.Duration, error) {
		integration.RecorderFrom(ctx).Record(call("/zero"))
		return 0, 0, nil
	})
	if ev := zrec.Evidence(); ev == nil || len(ev.Upstream) != 1 || ev.Upstream[0].Cached {
		t.Fatalf("unstored fill: %+v", ev)
	}
	if _, ok := c.Get("zero"); ok {
		t.Fatal("ttl 0 stored")
	}
	// Set stores no evidence, so a hit on it replays nothing.
	c.Set("set", 3, time.Minute)
	sctx, srec := integration.WithRecorder(context.Background())
	c.Do(sctx, "set", fill)
	if srec.Evidence() != nil {
		t.Fatalf("Set entry has evidence: %+v", srec.Evidence())
	}
}

// inflightCount reports the fills in flight, for the evidence test.
func (c *TTL[K, V]) inflightCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.inflight)
}

// Under a fresh context Do looks the value up again, ignoring the entry
// and any fill in flight, records the calls as its own, and stores the
// answer for the callers after it.
func TestDoFresh(t *testing.T) {
	c := New[string, int](0)
	var fills atomic.Int32
	fill := func(ctx context.Context) (int, time.Duration, error) {
		n := int(fills.Add(1))
		integration.RecorderFrom(ctx).Record(integration.Call{Method: "GET", Path: "/v", Status: 200, ETag: strconv.Itoa(n)})
		return n, time.Minute, nil
	}
	ctx := context.Background()
	if v, _ := c.Do(ctx, "k", fill); v != 1 {
		t.Fatal(v)
	}
	if v, _ := c.Do(ctx, "k", fill); v != 1 || fills.Load() != 1 {
		t.Fatal("not cached")
	}
	fctx, frec := integration.WithRecorder(integration.WithFresh(ctx))
	if v, err := c.Do(fctx, "k", fill); err != nil || v != 2 || fills.Load() != 2 {
		t.Fatalf("fresh: %v %v fills=%d", v, err, fills.Load())
	}
	if ev := frec.Evidence(); ev == nil || len(ev.Upstream) != 1 || ev.Upstream[0].Cached || ev.Upstream[0].ETag != "2" {
		t.Fatalf("fresh evidence: %+v", ev)
	}
	// The fresh answer replaced the entry, evidence included.
	nctx, nrec := integration.WithRecorder(ctx)
	if v, _ := c.Do(nctx, "k", fill); v != 2 || fills.Load() != 2 {
		t.Fatal("fresh answer not stored")
	}
	if ev := nrec.Evidence(); ev == nil || !ev.Upstream[0].Cached || ev.Upstream[0].ETag != "2" {
		t.Fatalf("after fresh: %+v", ev)
	}

	// A fresh caller does not join a fill in flight, and the older fill
	// finishing later does not replace the fresh answer.
	c.SetClock(func() time.Time { return time.Now() })
	started := make(chan struct{})
	release := make(chan struct{})
	slow := func(ctx context.Context) (int, time.Duration, error) {
		close(started)
		<-release
		return 100, time.Minute, nil
	}
	slowDone := make(chan struct{})
	go func() { defer close(slowDone); c.Do(ctx, "slow", slow) }()
	<-started
	time.Sleep(2 * time.Millisecond) // the clock must move past the slow fill's start
	done := make(chan int, 1)
	go func() {
		v, _ := c.Do(integration.WithFresh(ctx), "slow", func(context.Context) (int, time.Duration, error) { return 7, time.Minute, nil })
		done <- v
	}()
	select {
	case v := <-done:
		if v != 7 {
			t.Fatal(v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fresh caller waited for the in-flight fill")
	}
	close(release)
	<-slowDone
	if v, ok := c.Get("slow"); !ok || v != 7 {
		t.Fatalf("older fill replaced the fresh answer: %v %v", v, ok)
	}
	// A fresh fill is joinable: a caller arriving while it runs waits for
	// it rather than starting another.
	var freshFills atomic.Int32
	fstarted := make(chan struct{})
	frelease := make(chan struct{})
	joinable := func(ctx context.Context) (int, time.Duration, error) {
		freshFills.Add(1)
		close(fstarted)
		<-frelease
		return 11, time.Minute, nil
	}
	go c.Do(integration.WithFresh(ctx), "join", joinable)
	<-fstarted
	joined := make(chan int, 1)
	go func() {
		v, _ := c.Do(ctx, "join", func(context.Context) (int, time.Duration, error) {
			freshFills.Add(1)
			return 12, time.Minute, nil
		})
		joined <- v
	}()
	for c.inflightCount() != 1 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
	close(frelease)
	if v := <-joined; v != 11 || freshFills.Load() != 1 {
		t.Fatalf("joined fresh fill: v=%d fills=%d", v, freshFills.Load())
	}
	// A panic in a fresh fill is a PanicError, like any other.
	var pe *PanicError
	if _, err := c.Do(integration.WithFresh(ctx), "boom", func(context.Context) (int, time.Duration, error) { panic("x") }); !errors.As(err, &pe) {
		t.Fatalf("fresh panic: %v", err)
	}

	// A failed fresh lookup stores nothing and leaves the entry; a fresh
	// answer with ttl 0 removes it.
	if _, err := c.Do(integration.WithFresh(ctx), "k", func(context.Context) (int, time.Duration, error) { return 0, time.Minute, errors.New("x") }); err == nil {
		t.Fatal("no error")
	}
	if v, ok := c.Get("k"); !ok || v != 2 {
		t.Fatal("entry lost on a failed fresh lookup")
	}
	if v, err := c.Do(integration.WithFresh(ctx), "k", func(context.Context) (int, time.Duration, error) { return 9, 0, nil }); err != nil || v != 9 {
		t.Fatal(v, err)
	}
	if _, ok := c.Get("k"); ok {
		t.Fatal("ttl 0 fresh answer stored")
	}
}
