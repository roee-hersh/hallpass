package cache

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/roee-hersh/hallpass/internal/evidence"
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
// gets the calls as its own, a waiter gets them marked shared, a later hit
// gets them marked cached, and a fill that failed still reports what it
// saw to its leader.
func TestDoEvidence(t *testing.T) {
	trackJoins(t)
	c := New[string, int](0)
	call := func(p string) evidence.Call { return evidence.Call{Method: "GET", Path: p, Status: 200} }
	fill := func(ctx context.Context) (int, time.Duration, error) {
		evidence.RecorderFrom(ctx).Record(call("/lookup"))
		return 1, time.Minute, nil
	}
	ctx, rec := evidence.WithRecorder(context.Background())
	if _, err := c.Do(ctx, "k", fill); err != nil {
		t.Fatal(err)
	}
	if ev := rec.Evidence(); ev == nil || len(ev.Calls()) != 1 || ev.Calls()[0].Cached || ev.Calls()[0].Path != "/lookup" {
		t.Fatalf("leader: %+v", ev)
	}
	// A hit replays the fill's evidence, marked cached.
	ctx2, rec2 := evidence.WithRecorder(context.Background())
	if _, err := c.Do(ctx2, "k", fill); err != nil {
		t.Fatal(err)
	}
	if ev := rec2.Evidence(); ev == nil || len(ev.Calls()) != 1 || !ev.Calls()[0].Cached {
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
		evidence.RecorderFrom(ctx).Record(call("/slow"))
		close(started)
		<-release
		return 2, time.Minute, nil
	}
	lctx, lrec := evidence.WithRecorder(context.Background())
	wctx, wrec := evidence.WithRecorder(context.Background())
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
	c.awaitWaiters(t, "slow", 1, 0)
	close(release)
	wg.Wait()
	// The leader made the call; the waiter joined it: shared, not cached.
	if ev := lrec.Evidence(); ev == nil || len(ev.Calls()) != 1 || ev.Calls()[0].Cached || ev.Calls()[0].Shared {
		t.Fatalf("leader of shared fill: %+v", ev)
	}
	if ev := wrec.Evidence(); ev == nil || len(ev.Calls()) != 1 || ev.Calls()[0].Cached || !ev.Calls()[0].Shared {
		t.Fatalf("waiter: %+v", ev)
	}

	// A failed fill is not stored but its leader still sees the evidence;
	// a fill that asks not to be stored (ttl 0) is live evidence too.
	ectx, erec := evidence.WithRecorder(context.Background())
	_, err := c.Do(ectx, "err", func(ctx context.Context) (int, time.Duration, error) {
		evidence.RecorderFrom(ctx).Record(evidence.Call{Method: "GET", Path: "/err", Status: 503})
		return 0, 0, errors.New("upstream")
	})
	if err == nil {
		t.Fatal("no error")
	}
	if ev := erec.Evidence(); ev == nil || len(ev.Calls()) != 1 || ev.Calls()[0].Status != 503 || ev.Calls()[0].Cached {
		t.Fatalf("failed fill: %+v", ev)
	}
	zctx, zrec := evidence.WithRecorder(context.Background())
	c.Do(zctx, "zero", func(ctx context.Context) (int, time.Duration, error) {
		evidence.RecorderFrom(ctx).Record(call("/zero"))
		return 0, 0, nil
	})
	if ev := zrec.Evidence(); ev == nil || len(ev.Calls()) != 1 || ev.Calls()[0].Cached {
		t.Fatalf("unstored fill: %+v", ev)
	}
	if _, ok := c.Get("zero"); ok {
		t.Fatal("ttl 0 stored")
	}
	// Set stores no evidence, so a hit on it replays nothing.
	c.Set("set", 3, time.Minute)
	sctx, srec := evidence.WithRecorder(context.Background())
	c.Do(sctx, "set", fill)
	if srec.Evidence() != nil {
		t.Fatalf("Set entry has evidence: %+v", srec.Evidence())
	}
}

// inflightCount reports the fills in flight, for the evidence test.
func (c *TTL[K, V]) inflightCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.inflight) + len(c.fresh)
}

// joins counts, per key and kind, the callers that joined a fill since
// trackJoins was called, through the package's test hook.
var joins struct {
	mu sync.Mutex
	n  map[string]int
}

func joinKey(k any, fresh bool) string { return fmt.Sprintf("%v/%v", k, fresh) }

// trackJoins installs the hook for the test's lifetime.
func trackJoins(t *testing.T) {
	t.Helper()
	joins.mu.Lock()
	joins.n = map[string]int{}
	joins.mu.Unlock()
	joined = func(k any, fresh bool) {
		joins.mu.Lock()
		joins.n[joinKey(k, fresh)]++
		joins.mu.Unlock()
	}
	t.Cleanup(func() { joined = nil })
}

// awaitWaiters spins until at least ordinary ordinary callers and fresh
// fresh callers have joined a fill for k (whichever fill they joined)
// since trackJoins, so a test releases a fill only once the callers it
// wants on it have joined.
func (c *TTL[K, V]) awaitWaiters(t *testing.T, k K, ordinary, fresh int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		joins.mu.Lock()
		o, f := joins.n[joinKey(k, false)], joins.n[joinKey(k, true)]
		joins.mu.Unlock()
		if o >= ordinary && f >= fresh {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("waiters on %v did not arrive", k)
}

// awaitFresh spins until k has (or no longer has) a fresh fill in flight.
func (c *TTL[K, V]) awaitFresh(t *testing.T, k K, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		_, ok := c.fresh[k]
		c.mu.Unlock()
		if ok == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("fresh fill on %v: in flight = %v, want %v", k, !want, want)
}

// Under a fresh context Do looks the value up again, ignoring the entry
// and any fill in flight, records the calls as its own, and stores the
// answer for the callers after it.
func TestDoFresh(t *testing.T) {
	trackJoins(t)
	c := New[string, int](0)
	var clockMu sync.Mutex
	clock := time.Now()
	c.SetClock(func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock })
	tick := func(d time.Duration) { clockMu.Lock(); clock = clock.Add(d); clockMu.Unlock() }
	var fills atomic.Int32
	fill := func(ctx context.Context) (int, time.Duration, error) {
		n := int(fills.Add(1))
		evidence.RecorderFrom(ctx).Record(evidence.Call{Method: "GET", Path: "/v", Status: 200, ETag: strconv.Itoa(n)})
		return n, time.Minute, nil
	}
	ctx := context.Background()
	if v, _ := c.Do(ctx, "k", fill); v != 1 {
		t.Fatal(v)
	}
	if v, _ := c.Do(ctx, "k", fill); v != 1 || fills.Load() != 1 {
		t.Fatal("not cached")
	}
	// Within the join window a fresh caller takes the entry, dated now;
	// past it, it reads again.
	if v, _ := c.Do(evidence.WithFresh(ctx), "k", fill); v != 1 || fills.Load() != 1 {
		t.Fatalf("fresh caller re-read an entry younger than the window: v=%d fills=%d", v, fills.Load())
	}
	tick(FreshJoinWindow)
	fctx, frec := evidence.WithRecorder(evidence.WithFresh(ctx))
	if v, err := c.Do(fctx, "k", fill); err != nil || v != 2 || fills.Load() != 2 {
		t.Fatalf("fresh: %v %v fills=%d", v, err, fills.Load())
	}
	if ev := frec.Evidence(); ev == nil || len(ev.Calls()) != 1 || ev.Calls()[0].Cached || ev.Calls()[0].ETag != "2" {
		t.Fatalf("fresh evidence: %+v", ev)
	}
	// The fresh answer replaced the entry, evidence included.
	nctx, nrec := evidence.WithRecorder(ctx)
	if v, _ := c.Do(nctx, "k", fill); v != 2 || fills.Load() != 2 {
		t.Fatal("fresh answer not stored")
	}
	if ev := nrec.Evidence(); ev == nil || !ev.Calls()[0].Cached || ev.Calls()[0].ETag != "2" {
		t.Fatalf("after fresh: %+v", ev)
	}

	// A fresh caller does not join an ordinary fill in flight, and the
	// older fill finishing later does not replace the fresh answer.
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
	tick(time.Millisecond) // the fresh read begins after the slow fill's start
	done := make(chan int, 1)
	go func() {
		v, _ := c.Do(evidence.WithFresh(ctx), "slow", func(context.Context) (int, time.Duration, error) { return 7, time.Minute, nil })
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
	// The other order: the older fill stores while the fresh one is still
	// running. The fresh answer still stands, since its read began later.
	started2 := make(chan struct{})
	release2 := make(chan struct{})
	slow2 := func(ctx context.Context) (int, time.Duration, error) {
		close(started2)
		<-release2
		return 100, time.Minute, nil
	}
	slowDone2 := make(chan struct{})
	go func() { defer close(slowDone2); c.Do(ctx, "order", slow2) }()
	<-started2
	tick(time.Millisecond)
	fstarted2 := make(chan struct{})
	frelease2 := make(chan struct{})
	freshDone2 := make(chan struct{})
	go func() {
		defer close(freshDone2)
		c.Do(evidence.WithFresh(ctx), "order", func(context.Context) (int, time.Duration, error) {
			close(fstarted2)
			<-frelease2
			return 7, time.Minute, nil
		})
	}()
	<-fstarted2
	close(release2) // the older read stores first
	<-slowDone2
	if v, ok := c.Get("order"); !ok || v != 100 {
		t.Fatalf("older read not stored while the fresh one runs: %v %v", v, ok)
	}
	close(frelease2)
	<-freshDone2
	if v, ok := c.Get("order"); !ok || v != 7 {
		t.Fatalf("fresh answer lost to an older read that stored first: %v %v", v, ok)
	}
	// Store (the engine's decision cache) follows the same rule.
	c.Store("order", 1, time.Minute, clock.Add(-time.Hour))
	if v, _ := c.Get("order"); v != 7 {
		t.Fatal("Store replaced a newer entry")
	}
	tick(time.Millisecond)
	c.Store("order", 2, time.Minute, clock)
	if v, _ := c.Get("order"); v != 2 {
		t.Fatal("Store did not replace an older entry")
	}
	c.Store("order", 3, 0, clock.Add(-time.Hour))
	if _, ok := c.Get("order"); !ok {
		t.Fatal("Store with ttl 0 dropped a newer entry")
	}
	c.Store("order", 3, 0, clock)
	if _, ok := c.Get("order"); ok {
		t.Fatal("Store with ttl 0 kept an older entry")
	}

	// Fresh fills are kept apart from ordinary ones: an ordinary caller
	// joins the ordinary fill in flight, a fresh one within the join
	// window shares the fresh fill, one arriving later reads again, and
	// the latest read's answer is what the cache keeps.
	var freshFills atomic.Int32
	ostarted := make(chan struct{})
	orelease := make(chan struct{})
	ordinary := func(ctx context.Context) (int, time.Duration, error) {
		close(ostarted)
		<-orelease
		return 10, time.Minute, nil
	}
	ordinaryDone := make(chan int, 1)
	go func() { v, _ := c.Do(ctx, "join", ordinary); ordinaryDone <- v }()
	<-ostarted
	fstarted := make(chan struct{})
	frelease := make(chan struct{})
	joinable := func(ctx context.Context) (int, time.Duration, error) {
		freshFills.Add(1)
		close(fstarted)
		<-frelease
		return 11, time.Minute, nil
	}
	freshDone := make(chan int, 1)
	go func() { v, _ := c.Do(evidence.WithFresh(ctx), "join", joinable); freshDone <- v }()
	<-fstarted
	joined := make(chan int, 1)
	another := func(context.Context) (int, time.Duration, error) {
		freshFills.Add(1)
		return 12, time.Minute, nil
	}
	go func() { v, _ := c.Do(ctx, "join", another); joined <- v }()
	freshJoined := make(chan int, 1)
	go func() { v, _ := c.Do(evidence.WithFresh(ctx), "join", another); freshJoined <- v }()
	c.awaitWaiters(t, "join", 1, 1)
	clockMu.Lock()
	clock = clock.Add(FreshJoinWindow)
	clockMu.Unlock()
	if v, _ := c.Do(evidence.WithFresh(ctx), "join", another); v != 12 || freshFills.Load() != 2 {
		t.Fatalf("late fresh caller joined a fill older than the window: v=%d fills=%d", v, freshFills.Load())
	}
	close(frelease)
	if v := <-freshJoined; v != 11 {
		t.Fatalf("fresh caller within the window did not share the fresh fill: %d", v)
	}
	if v := <-freshDone; v != 11 {
		t.Fatalf("fresh fill: v=%d", v)
	}
	close(orelease)
	if v := <-joined; v != 10 {
		t.Fatalf("ordinary caller did not join the ordinary fill: %d", v)
	}
	if v := <-ordinaryDone; v != 10 {
		t.Fatalf("ordinary leader lost its fill: %d", v)
	}
	if v, _ := c.Get("join"); v != 12 {
		t.Fatalf("an older read replaced the latest fresh answer: %d", v)
	}

	// An ordinary caller with a valid entry takes it even while a fresh
	// read is in flight, and never waits on it.
	c.Set("keep", 1, time.Minute)
	tick(FreshJoinWindow)
	dstarted := make(chan struct{})
	drelease := make(chan struct{})
	go c.Do(evidence.WithFresh(ctx), "keep", func(context.Context) (int, time.Duration, error) {
		close(dstarted)
		<-drelease
		return 2, time.Minute, nil
	})
	<-dstarted
	if v, _ := c.Do(ctx, "keep", func(context.Context) (int, time.Duration, error) { return 3, time.Minute, nil }); v != 1 {
		t.Fatalf("ordinary caller got %d while a fresh read was in flight, want the entry's 1", v)
	}
	close(drelease)
	c.awaitFresh(t, "keep", false)
	if v, _ := c.Get("keep"); v != 2 {
		t.Fatalf("fresh answer not stored: %d", v)
	}
	// With no entry and no ordinary fill, an ordinary caller joins the
	// fresh read (shared); when that read fails it gets the failure,
	// unless an entry has landed meanwhile.
	fstart := make(chan struct{})
	ffail := make(chan struct{})
	ferr := make(chan error, 1)
	go func() {
		_, err := c.Do(evidence.WithFresh(ctx), "joinfail", func(context.Context) (int, time.Duration, error) {
			close(fstart)
			<-ffail
			return 0, 0, errors.New("upstream")
		})
		ferr <- err
	}()
	<-fstart
	octx, orec := evidence.WithRecorder(ctx)
	ogot := make(chan error, 1)
	go func() {
		_, err := c.Do(octx, "joinfail", func(context.Context) (int, time.Duration, error) { return 3, time.Minute, nil })
		ogot <- err
	}()
	c.awaitWaiters(t, "joinfail", 1, 0)
	close(ffail)
	if err := <-ferr; err == nil {
		t.Fatal("fresh caller did not get the error")
	}
	if err := <-ogot; err == nil {
		t.Fatal("ordinary caller that joined the failed fresh read got no error")
	}
	if ev := orec.Evidence(); ev != nil && len(ev.Calls()) != 0 {
		t.Fatalf("ordinary caller's evidence: %+v", ev.Calls())
	}
	// Same, but an entry lands (from an ordinary fill) before the fresh
	// read fails: the ordinary caller takes the entry.
	fstart2 := make(chan struct{})
	ffail2 := make(chan struct{})
	go c.Do(evidence.WithFresh(ctx), "landed", func(context.Context) (int, time.Duration, error) {
		close(fstart2)
		<-ffail2
		return 0, 0, errors.New("upstream")
	})
	<-fstart2
	got2 := make(chan int, 1)
	go func() {
		v, _ := c.Do(ctx, "landed", func(context.Context) (int, time.Duration, error) { return 3, time.Minute, nil })
		got2 <- v
	}()
	c.awaitWaiters(t, "landed", 1, 0)
	c.Set("landed", 4, time.Minute)
	close(ffail2)
	if v := <-got2; v != 4 {
		t.Fatalf("ordinary caller got %d, want the entry that landed", v)
	}
	// A failed fill's own calls stay on the record of the caller an entry
	// answered, next to the entry's, and do not date the answer.
	fctx3, frec3 := evidence.WithRecorder(ctx)
	fstart3 := make(chan struct{})
	ffail3 := make(chan struct{})
	got3 := make(chan int, 1)
	go func() {
		v, _ := c.Do(fctx3, "failed-record", func(ctx context.Context) (int, time.Duration, error) {
			evidence.RecorderFrom(ctx).Record(evidence.Call{Method: "GET", Path: "/failed", Status: 503})
			close(fstart3)
			<-ffail3
			return 0, 0, errors.New("upstream")
		})
		got3 <- v
	}()
	<-fstart3
	landedCtx, landedRec := evidence.WithRecorder(ctx)
	landedRec.Record(evidence.Call{Method: "GET", Path: "/landed", Status: 200})
	_ = landedCtx
	c.mu.Lock()
	c.storeLocked("failed-record", 6, time.Minute, landedRec.Evidence(), clock.Add(-time.Hour))
	c.mu.Unlock()
	close(ffail3)
	if v := <-got3; v != 6 {
		t.Fatalf("got %d", v)
	}
	calls := frec3.Evidence().Calls()
	if len(calls) != 2 || calls[0].Path != "/failed" || calls[0].Cached || calls[1].Path != "/landed" || !calls[1].Cached {
		t.Fatalf("record after a failed fill answered by an entry: %+v", calls)
	}
	if o, ok := frec3.Oldest(); !ok || !o.Equal(clock.Add(-time.Hour)) {
		t.Fatalf("dated %v %v, want the entry's read", o, ok)
	}

	// With a fresh max age, a fresh caller takes an entry younger than it
	// and reads again past it.
	aged := New[string, int](0)
	aged.SetClock(func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock })
	aged.SetFreshMaxAge(time.Minute)
	var agedFills atomic.Int32
	agedFill := func(context.Context) (int, time.Duration, error) { return int(agedFills.Add(1)), time.Hour, nil }
	actx, arec := evidence.WithRecorder(evidence.WithFresh(ctx))
	if v, _ := aged.Do(actx, "k", agedFill); v != 1 {
		t.Fatal(v)
	}
	if v, _ := aged.Do(actx, "k", agedFill); v != 1 || agedFills.Load() != 1 {
		t.Fatalf("young entry not taken by a fresh caller: v=%d fills=%d", v, agedFills.Load())
	}
	if calls := arec.Evidence().Calls(); len(calls) != 0 {
		t.Fatalf("no calls were recorded, got %+v", calls)
	}
	// The young entry a fresh caller took counts as read now, not when
	// it was read: the accepted staleness must not date the fresh check
	// older than an ordinary one resting on the same entry.
	if o, ok := arec.Oldest(); !ok || o.Before(clock) {
		t.Fatalf("fresh reuse dated %v %v, want now (%v)", o, ok, clock)
	}
	clockMu.Lock()
	clock = clock.Add(time.Second)
	clockMu.Unlock()
	octx2, orec2 := evidence.WithRecorder(ctx)
	aged.Do(octx2, "k", agedFill)
	if o, ok := orec2.Oldest(); !ok || !o.Before(clock) {
		t.Fatalf("ordinary hit dated %v %v, want the entry's read", o, ok)
	}
	clockMu.Lock()
	clock = clock.Add(time.Minute)
	clockMu.Unlock()
	if v, _ := aged.Do(actx, "k", agedFill); v != 2 || agedFills.Load() != 2 {
		t.Fatalf("aged entry served to a fresh caller: v=%d fills=%d", v, agedFills.Load())
	}
	// With a fresh max age, a fresh caller also shares a fresh fill older
	// than the join window but younger than that age.
	astarted := make(chan struct{})
	arelease := make(chan struct{})
	go aged.Do(evidence.WithFresh(ctx), "share", func(context.Context) (int, time.Duration, error) {
		agedFills.Add(1)
		close(astarted)
		<-arelease
		return 10, time.Hour, nil
	})
	<-astarted
	clockMu.Lock()
	clock = clock.Add(FreshJoinWindow + time.Second)
	clockMu.Unlock()
	shared := make(chan int, 1)
	go func() { v, _ := aged.Do(evidence.WithFresh(ctx), "share", agedFill); shared <- v }()
	aged.awaitWaiters(t, "share", 0, 1)
	close(arelease)
	if v := <-shared; v != 10 || agedFills.Load() != 3 {
		t.Fatalf("fresh caller within the max age did not share the fill: v=%d fills=%d", v, agedFills.Load())
	}
	// ... and an ordinary fill that young as well.
	ostarted2 := make(chan struct{})
	orelease2 := make(chan struct{})
	go aged.Do(ctx, "ordinary", func(context.Context) (int, time.Duration, error) {
		agedFills.Add(1)
		close(ostarted2)
		<-orelease2
		return 20, time.Hour, nil
	})
	<-ostarted2
	sharedO := make(chan int, 1)
	go func() { v, _ := aged.Do(evidence.WithFresh(ctx), "ordinary", agedFill); sharedO <- v }()
	aged.awaitWaiters(t, "ordinary", 0, 1)
	close(orelease2)
	if v := <-sharedO; v != 20 || agedFills.Load() != 4 {
		t.Fatalf("fresh caller within the max age did not share the ordinary fill: v=%d fills=%d", v, agedFills.Load())
	}
	// A panic in a fresh fill is a PanicError, like any other.
	var pe *PanicError
	if _, err := c.Do(evidence.WithFresh(ctx), "boom", func(context.Context) (int, time.Duration, error) { panic("x") }); !errors.As(err, &pe) {
		t.Fatalf("fresh panic: %v", err)
	}

	// A failed fresh lookup stores nothing and leaves the entry for
	// ordinary callers; a fresh answer with ttl 0 removes it.
	c.Set("k", 2, time.Minute)
	tick(FreshJoinWindow)
	if _, err := c.Do(evidence.WithFresh(ctx), "k", func(context.Context) (int, time.Duration, error) { return 0, time.Minute, errors.New("x") }); err == nil {
		t.Fatal("no error")
	}
	if v, ok := c.Get("k"); !ok || v != 2 {
		t.Fatal("entry lost on a failed fresh lookup")
	}
	tick(FreshJoinWindow)
	if v, err := c.Do(evidence.WithFresh(ctx), "k", func(context.Context) (int, time.Duration, error) { return 9, 0, nil }); err != nil || v != 9 {
		t.Fatal(v, err)
	}
	if _, ok := c.Get("k"); ok {
		t.Fatal("ttl 0 fresh answer stored")
	}
}

// The leader of an ordinary fill that fails takes an entry that landed
// meanwhile, like its waiters do.
func TestDoFailedLeaderTakesLandedEntry(t *testing.T) {
	c := New[string, int](0)
	started := make(chan struct{})
	fail := make(chan struct{})
	got := make(chan int, 1)
	go func() {
		v, _ := c.Do(context.Background(), "k", func(context.Context) (int, time.Duration, error) {
			close(started)
			<-fail
			return 0, 0, errors.New("upstream")
		})
		got <- v
	}()
	<-started
	c.Set("k", 5, time.Minute)
	close(fail)
	if v := <-got; v != 5 {
		t.Fatalf("failed leader got %d, want the entry that landed", v)
	}
	// An expired resident does not block a live store.
	e := New[string, int](0)
	var clockMu sync.Mutex
	clock := time.Now()
	e.SetClock(func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock })
	e.Store("k", 1, time.Second, clock)
	clockMu.Lock()
	clock = clock.Add(2 * time.Second)
	clockMu.Unlock()
	e.Store("k", 2, time.Minute, clock.Add(-time.Hour))
	if v, ok := e.Get("k"); !ok || v != 2 {
		t.Fatalf("live store lost to an expired resident: %d %v", v, ok)
	}
}

// A hit and a fill date the caller's record by when the read began, and
// an entry is as old as the oldest cached read its fill rested on: a
// later fill built on an older input does not replace a newer entry.
func TestDoDatesReads(t *testing.T) {
	c := New[string, int](0)
	var clockMu sync.Mutex
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.SetClock(func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock })
	tick := func(d time.Duration) { clockMu.Lock(); clock = clock.Add(d); clockMu.Unlock() }
	t0 := clock
	fill := func(ctx context.Context) (int, time.Duration, error) { return 1, time.Hour, nil }
	c.Do(context.Background(), "in", fill)
	tick(time.Minute)
	// A hit is dated by the entry's read.
	hctx, hrec := evidence.WithRecorder(context.Background())
	c.Do(hctx, "in", fill)
	if o, ok := hrec.Oldest(); !ok || !o.Equal(t0) {
		t.Fatalf("hit dated %v %v, want %v", o, ok, t0)
	}
	// A fill that reads the cached input is as old as that input.
	built := New[string, int](0)
	built.SetClock(func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock })
	built.Do(context.Background(), "out", func(ctx context.Context) (int, time.Duration, error) {
		v, _ := c.Do(ctx, "in", fill)
		return v + 10, time.Hour, nil
	})
	tick(time.Minute)
	// A read that began now, before the built entry's own start but after
	// its input, still replaces it: the built entry is dated by its
	// input at t0.
	built.Store("out", 99, time.Hour, t0.Add(30*time.Second))
	if v, _ := built.Get("out"); v != 99 {
		t.Fatalf("entry dated by its own start, not its oldest input: %d", v)
	}
	// And one older than the input does not.
	built.Store("out", 7, time.Hour, t0.Add(-time.Second))
	if v, _ := built.Get("out"); v != 99 {
		t.Fatalf("older read replaced the entry: %d", v)
	}
}

// A waiter is not failed by the leader's deadline: when the shared fill
// ended because the leader's remaining time ran out, the waiter, which has
// time left, fills again with its own context.
func TestDoWaiterRefillsAfterLeaderDeadline(t *testing.T) {
	c := New[string, int](0)
	var fills atomic.Int32
	fill := func(ctx context.Context) (int, time.Duration, error) {
		n := int(fills.Add(1))
		select {
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		case <-time.After(150 * time.Millisecond):
			return n, time.Minute, nil
		}
	}
	leaderCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	leaderErr := make(chan error, 1)
	go func() { _, err := c.Do(leaderCtx, "k", fill); leaderErr <- err }()
	for c.inflightCount() != 1 {
		time.Sleep(time.Millisecond)
	}
	wctx, wrec := evidence.WithRecorder(context.Background())
	v, err := c.Do(wctx, "k", fill)
	if err != nil || v != 2 || fills.Load() != 2 {
		t.Fatalf("waiter: v=%d err=%v fills=%d", v, err, fills.Load())
	}
	if !errors.Is(<-leaderErr, context.DeadlineExceeded) {
		t.Fatal("leader did not get its own deadline")
	}
	if wrec.Evidence() != nil {
		t.Fatalf("no calls were recorded, yet: %+v", wrec.Evidence().Calls())
	}
	if got, ok := c.Get("k"); !ok || got != 2 {
		t.Fatal("waiter's answer not stored")
	}
}
