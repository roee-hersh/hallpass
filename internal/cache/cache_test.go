package cache

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
