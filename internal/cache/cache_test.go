package cache

import (
	"context"
	"errors"
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
