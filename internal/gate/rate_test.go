package gate

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDefaultRateIsSixPerMinute(t *testing.T) {
	start := time.Now()
	clock := NewFakeClock(start)
	limiter := NewLimiter(DefaultRatePerMinute, clock)

	testStart := time.Now()
	for i := 0; i < 3; i++ {
		if err := limiter.Wait(context.Background()); err != nil {
			t.Fatalf("Wait: %v", err)
		}
	}
	elapsed := time.Since(testStart)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("test took %v of real time, want well under a second", elapsed)
	}

	sleeps := clock.Sleeps()
	if len(sleeps) != 2 {
		t.Fatalf("recorded %d sleeps, want 2 (no wait before the first slot)", len(sleeps))
	}
	want := 10 * time.Second
	for i, s := range sleeps {
		if s != want {
			t.Errorf("sleep[%d] = %v, want %v", i, s, want)
		}
	}
}

func TestRateAboveDefaultIsRefused(t *testing.T) {
	requested := DefaultRatePerMinute + 1
	_, err := ResolveRate(&requested)
	if err == nil {
		t.Fatal("ResolveRate: got nil error, want a refusal for a rate above the default")
	}
}

func TestRateBelowDefaultIsAccepted(t *testing.T) {
	requested := DefaultRatePerMinute - 1
	got, err := ResolveRate(&requested)
	if err != nil {
		t.Fatalf("ResolveRate: %v", err)
	}
	if got != requested {
		t.Errorf("ResolveRate = %d, want %d", got, requested)
	}
}

func TestRateZeroIsDistinguishableFromAbsent(t *testing.T) {
	zero := 0
	gotZero, err := ResolveRate(&zero)
	if err != nil {
		t.Fatalf("ResolveRate(&0): %v", err)
	}
	if gotZero != 0 {
		t.Errorf("ResolveRate(&0) = %d, want 0", gotZero)
	}

	gotAbsent, err := ResolveRate(nil)
	if err != nil {
		t.Fatalf("ResolveRate(nil): %v", err)
	}
	if gotAbsent != DefaultRatePerMinute {
		t.Errorf("ResolveRate(nil) = %d, want default %d", gotAbsent, DefaultRatePerMinute)
	}
}

func TestLimiterHonoursContextCancellation(t *testing.T) {
	clock := NewFakeClock(time.Now())
	limiter := NewLimiter(1, clock)

	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("first Wait: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := limiter.Wait(ctx)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait error = %v, want context.Canceled", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("cancelled Wait took %v of real time, want near-instant", elapsed)
	}
}

func TestLimiterIsRaceFree(t *testing.T) {
	clock := NewFakeClock(time.Now())
	limiter := NewLimiter(DefaultRatePerMinute, clock)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = limiter.Wait(context.Background())
		}()
	}
	wg.Wait()
}

func TestDeferralBackoffIsExponential(t *testing.T) {
	clock := NewFakeClock(time.Now())
	backoff := NewBackoff(BackoffConfig{Base: time.Second, Threshold: 10}, clock)

	for i := 0; i < 4; i++ {
		if err := backoff.Defer(context.Background()); err != nil {
			t.Fatalf("Defer[%d]: %v", i, err)
		}
	}

	sleeps := clock.Sleeps()
	if len(sleeps) != 4 {
		t.Fatalf("recorded %d sleeps, want 4", len(sleeps))
	}
	for i := 1; i < len(sleeps); i++ {
		if sleeps[i] != 2*sleeps[i-1] {
			t.Errorf("sleep[%d] = %v, want double sleep[%d] = %v", i, sleeps[i], i-1, 2*sleeps[i-1])
		}
	}
}

func TestBackoffAbortsPastThreshold(t *testing.T) {
	clock := NewFakeClock(time.Now())
	backoff := NewBackoff(BackoffConfig{Base: time.Millisecond, Threshold: 3}, clock)

	for i := 0; i < 3; i++ {
		if err := backoff.Defer(context.Background()); err != nil {
			t.Fatalf("Defer[%d]: %v", i, err)
		}
	}

	err := backoff.Defer(context.Background())
	if !errors.Is(err, ErrBackoffAborted) {
		t.Fatalf("Defer past threshold: err = %v, want ErrBackoffAborted", err)
	}
}

func TestSuccessResetsBackoff(t *testing.T) {
	clock := NewFakeClock(time.Now())
	backoff := NewBackoff(BackoffConfig{Base: time.Second, Threshold: 10}, clock)

	if err := backoff.Defer(context.Background()); err != nil {
		t.Fatalf("Defer[0]: %v", err)
	}
	if err := backoff.Defer(context.Background()); err != nil {
		t.Fatalf("Defer[1]: %v", err)
	}

	backoff.Reset()

	if err := backoff.Defer(context.Background()); err != nil {
		t.Fatalf("Defer after reset: %v", err)
	}

	sleeps := clock.Sleeps()
	if len(sleeps) != 3 {
		t.Fatalf("recorded %d sleeps, want 3", len(sleeps))
	}
	if sleeps[2] != sleeps[0] {
		t.Errorf("sleep after reset = %v, want it to restart at the base delay %v", sleeps[2], sleeps[0])
	}
}
