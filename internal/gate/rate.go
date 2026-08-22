package gate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const DefaultRatePerMinute = 6

// ResolveRate applies SPEC.md's "--rate defaults to 6 per minute ... matrix
// may lower it and can never raise it above the default". requested is nil
// when the flag was absent; a non-nil pointer to 0 is a distinct, valid
// request, per ADR-0005's absent-vs-zero distinction.
//
// An attempt to raise the rate is refused with an error rather than silently
// clamped to the default, because a silent clamp would let a caller believe
// it configured a faster rate than the one actually in effect.
func ResolveRate(requested *int) (int, error) {
	if requested == nil {
		return DefaultRatePerMinute, nil
	}
	if *requested > DefaultRatePerMinute {
		return 0, fmt.Errorf("gate: rate %d exceeds the default of %d and is refused, not clamped", *requested, DefaultRatePerMinute)
	}
	return *requested, nil
}

type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	clock    Clock
}

func NewLimiter(perMinute int, clock Clock) *Limiter {
	var interval time.Duration
	if perMinute > 0 {
		interval = time.Minute / time.Duration(perMinute)
	}
	return &Limiter{interval: interval, clock: clock}
}

func (l *Limiter) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return sleepCtx(ctx, l.clock, l.reserve())
}

func (l *Limiter) reserve() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	return wait
}

// sleepCtx sleeps on clock for d, but returns as soon as ctx is cancelled.
// Checking ctx first, before ever calling clock.Sleep, is what lets a
// pre-cancelled context skip the wait entirely rather than racing it.
func sleepCtx(ctx context.Context, clock Clock, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	done := make(chan struct{})
	go func() {
		clock.Sleep(d)
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

const DefaultBackoffBase = time.Second
const DefaultBackoffThreshold = 5

var ErrBackoffAborted = errors.New("gate: repeated deferrals exceeded the backoff threshold")

type BackoffConfig struct {
	Base      time.Duration
	Threshold int
}

type Backoff struct {
	mu      sync.Mutex
	cfg     BackoffConfig
	clock   Clock
	attempt int
}

func NewBackoff(cfg BackoffConfig, clock Clock) *Backoff {
	if cfg.Base <= 0 {
		cfg.Base = DefaultBackoffBase
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = DefaultBackoffThreshold
	}
	return &Backoff{cfg: cfg, clock: clock}
}

// Defer records one Deferral and waits the next exponential delay, or
// returns an error wrapping ErrBackoffAborted once the threshold is passed,
// without waiting again first: past the threshold Frank stops knocking
// rather than knocking once more before giving up.
func (b *Backoff) Defer(ctx context.Context) error {
	b.mu.Lock()
	b.attempt++
	attempt := b.attempt
	cfg := b.cfg
	b.mu.Unlock()

	if attempt > cfg.Threshold {
		return fmt.Errorf("%w: %d deferrals", ErrBackoffAborted, attempt-1)
	}

	delay := cfg.Base * time.Duration(uint64(1)<<uint(attempt-1))
	return sleepCtx(ctx, b.clock, delay)
}

// Reset clears the back-off state. A caller invokes it on any successful,
// non-Deferral Outcome, per SPEC.md.
func (b *Backoff) Reset() {
	b.mu.Lock()
	b.attempt = 0
	b.mu.Unlock()
}
