package gate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultRatePerMinute is the conservative cap that applies to every mode that
// opens connections. The spec's safety posture makes it mandatory, and matrix
// may lower it but never raise it.
const DefaultRatePerMinute = 6

// ErrRateTooHigh is returned when a caller asks for a rate above the default.
// The request is refused rather than silently clamped: a run that believed it
// was probing faster than it was would misreport its own pacing.
var ErrRateTooHigh = errors.New("gate: requested rate exceeds the mandatory default")

// ErrBackoffExhausted is returned once repeated Deferrals pass the threshold.
// Frank aborts rather than continuing to knock.
var ErrBackoffExhausted = errors.New("gate: too many consecutive deferrals, aborting rather than continuing to knock")

// NewLimiter builds a limiter for perMinute connections. A nil perMinute means
// the caller did not set a rate and gets the default; a pointer to 0 is an
// explicit request for no pacing and is honoured, which is the distinction
// ADR-0005 keeps between an absent key and a key set to zero.
func NewLimiter(perMinute *int, clock Clock) (*Limiter, error) {
	rate := DefaultRatePerMinute
	if perMinute != nil {
		if *perMinute > DefaultRatePerMinute {
			return nil, fmt.Errorf("%w: %d per minute, the cap is %d",
				ErrRateTooHigh, *perMinute, DefaultRatePerMinute)
		}
		rate = *perMinute
	}
	if clock == nil {
		clock = RealClock{}
	}
	return &Limiter{rate: rate, clock: clock}, nil
}

// Limiter paces connections. It is safe for concurrent use, because the matrix
// runner is concurrent.
type Limiter struct {
	mu   sync.Mutex
	rate int
	last time.Time

	clock Clock
}

// Rate is the effective connections-per-minute cap.
func (l *Limiter) Rate() int { return l.rate }

// Interval is the minimum gap between connections.
func (l *Limiter) Interval() time.Duration {
	if l.rate <= 0 {
		return 0
	}
	return time.Minute / time.Duration(l.rate)
}

// Wait blocks until the next connection may be opened, or until ctx ends.
func (l *Limiter) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	l.mu.Lock()
	interval := l.Interval()
	var delay time.Duration
	now := l.clock.Now()
	if interval > 0 && !l.last.IsZero() {
		if elapsed := now.Sub(l.last); elapsed < interval {
			delay = interval - elapsed
		}
	}
	l.last = now.Add(delay)
	l.mu.Unlock()

	return sleepWithContext(ctx, l.clock, delay)
}

// BackoffConfig tunes the Deferral back-off.
type BackoffConfig struct {
	// Base is the first delay after a Deferral. Zero means one second.
	Base time.Duration
	// Threshold is how many consecutive Deferrals are tolerated before the run
	// aborts. Zero means four.
	Threshold int
}

func (c BackoffConfig) base() time.Duration {
	if c.Base <= 0 {
		return time.Second
	}
	return c.Base
}

func (c BackoffConfig) threshold() int {
	if c.Threshold <= 0 {
		return 4
	}
	return c.Threshold
}

// NewBackoff builds a back-off tracker.
func NewBackoff(cfg BackoffConfig, clock Clock) *Backoff {
	if clock == nil {
		clock = RealClock{}
	}
	return &Backoff{cfg: cfg, clock: clock}
}

// Backoff turns repeated Deferrals into exponentially longer waits and, past a
// threshold, into an abort.
type Backoff struct {
	mu          sync.Mutex
	cfg         BackoffConfig
	consecutive int

	clock Clock
}

// Deferred records a Deferral and waits the appropriate time. It returns
// ErrBackoffExhausted once the threshold is passed.
func (b *Backoff) Deferred(ctx context.Context) error {
	b.mu.Lock()
	b.consecutive++
	n := b.consecutive
	b.mu.Unlock()

	if n >= b.cfg.threshold() {
		return fmt.Errorf("%w: %d in a row", ErrBackoffExhausted, n)
	}

	delay := b.cfg.base() << (n - 1)
	return sleepWithContext(ctx, b.clock, delay)
}

// Succeeded resets the back-off, because the run of Deferrals is over.
func (b *Backoff) Succeeded() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consecutive = 0
}

// Consecutive is how many Deferrals have been seen in a row.
func (b *Backoff) Consecutive() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.consecutive
}
