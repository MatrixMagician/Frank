// Package gate implements Frank's send gating, rate limiting and back-off,
// per SPEC.md's "Safety posture (normative — do not weaken)".
package gate

import (
	"context"
	"sync"
	"time"
)

// Clock is the seam docs/architecture.md's "Time and the network are seams"
// requires: the rate limiter and back-off never call time.Sleep directly.
type Clock interface {
	Now() time.Time
	Sleep(d time.Duration)
}

type RealClock struct{}

func (RealClock) Now() time.Time        { return time.Now() }
func (RealClock) Sleep(d time.Duration) { time.Sleep(d) }

type FakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func NewFakeClock(start time.Time) *FakeClock {
	return &FakeClock{now: start}
}

func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Sleep advances the fake clock's virtual now by d instead of blocking real
// time, and records d, so a rate-limiter test can assert a ten-second wait
// without the test itself taking ten seconds.
func (c *FakeClock) Sleep(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.sleeps = append(c.sleeps, d)
	c.mu.Unlock()
}

func (c *FakeClock) Sleeps() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Duration, len(c.sleeps))
	copy(out, c.sleeps)
	return out
}

// NewFakeClockAtEpoch starts a fake clock at a fixed instant, so a caller that
// does not care where the virtual timeline begins need not invent one.
func NewFakeClockAtEpoch() *FakeClock {
	return NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
}

// Slept is an alias for Sleeps, kept because callers read more naturally as
// "what did it sleep for".
func (c *FakeClock) Slept() []time.Duration { return c.Sleeps() }

// Advance moves the virtual clock forward without recording a sleep.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// sleepWithContext sleeps unless ctx ends first. A fake clock is advanced
// directly, so a test never blocks on real time.
func sleepWithContext(ctx context.Context, clock Clock, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	if _, isReal := clock.(RealClock); !isReal {
		clock.Sleep(d)
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
