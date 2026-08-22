package gate

import (
	"context"
	"sync"
	"time"
)

// Clock is the time seam. Everything that would otherwise make the suite slow
// goes through it, so a rate limit of six per minute is asserted in
// microseconds of wall time rather than by really waiting ten seconds.
type Clock interface {
	Now() time.Time
	Sleep(d time.Duration)
}

// RealClock is the production Clock.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }
func (RealClock) Sleep(d time.Duration) {
	if d > 0 {
		time.Sleep(d)
	}
}

// FakeClock advances a virtual now instantly and records what it was asked to
// sleep for, so a test can assert the interval without spending it.
type FakeClock struct {
	mu    sync.Mutex
	now   time.Time
	slept []time.Duration
}

// NewFakeClock starts at a fixed instant, so a test's arithmetic is stable.
func NewFakeClock() *FakeClock {
	return &FakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *FakeClock) Sleep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d <= 0 {
		return
	}
	c.slept = append(c.slept, d)
	c.now = c.now.Add(d)
}

// Slept returns the durations Sleep was asked for, in order.
func (c *FakeClock) Slept() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.slept...)
}

// Advance moves the virtual clock forward without recording a sleep.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

var _ Clock = RealClock{}
var _ Clock = (*FakeClock)(nil)

// sleepWithContext sleeps unless ctx ends first.
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
