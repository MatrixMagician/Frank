// Package gate implements Frank's send gating, rate limiting and back-off,
// per SPEC.md's "Safety posture (normative — do not weaken)".
package gate

import (
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
