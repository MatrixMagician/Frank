package gate

import (
	"testing"
	"time"
)

func TestFakeClockSleepAdvancesVirtualNow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := NewFakeClock(start)

	clock.Sleep(5 * time.Second)

	if got := clock.Now(); !got.Equal(start.Add(5 * time.Second)) {
		t.Errorf("Now() = %v, want %v", got, start.Add(5*time.Second))
	}
	sleeps := clock.Sleeps()
	if len(sleeps) != 1 || sleeps[0] != 5*time.Second {
		t.Errorf("Sleeps() = %v, want [5s]", sleeps)
	}
}

func TestFakeClockSleepIsConcurrencySafe(t *testing.T) {
	clock := NewFakeClock(time.Now())
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			clock.Sleep(time.Millisecond)
			clock.Now()
			done <- struct{}{}
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
	if len(clock.Sleeps()) != 20 {
		t.Errorf("recorded %d sleeps, want 20", len(clock.Sleeps()))
	}
}
