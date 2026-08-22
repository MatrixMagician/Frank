package gate

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"sync"
	"testing"
	"time"
)

func TestWithoutConfirmSendDispositionIsDryRun(t *testing.T) {
	got, err := Decide(Input{Recipient: "rcpt@example.com", StdinIsTerminal: true})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got.Disposition != DispositionDryRun {
		t.Errorf("Disposition = %v, want dry-run without --confirm-send", got.Disposition)
	}
	if got.Recipient != "rcpt@example.com" {
		t.Errorf("Recipient = %q, want it recorded in every decision", got.Recipient)
	}
	if got.Reason == "" {
		t.Error("Reason is empty, but a reader needs to know why nothing was transmitted")
	}
}

func TestConfirmSendRequiresMatchingRecipient(t *testing.T) {
	t.Run("matching", func(t *testing.T) {
		got, err := Decide(Input{ConfirmSend: "rcpt@example.com", Recipient: "rcpt@example.com"})
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		if got.Disposition != DispositionSend {
			t.Errorf("Disposition = %v, want send", got.Disposition)
		}
	})

	t.Run("mismatched", func(t *testing.T) {
		_, err := Decide(Input{ConfirmSend: "other@example.com", Recipient: "rcpt@example.com"})
		if !errors.Is(err, ErrConfirmSendRecipientMismatch) {
			t.Errorf("err = %v, want ErrConfirmSendRecipientMismatch", err)
		}
	})
}

func TestConfirmSendWithDryRunIsUsageError(t *testing.T) {
	_, err := Decide(Input{
		ConfirmSend:     "rcpt@example.com",
		Recipient:       "rcpt@example.com",
		DryRunRequested: true,
	})
	if !errors.Is(err, ErrConfirmSendWithDryRun) {
		t.Errorf("err = %v, want ErrConfirmSendWithDryRun", err)
	}
}

// TestConfirmationWithoutTTYIsAnErrorNotAPrompt is what makes Frank safe in CI.
// The check lives in DecideInteractive, which every caller runs before dialing,
// so the error arrives before the target has been touched.
func TestConfirmationWithoutTTYIsAnErrorNotAPrompt(t *testing.T) {
	_, err := Decide(Input{
		Recipient:       "rcpt@example.com",
		StdinIsTerminal: false,
	})
	if !errors.Is(err, ErrConfirmationNeedsTerminal) {
		t.Fatalf("err = %v, want ErrConfirmationNeedsTerminal", err)
	}

	if _, err := Decide(Input{
		Recipient:       "rcpt@example.com",
		DryRunRequested: true,
		StdinIsTerminal: false,
	}); err != nil {
		t.Errorf("an explicit --dry-run with no terminal errored: %v", err)
	}

	if _, err := Decide(Input{
		ConfirmSend:     "rcpt@example.com",
		Recipient:       "rcpt@example.com",
		StdinIsTerminal: false,
	}); err != nil {
		t.Errorf("an explicit --confirm-send with no terminal errored: %v", err)
	}
}

// TestDefaultRateIsSixPerMinute asserts the interval through the clock seam, so
// the check costs microseconds rather than the fifty seconds it describes.
func TestDefaultRateIsSixPerMinute(t *testing.T) {
	started := time.Now()

	clock := NewFakeClockAtEpoch()
	lim, err := NewLimiter(nil, clock)
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	if lim.Rate() != DefaultRatePerMinute {
		t.Errorf("Rate() = %d, want %d", lim.Rate(), DefaultRatePerMinute)
	}

	for range 5 {
		if err := lim.Wait(context.Background()); err != nil {
			t.Fatalf("Wait: %v", err)
		}
	}

	slept := clock.Slept()
	if len(slept) != 4 {
		t.Fatalf("slept %d times for 5 connections, want 4", len(slept))
	}
	for i, d := range slept {
		if d != 10*time.Second {
			t.Errorf("gap %d = %v, want 10s for six per minute", i+1, d)
		}
	}

	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("the test really took %v, so the clock seam is not being used", elapsed)
	}
}

func TestRateAboveDefaultIsRefused(t *testing.T) {
	tooFast := DefaultRatePerMinute + 1
	_, err := NewLimiter(&tooFast, NewFakeClockAtEpoch())
	if !errors.Is(err, ErrRateTooHigh) {
		t.Errorf("err = %v, want ErrRateTooHigh: the request is refused, not clamped", err)
	}
}

func TestRateBelowDefaultIsAccepted(t *testing.T) {
	slower := 2
	lim, err := NewLimiter(&slower, NewFakeClockAtEpoch())
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	if lim.Rate() != 2 {
		t.Errorf("Rate() = %d, want 2", lim.Rate())
	}
	if got := lim.Interval(); got != 30*time.Second {
		t.Errorf("Interval() = %v, want 30s for two per minute", got)
	}
}

// TestRateZeroIsDistinguishableFromAbsent is ADR-0005's distinction as running
// code: an absent --rate takes the default, a --rate 0 is an explicit request
// for no pacing.
func TestRateZeroIsDistinguishableFromAbsent(t *testing.T) {
	absent, err := NewLimiter(nil, NewFakeClockAtEpoch())
	if err != nil {
		t.Fatalf("NewLimiter(nil): %v", err)
	}
	if absent.Rate() != DefaultRatePerMinute {
		t.Errorf("an absent rate gave %d, want the default %d", absent.Rate(), DefaultRatePerMinute)
	}

	zero := 0
	explicit, err := NewLimiter(&zero, NewFakeClockAtEpoch())
	if err != nil {
		t.Fatalf("NewLimiter(&0): %v", err)
	}
	if explicit.Rate() != 0 {
		t.Errorf("an explicit zero gave %d, want 0", explicit.Rate())
	}
	if explicit.Interval() != 0 {
		t.Errorf("Interval() = %v, want no pacing for an explicit zero", explicit.Interval())
	}
}

func TestDeferralBackoffIsExponential(t *testing.T) {
	clock := NewFakeClockAtEpoch()
	b := NewBackoff(BackoffConfig{Base: time.Second, Threshold: 5}, clock)

	for range 4 {
		if err := b.Deferred(context.Background()); err != nil {
			t.Fatalf("Deferred: %v", err)
		}
	}

	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	got := clock.Slept()
	if len(got) != len(want) {
		t.Fatalf("slept %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("delay %d = %v, want %v", i+1, got[i], want[i])
		}
	}
}

func TestBackoffAbortsPastThreshold(t *testing.T) {
	b := NewBackoff(BackoffConfig{Base: time.Second, Threshold: 3}, NewFakeClockAtEpoch())

	for i := range 2 {
		if err := b.Deferred(context.Background()); err != nil {
			t.Fatalf("deferral %d aborted early: %v", i+1, err)
		}
	}
	err := b.Deferred(context.Background())
	if !errors.Is(err, ErrBackoffExhausted) {
		t.Errorf("err = %v, want ErrBackoffExhausted rather than continuing to knock", err)
	}
}

func TestSuccessResetsBackoff(t *testing.T) {
	clock := NewFakeClockAtEpoch()
	b := NewBackoff(BackoffConfig{Base: time.Second, Threshold: 4}, clock)

	b.Deferred(context.Background())
	b.Deferred(context.Background())
	if b.Consecutive() != 2 {
		t.Fatalf("Consecutive() = %d, want 2", b.Consecutive())
	}

	b.Succeeded()
	if b.Consecutive() != 0 {
		t.Errorf("Consecutive() = %d after a success, want 0", b.Consecutive())
	}

	before := len(clock.Slept())
	if err := b.Deferred(context.Background()); err != nil {
		t.Fatalf("Deferred after reset: %v", err)
	}
	got := clock.Slept()[before]
	if got != time.Second {
		t.Errorf("the first delay after a reset = %v, want the base %v", got, time.Second)
	}
}

func TestLimiterHonoursContextCancellation(t *testing.T) {
	lim, err := NewLimiter(nil, RealClock{})
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}

	if err := lim.Wait(context.Background()); err != nil {
		t.Fatalf("first Wait: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := lim.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestLimiterIsRaceFree(t *testing.T) {
	clock := NewFakeClockAtEpoch()
	lim, err := NewLimiter(nil, clock)
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	b := NewBackoff(BackoffConfig{Base: time.Millisecond, Threshold: 1000}, clock)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 4 {
				lim.Wait(context.Background())
				b.Deferred(context.Background())
				b.Succeeded()
			}
		}()
	}
	wg.Wait()
}

func TestDispositionString(t *testing.T) {
	if DispositionDryRun.String() != "dry-run" {
		t.Errorf("DispositionDryRun = %q", DispositionDryRun.String())
	}
	if DispositionSend.String() != "send" {
		t.Errorf("DispositionSend = %q", DispositionSend.String())
	}
}

// TestStdinIsTerminalRejectsDevNull guards the reason StdinIsTerminal does more
// than check for a character device. /dev/null is one, so the simpler check
// reported it as interactive and a run that should have refused to send dialed
// instead.
func TestStdinIsTerminalRejectsDevNull(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer devNull.Close()

	info, err := devNull.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode()&fs.ModeCharDevice == 0 {
		t.Skip("this platform does not present the null device as a character device")
	}

	if isTerminal(devNull.Fd()) {
		t.Error("isTerminal reports the null device as a terminal, so a piped run would look interactive")
	}
}

func TestStdinIsTerminalRejectsAPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	if isTerminal(r.Fd()) {
		t.Error("isTerminal reports a pipe as a terminal")
	}
}
