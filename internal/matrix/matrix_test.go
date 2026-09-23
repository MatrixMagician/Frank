package matrix

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MatrixMagician/Frank/internal/gate"
	"github.com/MatrixMagician/Frank/internal/smtptest"
)

func testSlots() Slots {
	return Slots{
		EnvelopeSenders: []string{"bounce@sender.example", "other@sender.example"},
		HeloIdentities:  []string{"frank.invalid"},
		HeaderFroms:     []string{"ceo@victim.example", "author@sender.example"},
	}
}

// instantLimiter paces through the fake clock, so a sweep of several Cells
// costs microseconds instead of the minutes its rate describes.
func instantLimiter(t *testing.T) (*gate.Limiter, *gate.Backoff) {
	t.Helper()
	clock := gate.NewFakeClockAtEpoch()
	lim := gate.NewLimiter(gate.DefaultRatePerMinute, clock)
	return lim, gate.NewBackoff(gate.BackoffConfig{Base: time.Millisecond, Threshold: 3}, clock)
}

func sweep(t *testing.T, srv *smtptest.Server, slots Slots) *Matrix {
	t.Helper()
	lim, back := instantLimiter(t)
	m, err := Run(context.Background(), Config{
		TargetHost: srv.Addr(),
		Recipient:  "rcpt@target.example",
		Slots:      slots,
		Limiter:    lim,
		Backoff:    back,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return m
}

func cellFor(t *testing.T, m *Matrix, triple Triple) *Cell {
	t.Helper()
	for _, c := range m.Cells {
		if c.Triple == triple {
			return c
		}
	}
	t.Fatalf("no cell for %v", triple)
	return nil
}

func TestRejectedTripleIsolated(t *testing.T) {
	rejected := Triple{
		EnvelopeSender: "bounce@sender.example",
		HeloIdentity:   "frank.invalid",
		HeaderFrom:     "ceo@victim.example",
	}
	srv := smtptest.Start(t, smtptest.RejectTriple(smtptest.PhaseEndOfData,
		smtptest.ObservedTriple{EnvelopeSender: rejected.EnvelopeSender, HeaderFrom: rejected.HeaderFrom},
		550, "5.7.1", "sender address not owned by authenticated user"))

	m := sweep(t, srv, testSlots())

	for _, c := range m.Cells {
		want := Accepted
		if c.Triple == rejected {
			want = Rejected
		}
		if got := c.Resolution(); got != want {
			t.Errorf("cell %v resolved %v, want %v", c.Triple, got, want)
		}
	}

	if !strings.Contains(m.Boundary(), "1 of 4") {
		t.Errorf("Boundary() = %q, want it to count the single rejection", m.Boundary())
	}
}

// TestFreshConnectionPerCell is ADR-0003 as an assertion. A Cell is one clean
// Probe, and that has to stay literally true or one Cell's Outcome could depend
// on the Cell before it.
func TestFreshConnectionPerCell(t *testing.T) {
	srv := smtptest.Start(t)
	slots := testSlots()

	m := sweep(t, srv, slots)

	if got, want := srv.ConnectionCount(), len(m.Cells); got != want {
		t.Errorf("the double saw %d connections for %d cells, want one each", got, want)
	}
}

func TestGreylistedCellInconclusiveThenAcceptedOnRetry(t *testing.T) {
	t.Run("retry resolves it to accepted", func(t *testing.T) {
		srv := smtptest.Start(t, smtptest.Greylist(smtptest.PhaseEndOfData, 1,
			450, "4.7.1", "greylisted, try again later"))

		slots := Slots{
			EnvelopeSenders: []string{"a@sender.example"},
			HeloIdentities:  []string{"frank.invalid"},
			HeaderFroms:     []string{"a@sender.example"},
		}
		m := sweep(t, srv, slots)

		cell := m.Cells[0]
		if got := cell.Resolution(); got != Accepted {
			t.Errorf("resolution = %v, want accepted once the retry succeeded", got)
		}
		if len(cell.Probes) < 2 {
			t.Errorf("cell holds %d probes, want the deferral and the retry", len(cell.Probes))
		}
	})

	t.Run("a host that only ever defers stays inconclusive", func(t *testing.T) {
		srv := smtptest.Start(t, smtptest.Greylist(smtptest.PhaseEndOfData, 99,
			450, "4.7.1", "greylisted, try again later"))

		slots := Slots{
			EnvelopeSenders: []string{"a@sender.example"},
			HeloIdentities:  []string{"frank.invalid"},
			HeaderFroms:     []string{"a@sender.example"},
		}
		m := sweep(t, srv, slots)

		if got := m.Cells[0].Resolution(); got != Inconclusive {
			t.Errorf("resolution = %v, want inconclusive: a greylisting host is not a policy rejection", got)
		}
	})
}

// TestAbortedSweepLeavesUnrunCellsRenderedDistinctly guards the difference the
// glossary insists on: one Cell was asked and would not answer, the other was
// never asked, and neither is ever reported as a rejected Triple.
func TestAbortedSweepLeavesUnrunCellsRenderedDistinctly(t *testing.T) {
	srv := smtptest.Start(t, smtptest.Greylist(smtptest.PhaseEndOfData, 99,
		450, "4.7.1", "greylisted, try again later"))

	clock := gate.NewFakeClockAtEpoch()
	lim := gate.NewLimiter(gate.DefaultRatePerMinute, clock)
	m, err := Run(context.Background(), Config{
		TargetHost: srv.Addr(),
		Recipient:  "rcpt@target.example",
		Slots:      testSlots(),
		Limiter:    lim,
		Backoff:    gate.NewBackoff(gate.BackoffConfig{Base: time.Millisecond, Threshold: 2}, clock),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if m.Aborted == "" {
		t.Fatal("the sweep completed, want it aborted by the back-off threshold")
	}

	counts := m.Counts()
	if counts[Unrun] == 0 {
		t.Fatal("no cell is unrun after an aborted sweep")
	}
	if counts[Rejected] != 0 {
		t.Error("an aborted sweep reported a rejected Triple")
	}

	var out bytes.Buffer
	if err := Render(&out, m); err != nil {
		t.Fatalf("Render: %v", err)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "unrun (never asked)") {
		t.Error("the rendering does not explain what an unrun cell means")
	}
	if !strings.Contains(rendered, "inconclusive (asked, no answer)") {
		t.Error("the rendering does not explain what an inconclusive cell means")
	}
	if Unrun.Symbol() == Inconclusive.Symbol() {
		t.Error("unrun and inconclusive share a symbol, so the two cannot be told apart in the grid")
	}
}

func TestRateHonouredAndCannotBeRaised(t *testing.T) {
	tooFast := gate.DefaultRatePerMinute + 1
	if _, err := gate.ResolveRate(&tooFast); err == nil {
		t.Error("a rate above the default was accepted, but matrix may only lower it")
	}

	clock := gate.NewFakeClockAtEpoch()
	slower := 2
	rate, err := gate.ResolveRate(&slower)
	if err != nil {
		t.Fatalf("ResolveRate: %v", err)
	}
	lim := gate.NewLimiter(rate, clock)

	srv := smtptest.Start(t)
	if _, err := Run(context.Background(), Config{
		TargetHost: srv.Addr(),
		Recipient:  "rcpt@target.example",
		Slots:      testSlots(),
		Limiter:    lim,
		Backoff:    gate.NewBackoff(gate.BackoffConfig{Base: time.Millisecond}, clock),
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	for i, d := range clock.Sleeps() {
		if d != 30*time.Second {
			t.Errorf("gap %d = %v, want 30s for two per minute", i+1, d)
		}
	}
}

func TestNullEnvelopeSenderIsAFirstClassTripleValue(t *testing.T) {
	srv := smtptest.Start(t)
	slots := Slots{
		EnvelopeSenders: []string{"", "a@sender.example"},
		HeloIdentities:  []string{"frank.invalid"},
		HeaderFroms:     []string{"a@sender.example"},
	}

	m := sweep(t, srv, slots)

	null := cellFor(t, m, Triple{EnvelopeSender: "", HeloIdentity: "frank.invalid", HeaderFrom: "a@sender.example"})
	if got := null.Resolution(); got != Accepted {
		t.Errorf("the null sender cell resolved %v, want accepted: <> is a legal value", got)
	}

	var out bytes.Buffer
	Render(&out, m)
	if !strings.Contains(out.String(), "<>") {
		t.Error("the rendering does not show the null sender as <>")
	}
}

func TestCellResolutionIsDerivedNotStored(t *testing.T) {
	c := &Cell{Triple: Triple{}, reached: true}
	if got := c.Resolution(); got != Inconclusive {
		t.Errorf("a reached cell with no probes resolved %v, want inconclusive", got)
	}

	unreached := &Cell{Triple: Triple{}}
	if got := unreached.Resolution(); got != Unrun {
		t.Errorf("an unreached cell resolved %v, want unrun", got)
	}
}

func TestTriplesAreTheCartesianProductInAStableOrder(t *testing.T) {
	slots := Slots{
		EnvelopeSenders: []string{"e1", "e2"},
		HeloIdentities:  []string{"h1", "h2"},
		HeaderFroms:     []string{"f1", "f2", "f3"},
	}

	first := slots.Triples()
	if len(first) != 12 {
		t.Fatalf("got %d triples, want 2*2*3", len(first))
	}
	second := slots.Triples()
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("triple %d differs between calls, so a rendered matrix is not reproducible", i)
		}
	}
}

func TestBoundaryNamesTheDiscriminatingSlot(t *testing.T) {
	srv := smtptest.Start(t, smtptest.RejectTriple(smtptest.PhaseEndOfData,
		smtptest.ObservedTriple{HeaderFrom: "ceo@victim.example"},
		550, "5.7.1", "not allowed"))

	m := sweep(t, srv, testSlots())

	got := m.Boundary()
	if !strings.Contains(got, "header from") {
		t.Errorf("Boundary() = %q, want it to name the header from as the discriminating slot", got)
	}
	if !strings.Contains(got, "ceo@victim.example") {
		t.Errorf("Boundary() = %q, want it to name the offending value", got)
	}
}

func TestConcurrentSweepIsRaceFree(t *testing.T) {
	srv := smtptest.Start(t)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			clock := gate.NewFakeClockAtEpoch()
			lim := gate.NewLimiter(gate.DefaultRatePerMinute, clock)
			_, err := Run(context.Background(), Config{
				TargetHost: srv.Addr(),
				Recipient:  "rcpt@target.example",
				Slots:      testSlots(),
				Limiter:    lim,
				Backoff:    gate.NewBackoff(gate.BackoffConfig{Base: time.Millisecond}, clock),
			})
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestRenderJSONCarriesResolutionAndBoundary(t *testing.T) {
	srv := smtptest.Start(t, smtptest.RejectTriple(smtptest.PhaseEndOfData,
		smtptest.ObservedTriple{HeaderFrom: "ceo@victim.example"},
		550, "5.7.1", "not allowed"))

	m := sweep(t, srv, testSlots())

	var out bytes.Buffer
	if err := RenderJSON(&out, m); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	for _, want := range []string{`"resolution"`, `"rejected"`, `"accepted"`, `"boundary"`, `"code": 550`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("json does not contain %s:\n%s", want, out.String())
		}
	}
}

func TestSweepRequiresEverySlotToHaveValues(t *testing.T) {
	_, err := Run(context.Background(), Config{
		TargetHost: "127.0.0.1:1",
		Recipient:  "a@b.example",
		Slots:      Slots{EnvelopeSenders: []string{"a@b.example"}},
	})
	if err == nil {
		t.Error("a sweep with no helo identities was accepted")
	}
}
