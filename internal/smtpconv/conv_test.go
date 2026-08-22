package smtpconv

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/MatrixMagician/Frank/internal/smtptest"
	"github.com/MatrixMagician/Frank/internal/transcript"
)

func testConfig(addr string, dryRun bool) Config {
	return Config{
		TargetHost: addr,
		Identities: Identities{
			EnvelopeSender: NewEnvelopeSender("envelope@sender.example"),
			HeloIdentity:   "client.helo.example",
			HeaderFrom:     "header@from.example",
		},
		Recipient:   "rcpt@recipient.example",
		DryRun:      dryRun,
		Dialer:      net.Dial,
		DialTimeout: 2 * time.Second,
	}
}

func eventsAt(tr *transcript.Transcript, phase transcript.Phase) []*transcript.Event {
	var out []*transcript.Event
	for _, e := range tr.Events {
		if e.Phase == phase {
			out = append(out, e)
		}
	}
	return out
}

func rawJoined(tr *transcript.Transcript, phase transcript.Phase) string {
	var b strings.Builder
	for _, e := range eventsAt(tr, phase) {
		b.Write(e.Raw)
	}
	return b.String()
}

func TestIdentitySlotsAreIndependent(t *testing.T) {
	srv := smtptest.Start(t)
	cfg := testConfig(srv.Addr(), false)
	cfg.Identities = Identities{
		EnvelopeSender: NewEnvelopeSender("one@envelope.example"),
		HeloIdentity:   "two.helo.example",
		HeaderFrom:     "three@header.example",
	}

	res := Run(cfg)
	if res.Err != nil {
		t.Fatalf("Run() error = %v", res.Err)
	}

	got := res.Transcript.Identity
	if got.EnvelopeSender != "one@envelope.example" {
		t.Errorf("EnvelopeSender = %q, want %q", got.EnvelopeSender, "one@envelope.example")
	}
	if got.HeloIdentity != "two.helo.example" {
		t.Errorf("HeloIdentity = %q, want %q", got.HeloIdentity, "two.helo.example")
	}
	if got.HeaderFrom != "three@header.example" {
		t.Errorf("HeaderFrom = %q, want %q", got.HeaderFrom, "three@header.example")
	}

	received := srv.Received()
	if len(received) != 1 {
		t.Fatalf("Received() = %d messages, want 1", len(received))
	}
	if received[0].Triple.EnvelopeSender != "one@envelope.example" {
		t.Errorf("server saw envelope sender %q, want %q", received[0].Triple.EnvelopeSender, "one@envelope.example")
	}
	if received[0].Triple.HeloIdentity != "two.helo.example" {
		t.Errorf("server saw helo %q, want %q", received[0].Triple.HeloIdentity, "two.helo.example")
	}
	if received[0].Triple.HeaderFrom != "three@header.example" {
		t.Errorf("server saw header from %q, want %q", received[0].Triple.HeaderFrom, "three@header.example")
	}
}

func TestMismatchedIdentitiesAppearVerbatimAtCorrectPhases(t *testing.T) {
	srv := smtptest.Start(t)
	cfg := testConfig(srv.Addr(), false)
	cfg.Identities = Identities{
		EnvelopeSender: NewEnvelopeSender("envelope-value@one.example"),
		HeloIdentity:   "helo-value.two.example",
		HeaderFrom:     "header-value@three.example",
	}

	res := Run(cfg)
	if res.Err != nil {
		t.Fatalf("Run() error = %v", res.Err)
	}
	tr := res.Transcript

	ehloRaw := rawJoined(tr, transcript.PhaseEHLO)
	if !strings.Contains(ehloRaw, "helo-value.two.example") {
		t.Errorf("PhaseEHLO events do not contain the HELO identity verbatim:\n%s", ehloRaw)
	}

	mailFromRaw := rawJoined(tr, transcript.PhaseMailFrom)
	if !strings.Contains(mailFromRaw, "envelope-value@one.example") {
		t.Errorf("PhaseMailFrom events do not contain the envelope sender verbatim:\n%s", mailFromRaw)
	}

	endOfDataRaw := rawJoined(tr, transcript.PhaseEndOfData)
	if !strings.Contains(endOfDataRaw, "header-value@three.example") {
		t.Errorf("PhaseEndOfData events do not contain the header from address verbatim:\n%s", endOfDataRaw)
	}

	if strings.Contains(mailFromRaw, "helo-value.two.example") || strings.Contains(mailFromRaw, "header-value@three.example") {
		t.Errorf("PhaseMailFrom leaked another identity slot:\n%s", mailFromRaw)
	}
	if strings.Contains(ehloRaw, "envelope-value@one.example") || strings.Contains(ehloRaw, "header-value@three.example") {
		t.Errorf("PhaseEHLO leaked another identity slot:\n%s", ehloRaw)
	}
}

func TestEHLOFallsBackToHELOAndRecordsIt(t *testing.T) {
	srv := smtptest.Start(t, smtptest.RefuseEHLO())
	cfg := testConfig(srv.Addr(), false)

	res := Run(cfg)
	if res.Err != nil {
		t.Fatalf("Run() error = %v", res.Err)
	}

	ehloEvents := eventsAt(res.Transcript, transcript.PhaseEHLO)
	var sawEHLO, sawHELO, sawFallbackNote bool
	for _, e := range ehloEvents {
		raw := string(e.Raw)
		if strings.HasPrefix(raw, "EHLO ") {
			sawEHLO = true
		}
		if strings.HasPrefix(raw, "HELO ") {
			sawHELO = true
		}
		if strings.Contains(strings.ToLower(e.Note), "fall") {
			sawFallbackNote = true
		}
	}
	if !sawEHLO {
		t.Error("no EHLO command recorded at PhaseEHLO")
	}
	if !sawHELO {
		t.Error("no HELO fallback command recorded at PhaseEHLO")
	}
	if !sawFallbackNote {
		t.Error("no note recording the EHLO->HELO fallback")
	}

	received := srv.Received()
	if len(received) != 1 {
		t.Fatalf("Received() = %d, want 1 (HELO fallback should still complete the probe)", len(received))
	}
}

func TestAdvertisedExtensionsAreParsedAndRecorded(t *testing.T) {
	srv := smtptest.Start(t, smtptest.WithExtensions("SIZE 10240000", "PIPELINING", "8BITMIME"))
	cfg := testConfig(srv.Addr(), true)

	res := Run(cfg)
	if res.Err != nil {
		t.Fatalf("Run() error = %v", res.Err)
	}

	names := map[string]bool{}
	for _, ext := range res.Extensions {
		names[ext.Name] = true
	}
	for _, want := range []string{"SIZE", "PIPELINING", "8BITMIME"} {
		if !names[want] {
			t.Errorf("Extensions missing %q, got %+v", want, res.Extensions)
		}
	}

	ehloRaw := rawJoined(res.Transcript, transcript.PhaseEHLO)
	if !strings.Contains(ehloRaw, "PIPELINING") {
		t.Errorf("PhaseEHLO events do not record the advertised extensions:\n%s", ehloRaw)
	}
}

func TestExactlyOneRecipientPerProbe(t *testing.T) {
	var r Recipient = "single@recipient.example"
	if _, ok := any(r).([]string); ok {
		t.Fatal("Recipient must not be representable as a slice")
	}

	srv := smtptest.Start(t)
	cfg := testConfig(srv.Addr(), false)
	cfg.Recipient = r

	res := Run(cfg)
	if res.Err != nil {
		t.Fatalf("Run() error = %v", res.Err)
	}
	if res.Transcript.Recipient != string(r) {
		t.Errorf("Transcript.Recipient = %q, want %q", res.Transcript.Recipient, r)
	}

	rcptEvents := eventsAt(res.Transcript, transcript.PhaseRcptTo)
	sendCount := 0
	for _, e := range rcptEvents {
		if e.Kind == transcript.KindSend {
			sendCount++
		}
	}
	if sendCount != 1 {
		t.Errorf("RCPT TO sent %d times, want exactly 1", sendCount)
	}
}

func TestDotStuffingAndTermination(t *testing.T) {
	srv := smtptest.Start(t)
	cfg := testConfig(srv.Addr(), false)

	res := Run(cfg)
	if res.Err != nil {
		t.Fatalf("Run() error = %v", res.Err)
	}

	received := srv.Received()
	if len(received) != 1 {
		t.Fatalf("Received() = %d, want 1", len(received))
	}
	if strings.Contains(received[0].Data, "\r\n..") {
		t.Errorf("server-observed body still contains a stuffed dot, want it undone on receipt:\n%q", received[0].Data)
	}
}

func TestDataAndEndOfDataAreSeparatePhases(t *testing.T) {
	t.Run("reject at data", func(t *testing.T) {
		srv := smtptest.Start(t, smtptest.Reject(smtptest.PhaseData, 550, "5.7.1", "policy on the envelope"))
		cfg := testConfig(srv.Addr(), false)

		res := Run(cfg)
		if res.Err != nil {
			t.Fatalf("Run() error = %v", res.Err)
		}
		if res.Outcome == nil {
			t.Fatal("Outcome is nil, want a Rejection at PhaseData")
		}
		if res.Outcome.Phase() != transcript.PhaseData {
			t.Errorf("Outcome.Phase() = %v, want %v", res.Outcome.Phase(), transcript.PhaseData)
		}
		if !res.Outcome.IsRejection() {
			t.Errorf("Outcome.Kind() = %v, want rejection", res.Outcome.Kind())
		}
		if len(eventsAt(res.Transcript, transcript.PhaseEndOfData)) != 0 {
			t.Error("PhaseEndOfData carries events despite being rejected before end-of-data was reached")
		}
	})

	t.Run("reject at end of data", func(t *testing.T) {
		srv := smtptest.Start(t, smtptest.Reject(smtptest.PhaseEndOfData, 550, "5.7.1", "policy on the message"))
		cfg := testConfig(srv.Addr(), false)

		res := Run(cfg)
		if res.Err != nil {
			t.Fatalf("Run() error = %v", res.Err)
		}
		if res.Outcome == nil {
			t.Fatal("Outcome is nil, want a Rejection at PhaseEndOfData")
		}
		if res.Outcome.Phase() != transcript.PhaseEndOfData {
			t.Errorf("Outcome.Phase() = %v, want %v", res.Outcome.Phase(), transcript.PhaseEndOfData)
		}
		if !res.Outcome.IsRejection() {
			t.Errorf("Outcome.Kind() = %v, want rejection", res.Outcome.Kind())
		}
		dataEvents := eventsAt(res.Transcript, transcript.PhaseData)
		if len(dataEvents) == 0 {
			t.Error("PhaseData carries no events despite DATA having been accepted (354) before the reject")
		}
	})
}

func TestPhaseTimingsPopulatedAndMonotonic(t *testing.T) {
	srv := smtptest.Start(t, smtptest.Delay(smtptest.PhaseRcptTo, 30*time.Millisecond))
	cfg := testConfig(srv.Addr(), true)

	res := Run(cfg)
	if res.Err != nil {
		t.Fatalf("Run() error = %v", res.Err)
	}

	var prev time.Duration
	for i, e := range res.Transcript.Events {
		if e.Monotonic < prev {
			t.Errorf("Events[%d].Monotonic = %v < previous %v, want non-decreasing", i, e.Monotonic, prev)
		}
		prev = e.Monotonic
	}

	if len(res.Durations) == 0 {
		t.Fatal("Durations is empty, want a populated duration per Phase reached")
	}
	for _, phase := range []transcript.Phase{transcript.PhaseBanner, transcript.PhaseEHLO, transcript.PhaseMailFrom, transcript.PhaseRcptTo} {
		if _, ok := res.Durations[phase]; !ok {
			t.Errorf("Durations missing an entry for %v", phase)
		}
	}
	if res.Durations[transcript.PhaseRcptTo] < 30*time.Millisecond {
		t.Errorf("Durations[PhaseRcptTo] = %v, want at least the 30ms delay the server injected", res.Durations[transcript.PhaseRcptTo])
	}
}

func TestQuitOnEveryExitPathIncludingErrors(t *testing.T) {
	t.Run("dry run", func(t *testing.T) {
		srv := smtptest.Start(t)
		cfg := testConfig(srv.Addr(), true)
		res := Run(cfg)
		if res.Err != nil {
			t.Fatalf("Run() error = %v", res.Err)
		}
		if len(eventsAt(res.Transcript, transcript.PhaseQuit)) == 0 {
			t.Error("no QUIT recorded on a dry run")
		}
	})

	t.Run("rejected at rcpt to", func(t *testing.T) {
		srv := smtptest.Start(t, smtptest.Reject(smtptest.PhaseRcptTo, 550, "5.1.1", "no such user"))
		cfg := testConfig(srv.Addr(), false)
		res := Run(cfg)
		if res.Err != nil {
			t.Fatalf("Run() error = %v", res.Err)
		}
		if res.Outcome == nil || res.Outcome.Phase() != transcript.PhaseRcptTo {
			t.Fatalf("Outcome = %+v, want a Rejection at PhaseRcptTo", res.Outcome)
		}
		if len(eventsAt(res.Transcript, transcript.PhaseQuit)) == 0 {
			t.Error("no QUIT recorded after a Rejection at RCPT TO")
		}
	})

	t.Run("connection closed mid-conversation", func(t *testing.T) {
		srv := smtptest.Start(t, smtptest.WithRule(smtptest.Rule{Phase: smtptest.PhaseMailFrom, Close: true}))
		cfg := testConfig(srv.Addr(), false)
		res := Run(cfg)
		if res.Err == nil {
			t.Fatal("Run() error = nil, want an error from the dropped connection")
		}
		if len(eventsAt(res.Transcript, transcript.PhaseQuit)) == 0 {
			t.Error("no QUIT attempted after the server dropped the connection")
		}
	})
}

func TestNullEnvelopeSenderIsLegal(t *testing.T) {
	srv := smtptest.Start(t)
	cfg := testConfig(srv.Addr(), false)
	cfg.Identities.EnvelopeSender = NullEnvelopeSender()

	res := Run(cfg)
	if res.Err != nil {
		t.Fatalf("Run() error = %v, want the null sender accepted as legal", res.Err)
	}
	if res.Outcome == nil || !res.Outcome.IsAcceptance() {
		t.Fatalf("Outcome = %+v, want an Acceptance", res.Outcome)
	}
	if res.Transcript.Identity.EnvelopeSender != "<>" {
		t.Errorf("Transcript.Identity.EnvelopeSender = %q, want the literal null-sender marker", res.Transcript.Identity.EnvelopeSender)
	}

	mailFromRaw := rawJoined(res.Transcript, transcript.PhaseMailFrom)
	if !strings.Contains(mailFromRaw, "MAIL FROM:<>") {
		t.Errorf("MAIL FROM was not sent with the null sender:\n%s", mailFromRaw)
	}

	received := srv.Received()
	if len(received) != 1 || received[0].Triple.EnvelopeSender != "" {
		t.Fatalf("server-observed envelope sender = %+v, want empty (null)", received)
	}
}

func TestUnreachableTargetProducesPopulatedTranscript(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testConfig(addr, true)
	res := Run(cfg)

	if res.Err == nil {
		t.Fatal("Run() error = nil, want a dial failure against an unreachable target")
	}
	if res.Transcript == nil {
		t.Fatal("Transcript is nil, want a populated Transcript even on dial failure")
	}
	dialEvents := eventsAt(res.Transcript, transcript.PhaseDial)
	if len(dialEvents) == 0 {
		t.Fatal("no events recorded at PhaseDial")
	}
	var sawError bool
	for _, e := range dialEvents {
		if e.Kind == transcript.KindError {
			sawError = true
		}
	}
	if !sawError {
		t.Error("no error event recorded at PhaseDial")
	}
}

func TestDryRunStopsBeforeDATA(t *testing.T) {
	srv := smtptest.Start(t)
	cfg := testConfig(srv.Addr(), true)

	res := Run(cfg)
	if res.Err != nil {
		t.Fatalf("Run() error = %v", res.Err)
	}
	if len(eventsAt(res.Transcript, transcript.PhaseData)) != 0 {
		t.Error("dry run recorded events at PhaseData, want none")
	}
	if len(eventsAt(res.Transcript, transcript.PhaseRcptTo)) == 0 {
		t.Error("dry run stopped before RCPT TO, want it to walk through RCPT TO")
	}
	if len(srv.Received()) != 0 {
		t.Error("dry run transmitted a message, want none")
	}
	if res.Outcome != nil {
		t.Errorf("Outcome = %+v, want nil on a dry run that reached no Phase carrying one", res.Outcome)
	}
}
