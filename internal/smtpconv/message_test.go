package smtpconv

import (
	"strings"
	"testing"
	"time"
)

func TestNewProbeMessageRejectsEmptyIdentity(t *testing.T) {
	if _, err := NewProbeMessage("", "rcpt@example.com", time.Now()); err == nil {
		t.Fatal("NewProbeMessage with empty header from: want error, got nil")
	}
	if _, err := NewProbeMessage("from@example.com", "", time.Now()); err == nil {
		t.Fatal("NewProbeMessage with empty recipient: want error, got nil")
	}
}

func TestProbeMessageRenderCarriesRequiredHeaders(t *testing.T) {
	msg, err := NewProbeMessage("header@example.com", "rcpt@example.com", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewProbeMessage: %v", err)
	}
	rendered := msg.Render()

	for _, want := range []string{"Date:", "Message-ID:", "Subject:", "From: <header@example.com>", probeXHeader + ":"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered message missing %q:\n%s", want, rendered)
		}
	}
}

func TestProbeMessageHeaderFromIsIndependentOfEnvelope(t *testing.T) {
	msg, err := NewProbeMessage("only-the-header@example.com", "rcpt@example.com", time.Now())
	if err != nil {
		t.Fatalf("NewProbeMessage: %v", err)
	}
	rendered := msg.Render()
	if !strings.Contains(rendered, "only-the-header@example.com") {
		t.Fatalf("rendered message does not contain the header from address:\n%s", rendered)
	}
}

func TestDotStuffDoublesLeadingDot(t *testing.T) {
	body := "Subject: test\r\n\r\n.leading dot line\r\nordinary line\r\n"
	stuffed := string(DotStuff(body))

	if !strings.Contains(stuffed, "\r\n..leading dot line\r\n") {
		t.Errorf("stuffed body does not double the leading dot:\n%q", stuffed)
	}
	if !strings.HasSuffix(stuffed, "\r\n.\r\n") {
		t.Errorf("stuffed body does not terminate with CRLF.CRLF:\n%q", stuffed)
	}
}

func TestDotStuffLeavesOrdinaryLinesAlone(t *testing.T) {
	body := "hello\r\nworld\r\n"
	stuffed := string(DotStuff(body))
	if strings.Contains(stuffed, "hello\r\n.") {
		t.Errorf("ordinary line was stuffed unexpectedly:\n%q", stuffed)
	}
	if !strings.HasPrefix(stuffed, "hello\r\nworld\r\n") {
		t.Errorf("stuffed body altered ordinary content:\n%q", stuffed)
	}
}

func TestDotStuffTerminatesEvenEmptyBody(t *testing.T) {
	stuffed := string(DotStuff(""))
	if stuffed != ".\r\n" {
		t.Errorf("DotStuff(\"\") = %q, want %q", stuffed, ".\r\n")
	}
}
