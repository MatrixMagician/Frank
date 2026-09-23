package cli

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MatrixMagician/Frank/internal/resolve"
)

func TestAuthRendersTreeAndVerdict(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 include:inc.example -all")
	z.TXT("inc.example", "v=spf1 ip4:192.0.2.0/24 -all")

	var stdout, stderr bytes.Buffer
	code := runAuthWith(context.Background(), &Options{}, authOptions{
		envelopeFrom: "a@example.com",
		helo:         "frank.invalid",
		candidateIP:  "192.0.2.7",
		resolver:     z,
	}, &stdout, &stderr)

	if code != CodeAcceptance {
		t.Errorf("code = %v, want %v (stderr: %s)", code, CodeAcceptance, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"subject: example.com", "verdict: pass", "include:inc.example", "matched mechanism:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
}

func TestAuthWithoutCandidateIPReportsNotEvaluated(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 include:inc.example -all")
	z.TXT("inc.example", "v=spf1 ip4:192.0.2.0/24 -all")

	var stdout, stderr bytes.Buffer
	code := runAuthWith(context.Background(), &Options{}, authOptions{
		envelopeFrom: "a@example.com",
		resolver:     z,
	}, &stdout, &stderr)

	if code != CodeAcceptance {
		t.Errorf("code = %v, want %v", code, CodeAcceptance)
	}
	out := stdout.String()
	if !strings.Contains(out, "not-evaluated") {
		t.Errorf("output does not report the verdict as not evaluated:\n%s", out)
	}
	if !strings.Contains(out, "include:inc.example") {
		t.Errorf("tree is not rendered without a Candidate Sending IP:\n%s", out)
	}
}

// TestAuthOpensNoTCPConnection installs a dialer that records any attempt and
// asserts none was made. `auth` reads DNS and nothing else, which is why it
// has no observed Source Address to default the Candidate Sending IP to.
// TestAuthOpensNoTCPConnection stands a real SMTP listener up and asserts auth
// never touches it. Counting dials through an injected resolver would be
// circular: a fixture resolver cannot dial by construction, so such a test
// passes however auth behaves. This one would catch auth growing a probe.
func TestAuthOpensNoTCPConnection(t *testing.T) {
	var accepted atomic.Int64

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conn.Close()
		}
	}()

	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all")
	z.MX("example.com", 10, ln.Addr().String())
	z.A("example.com", "127.0.0.1")

	var stdout, stderr bytes.Buffer
	code := runAuthWith(context.Background(), &Options{}, authOptions{
		envelopeFrom: "a@example.com",
		helo:         ln.Addr().String(),
		headerFrom:   "a@example.com",
		candidateIP:  "192.0.2.7",
		resolver:     z,
	}, &stdout, &stderr)

	if code != CodeAcceptance {
		t.Fatalf("code = %v, want %v (stderr: %s)", code, CodeAcceptance, stderr.String())
	}
	if got := accepted.Load(); got != 0 {
		t.Errorf("auth opened %d tcp connections to the listener, want 0", got)
	}
}

func TestAuthRejectsZonedCandidateIP(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 -all")

	var stdout, stderr bytes.Buffer
	code := runAuthWith(context.Background(), &Options{}, authOptions{
		envelopeFrom: "a@example.com",
		candidateIP:  "fe80::1%eth0",
		resolver:     z,
	}, &stdout, &stderr)

	if code != CodeUsage {
		t.Errorf("code = %v, want %v for an address carrying a zone", code, CodeUsage)
	}
}

func TestAuthTakesTheCandidateIPFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runAuth(&Options{}, []string{"--envelope-from", "a@example.com", "--candidate-ip", "nope"}, &stdout, &stderr)
	if code != CodeUsage {
		t.Errorf("code = %v, want %v for an unparseable address", code, CodeUsage)
	}
	if want := `--candidate-ip "nope" is not an ip address`; !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
	}

	stderr.Reset()
	if code := runAuth(&Options{}, []string{"--envelope-from", "a@example.com", "--client-ip", "192.0.2.7"}, &stdout, &stderr); code != CodeUsage {
		t.Errorf("--client-ip: code = %v, want %v: the flag was renamed outright", code, CodeUsage)
	}
}

func TestAuthNullEnvelopeSenderUsesHELOSubject(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("frank.invalid", "v=spf1 ip4:192.0.2.0/24 -all")

	var stdout, stderr bytes.Buffer
	code := runAuthWith(context.Background(), &Options{}, authOptions{
		helo:        "frank.invalid",
		candidateIP: "192.0.2.7",
		resolver:    z,
	}, &stdout, &stderr)

	if code != CodeAcceptance {
		t.Fatalf("code = %v, want %v (stderr: %s)", code, CodeAcceptance, stderr.String())
	}
	if !strings.Contains(stdout.String(), "frank.invalid") {
		t.Errorf("output does not name the HELO Identity as the subject:\n%s", stdout.String())
	}
}
