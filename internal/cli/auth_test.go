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
		clientIP:     "192.0.2.7",
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

func TestAuthWithoutClientIPReportsNotEvaluated(t *testing.T) {
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
		t.Errorf("tree is not rendered without a client IP:\n%s", out)
	}
}

// TestAuthOpensNoTCPConnection installs a dialer that records any attempt and
// asserts none was made. `auth` reads DNS and nothing else, which is why it
// has no observed Source Address to default the Candidate Sending IP to.
func TestAuthOpensNoTCPConnection(t *testing.T) {
	var dials atomic.Int64
	original := net.DefaultResolver.Dial
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return nil, net.ErrClosed
	}
	t.Cleanup(func() { net.DefaultResolver.Dial = original })

	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all")

	var stdout, stderr bytes.Buffer
	runAuthWith(context.Background(), &Options{}, authOptions{
		envelopeFrom: "a@example.com",
		clientIP:     "192.0.2.7",
		resolver:     z,
	}, &stdout, &stderr)

	if got := dials.Load(); got != 0 {
		t.Errorf("auth made %d outbound dials, want 0", got)
	}
}

func TestAuthRejectsZonedClientIP(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 -all")

	var stdout, stderr bytes.Buffer
	code := runAuthWith(context.Background(), &Options{}, authOptions{
		envelopeFrom: "a@example.com",
		clientIP:     "fe80::1%eth0",
		resolver:     z,
	}, &stdout, &stderr)

	if code != CodeUsage {
		t.Errorf("code = %v, want %v for an address carrying a zone", code, CodeUsage)
	}
}

func TestAuthNullEnvelopeSenderUsesHELOSubject(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("frank.invalid", "v=spf1 ip4:192.0.2.0/24 -all")

	var stdout, stderr bytes.Buffer
	code := runAuthWith(context.Background(), &Options{}, authOptions{
		helo:     "frank.invalid",
		clientIP: "192.0.2.7",
		resolver: z,
	}, &stdout, &stderr)

	if code != CodeAcceptance {
		t.Fatalf("code = %v, want %v (stderr: %s)", code, CodeAcceptance, stderr.String())
	}
	if !strings.Contains(stdout.String(), "frank.invalid") {
		t.Errorf("output does not name the HELO Identity as the subject:\n%s", stdout.String())
	}
}
