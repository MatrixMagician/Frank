package smtptest

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// client is a deliberately minimal SMTP client used only to drive the double.
// The real hand-rolled client is issue #4's; this one exists so the double's
// tests do not depend on it.
type client struct {
	conn net.Conn
	rw   *bufio.ReadWriter
	t    *testing.T
}

func dial(t *testing.T, s *Server) *client {
	t.Helper()
	conn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &client{conn: conn, rw: bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)), t: t}
}

// readReply reads one reply, following 250- continuations to the final line.
func (c *client) readReply() (int, []string) {
	c.t.Helper()
	var lines []string
	for {
		line, err := c.rw.Reader.ReadString('\n')
		if err != nil {
			c.t.Fatalf("read: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if len(line) < 4 || line[3] == ' ' {
			code := 0
			fmt.Sscanf(line[:3], "%d", &code)
			return code, lines
		}
	}
}

func (c *client) send(format string, args ...any) (int, []string) {
	c.t.Helper()
	fmt.Fprintf(c.rw.Writer, format+"\r\n", args...)
	if err := c.rw.Writer.Flush(); err != nil {
		c.t.Fatalf("flush: %v", err)
	}
	return c.readReply()
}

func (c *client) upgrade(pool *x509.CertPool) *tls.ConnectionState {
	c.t.Helper()
	cfg := &tls.Config{ServerName: CertHostname, InsecureSkipVerify: true, SessionTicketsDisabled: true}
	if pool != nil {
		cfg = &tls.Config{ServerName: CertHostname, RootCAs: pool}
	}
	tconn := tls.Client(c.conn, cfg)
	if err := tconn.Handshake(); err != nil {
		c.t.Fatalf("tls handshake: %v", err)
	}
	c.conn = tconn
	c.rw = bufio.NewReadWriter(bufio.NewReader(tconn), bufio.NewWriter(tconn))
	st := tconn.ConnectionState()
	return &st
}

func TestBannerAndQuit(t *testing.T) {
	s := Start(t)
	c := dial(t, s)

	code, _ := c.readReply()
	if code != 220 {
		t.Errorf("banner code = %d, want 220", code)
	}
	if code, _ := c.send("QUIT"); code != 221 {
		t.Errorf("QUIT code = %d, want 221", code)
	}
}

func TestEHLOAdvertisesConfiguredExtensions(t *testing.T) {
	s := Start(t, WithExtensions("SIZE 10240000", "AUTH PLAIN LOGIN", "PIPELINING", "8BITMIME", "ENHANCEDSTATUSCODES"))
	c := dial(t, s)
	c.readReply()

	code, lines := c.send("EHLO frank.invalid")
	if code != 250 {
		t.Fatalf("EHLO code = %d, want 250", code)
	}
	for i, l := range lines[:len(lines)-1] {
		if l[3] != '-' {
			t.Errorf("line %d = %q, want a %q continuation separator", i, l, "-")
		}
	}
	last := lines[len(lines)-1]
	if last[3] != ' ' {
		t.Errorf("final line = %q, want a space separator", last)
	}
	for _, want := range []string{"SIZE 10240000", "AUTH PLAIN LOGIN", "PIPELINING", "8BITMIME"} {
		if !strings.Contains(strings.Join(lines, "\n"), want) {
			t.Errorf("EHLO reply does not advertise %q:\n%s", want, strings.Join(lines, "\n"))
		}
	}
}

func TestEHLORefusedFallsBackToHELO(t *testing.T) {
	s := Start(t, RefuseEHLO())
	c := dial(t, s)
	c.readReply()

	if code, _ := c.send("EHLO frank.invalid"); code != 502 {
		t.Errorf("EHLO code = %d, want 502 so a client must fall back", code)
	}
	if code, _ := c.send("HELO frank.invalid"); code != 250 {
		t.Errorf("HELO code = %d, want 250", code)
	}
}

func TestRejectAtEachPhase(t *testing.T) {
	tests := []struct {
		name  string
		phase Phase
		drive func(*client) (int, []string)
	}{
		{"banner", PhaseBanner, func(c *client) (int, []string) { return c.readReply() }},
		{"ehlo", PhaseEHLO, func(c *client) (int, []string) { c.readReply(); return c.send("EHLO frank.invalid") }},
		{"mail-from", PhaseMailFrom, func(c *client) (int, []string) {
			c.readReply()
			c.send("EHLO frank.invalid")
			return c.send("MAIL FROM:<a@example.com>")
		}},
		{"rcpt-to", PhaseRcptTo, func(c *client) (int, []string) {
			c.readReply()
			c.send("EHLO frank.invalid")
			c.send("MAIL FROM:<a@example.com>")
			return c.send("RCPT TO:<b@example.com>")
		}},
		{"data", PhaseData, func(c *client) (int, []string) {
			c.readReply()
			c.send("EHLO frank.invalid")
			c.send("MAIL FROM:<a@example.com>")
			c.send("RCPT TO:<b@example.com>")
			return c.send("DATA")
		}},
		{"end-of-data", PhaseEndOfData, func(c *client) (int, []string) {
			c.readReply()
			c.send("EHLO frank.invalid")
			c.send("MAIL FROM:<a@example.com>")
			c.send("RCPT TO:<b@example.com>")
			c.send("DATA")
			return c.send("From: a@example.com\r\n\r\nbody\r\n.")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Start(t, Reject(tt.phase, 550, "5.7.1", "refused by policy at "+tt.phase.String()))
			c := dial(t, s)

			code, lines := tt.drive(c)
			if code != 550 {
				t.Errorf("code at %s = %d, want 550", tt.phase, code)
			}
			joined := strings.Join(lines, "\n")
			if !strings.Contains(joined, "5.7.1") {
				t.Errorf("reply %q does not carry the enhanced status code", joined)
			}
			if !strings.Contains(joined, tt.phase.String()) {
				t.Errorf("reply %q does not carry the caller-supplied text", joined)
			}
		})
	}
}

func TestSTARTTLSUpgradesAndPresentsSelfSignedCert(t *testing.T) {
	s := Start(t, WithSTARTTLS(), WithExtensions("AUTH PLAIN LOGIN"))
	c := dial(t, s)
	c.readReply()

	_, lines := c.send("EHLO frank.invalid")
	if !strings.Contains(strings.Join(lines, "\n"), "STARTTLS") {
		t.Fatalf("EHLO does not advertise STARTTLS:\n%s", strings.Join(lines, "\n"))
	}
	if code, _ := c.send("STARTTLS"); code != 220 {
		t.Fatalf("STARTTLS code = %d, want 220", code)
	}

	st := c.upgrade(nil)
	if len(st.PeerCertificates) != 1 {
		t.Fatalf("peer certificates = %d, want 1", len(st.PeerCertificates))
	}
	if st.PeerCertificates[0].Subject.CommonName != CertHostname {
		t.Errorf("certificate CN = %q, want %q", st.PeerCertificates[0].Subject.CommonName, CertHostname)
	}
	if code, _ := c.send("EHLO frank.invalid"); code != 250 {
		t.Errorf("EHLO after upgrade = %d, want 250", code)
	}
}

func TestSelfSignedCertFailsDefaultVerificationButPassesAgainstSeededPool(t *testing.T) {
	s := Start(t, WithSTARTTLS())

	leaf := s.Certificate()
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: CertHostname}); err == nil {
		t.Error("certificate verified against the system roots, want a failure a Probe records as a finding")
	}

	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: CertHostname, Roots: pool}); err != nil {
		t.Errorf("certificate does not verify against a pool that trusts it: %v", err)
	}
}

func TestSTARTTLSRefusedWhenNotOffered(t *testing.T) {
	s := Start(t)
	c := dial(t, s)
	c.readReply()

	_, lines := c.send("EHLO frank.invalid")
	if strings.Contains(strings.Join(lines, "\n"), "STARTTLS") {
		t.Error("EHLO advertises STARTTLS without WithSTARTTLS")
	}
	if code, _ := c.send("STARTTLS"); code != 454 {
		t.Errorf("STARTTLS code = %d, want 454", code)
	}
}

func TestRejectsNamedIdentityTripleAcceptsOthers(t *testing.T) {
	rejected := Triple{EnvelopeSender: "bounce@sender.example", HeaderFrom: "ceo@victim.example"}
	s := Start(t, RejectTriple(PhaseEndOfData, rejected, 550, "5.7.1", "sender not allowed by policy"))

	deliver := func(envelope, headerFrom string) int {
		c := dial(t, s)
		c.readReply()
		c.send("EHLO frank.invalid")
		c.send("MAIL FROM:<%s>", envelope)
		c.send("RCPT TO:<rcpt@target.example>")
		c.send("DATA")
		code, _ := c.send("From: %s\r\nSubject: probe\r\n\r\nbody\r\n.", headerFrom)
		return code
	}

	if got := deliver("bounce@sender.example", "ceo@victim.example"); got != 550 {
		t.Errorf("the named Triple was accepted with %d, want 550", got)
	}
	if got := deliver("bounce@sender.example", "bounce@sender.example"); got != 250 {
		t.Errorf("an aligned Triple got %d, want 250", got)
	}
	if got := deliver("other@sender.example", "ceo@victim.example"); got != 250 {
		t.Errorf("a different envelope got %d, want 250", got)
	}
}

func TestGreylistDefersFirstConnectionAcceptsSecond(t *testing.T) {
	s := Start(t, Greylist(PhaseEndOfData, 1, 450, "4.7.1", "greylisted, try again later"))

	deliver := func() int {
		c := dial(t, s)
		c.readReply()
		c.send("EHLO frank.invalid")
		c.send("MAIL FROM:<a@example.com>")
		c.send("RCPT TO:<b@example.com>")
		c.send("DATA")
		code, _ := c.send("From: a@example.com\r\n\r\nbody\r\n.")
		return code
	}

	if got := deliver(); got != 450 {
		t.Errorf("first connection = %d, want a 450 Deferral", got)
	}
	if got := deliver(); got != 250 {
		t.Errorf("second connection = %d, want 250", got)
	}
}

func TestConnectionCountIsAccurate(t *testing.T) {
	s := Start(t)
	for i := 1; i <= 4; i++ {
		c := dial(t, s)
		c.readReply()
		c.send("QUIT")
		if got := s.ConnectionCount(); got != i {
			t.Errorf("after %d connections ConnectionCount() = %d", i, got)
		}
	}
}

func TestPerConnectionStateTightensAfterRefusal(t *testing.T) {
	// The first RCPT TO on a connection is fine; a second one is refused
	// because the first was. That is per-connection state, and it is exactly
	// the dependence between Cells ADR-0003 avoids by redialling every time.
	s := Start(t,
		Reject(PhaseRcptTo, 550, "5.7.1", "one recipient per connection"),
		TightenAfterRefusal(PhaseMailFrom, 550, "5.7.1", "connection already refused once"),
	)

	c := dial(t, s)
	c.readReply()
	c.send("EHLO frank.invalid")
	if code, _ := c.send("MAIL FROM:<a@example.com>"); code != 250 {
		t.Fatalf("first MAIL FROM = %d, want 250", code)
	}
	if code, _ := c.send("RCPT TO:<b@example.com>"); code != 550 {
		t.Fatalf("RCPT TO = %d, want 550", code)
	}
	if code, _ := c.send("MAIL FROM:<a@example.com>"); code != 550 {
		t.Errorf("second MAIL FROM = %d, want 550 from the tightened per-connection state", code)
	}

	fresh := dial(t, s)
	fresh.readReply()
	fresh.send("EHLO frank.invalid")
	if code, _ := fresh.send("MAIL FROM:<a@example.com>"); code != 250 {
		t.Errorf("MAIL FROM on a fresh connection = %d, want 250: per-connection state must not leak", code)
	}
}

func TestDotStuffingIsUndoneOnReceive(t *testing.T) {
	s := Start(t)
	c := dial(t, s)
	c.readReply()
	c.send("EHLO frank.invalid")
	c.send("MAIL FROM:<a@example.com>")
	c.send("RCPT TO:<b@example.com>")
	c.send("DATA")
	c.send("From: a@example.com\r\n\r\n..leading dot line\r\nplain line\r\n.")

	received := s.Received()
	if len(received) != 1 {
		t.Fatalf("received %d messages, want 1", len(received))
	}
	if !strings.Contains(received[0].Data, ".leading dot line") {
		t.Errorf("body = %q, want the dot-stuffing undone", received[0].Data)
	}
	if strings.Contains(received[0].Data, "..leading") {
		t.Errorf("body = %q, still carries the stuffed dot", received[0].Data)
	}
}

func TestHeaderFromIsParsedFromDATA(t *testing.T) {
	s := Start(t)
	c := dial(t, s)
	c.readReply()
	c.send("EHLO frank.invalid")
	c.send("MAIL FROM:<envelope@sender.example>")
	c.send("RCPT TO:<rcpt@target.example>")
	c.send("DATA")
	c.send("From: <header@author.example>\r\nSubject: probe\r\n\r\nbody\r\n.")

	got := s.Received()[0].Triple
	want := Triple{
		EnvelopeSender: "envelope@sender.example",
		HeloIdentity:   "frank.invalid",
		HeaderFrom:     "header@author.example",
	}
	if got != want {
		t.Errorf("observed Triple = %+v, want %+v", got, want)
	}
}

func TestNullEnvelopeSenderIsRecordedAsEmpty(t *testing.T) {
	s := Start(t)
	c := dial(t, s)
	c.readReply()
	c.send("EHLO frank.invalid")
	if code, _ := c.send("MAIL FROM:<>"); code != 250 {
		t.Fatalf("null sender = %d, want 250: <> is a legal value, not an error", code)
	}
	c.send("RCPT TO:<b@example.com>")
	c.send("DATA")
	c.send("From: a@example.com\r\n\r\nbody\r\n.")

	if got := s.Received()[0].Triple.EnvelopeSender; got != "" {
		t.Errorf("envelope sender = %q, want empty for the null sender", got)
	}
}

func TestAuthPlainAndLoginAreRecorded(t *testing.T) {
	t.Run("PLAIN", func(t *testing.T) {
		s := Start(t, WithExtensions("AUTH PLAIN LOGIN"))
		c := dial(t, s)
		c.readReply()
		c.send("EHLO frank.invalid")

		payload := base64.StdEncoding.EncodeToString([]byte("\x00probe@example.com\x00hunter2"))
		if code, _ := c.send("AUTH PLAIN %s", payload); code != 235 {
			t.Fatalf("AUTH PLAIN = %d, want 235", code)
		}
		creds := s.Credentials()
		if len(creds) != 1 || creds[0].Username != "probe@example.com" || creds[0].Password != "hunter2" {
			t.Errorf("credentials = %+v, want the PLAIN username and password recorded", creds)
		}
	})

	t.Run("LOGIN", func(t *testing.T) {
		s := Start(t, WithExtensions("AUTH PLAIN LOGIN"))
		c := dial(t, s)
		c.readReply()
		c.send("EHLO frank.invalid")

		code, _ := c.send("AUTH LOGIN")
		if code != 334 {
			t.Fatalf("AUTH LOGIN = %d, want a 334 challenge", code)
		}
		if code, _ = c.send("%s", base64.StdEncoding.EncodeToString([]byte("probe@example.com"))); code != 334 {
			t.Fatalf("username challenge = %d, want 334", code)
		}
		if code, _ = c.send("%s", base64.StdEncoding.EncodeToString([]byte("hunter2"))); code != 235 {
			t.Fatalf("password = %d, want 235", code)
		}
		creds := s.Credentials()
		if len(creds) != 1 || creds[0].Username != "probe@example.com" || creds[0].Password != "hunter2" {
			t.Errorf("credentials = %+v, want the LOGIN username and password recorded", creds)
		}
	})
}

func TestAuthAdvertisedOnlyOverTLS(t *testing.T) {
	s := Start(t, WithSTARTTLS(), WithAuthOverTLSOnly(), WithExtensions("AUTH PLAIN LOGIN"))
	c := dial(t, s)
	c.readReply()

	_, plain := c.send("EHLO frank.invalid")
	if strings.Contains(strings.Join(plain, "\n"), "AUTH") {
		t.Error("AUTH advertised before TLS, want it hidden until the connection is encrypted")
	}

	c.send("STARTTLS")
	c.upgrade(nil)
	_, encrypted := c.send("EHLO frank.invalid")
	if !strings.Contains(strings.Join(encrypted, "\n"), "AUTH") {
		t.Errorf("AUTH not advertised after TLS:\n%s", strings.Join(encrypted, "\n"))
	}
}

func TestUnsupportedAuthMechanismIsReportedClearly(t *testing.T) {
	s := Start(t, WithExtensions("AUTH PLAIN"))
	c := dial(t, s)
	c.readReply()
	c.send("EHLO frank.invalid")

	code, lines := c.send("AUTH CRAM-MD5")
	if code != 504 {
		t.Errorf("code = %d, want 504 for an unsupported mechanism", code)
	}
	if !strings.Contains(strings.ToLower(strings.Join(lines, "\n")), "mechanism") {
		t.Errorf("reply %q does not say what was wrong", strings.Join(lines, "\n"))
	}
}

func TestDelayedReplyTakesAtLeastTheConfiguredTime(t *testing.T) {
	s := Start(t, Delay(PhaseMailFrom, 60*time.Millisecond))
	c := dial(t, s)
	c.readReply()
	c.send("EHLO frank.invalid")

	start := time.Now()
	c.send("MAIL FROM:<a@example.com>")
	if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
		t.Errorf("MAIL FROM took %v, want at least the configured 60ms stall", elapsed)
	}
}

func TestConcurrentConnectionsAreRaceFree(t *testing.T) {
	s := Start(t)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("tcp", s.Addr())
			if err != nil {
				t.Errorf("dial: %v", err)
				return
			}
			defer conn.Close()
			rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
			rw.Reader.ReadString('\n')
			fmt.Fprint(rw.Writer, "EHLO frank.invalid\r\n")
			rw.Writer.Flush()
			for {
				line, err := rw.Reader.ReadString('\n')
				if err != nil || len(line) < 4 || line[3] == ' ' {
					break
				}
			}
			fmt.Fprint(rw.Writer, "MAIL FROM:<a@example.com>\r\nRCPT TO:<b@example.com>\r\nDATA\r\n")
			rw.Writer.Flush()
			fmt.Fprint(rw.Writer, "From: a@example.com\r\n\r\nbody\r\n.\r\nQUIT\r\n")
			rw.Writer.Flush()
		}()
	}
	wg.Wait()

	if got := s.ConnectionCount(); got != 8 {
		t.Errorf("ConnectionCount() = %d, want 8", got)
	}
}

func TestStartsOnEphemeralPortWithoutDiskFixtures(t *testing.T) {
	a := Start(t, WithSTARTTLS())
	b := Start(t, WithSTARTTLS())

	if a.Addr() == b.Addr() {
		t.Errorf("both servers bound %s, want distinct ephemeral ports", a.Addr())
	}
	for _, s := range []*Server{a, b} {
		if !strings.HasPrefix(s.Addr(), "127.0.0.1:") {
			t.Errorf("Addr() = %q, want a loopback address", s.Addr())
		}
		if s.Certificate() == nil {
			t.Error("no certificate was generated in process")
		}
	}
}
