package smtpconv

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/MatrixMagician/Frank/internal/smtptest"
	"github.com/MatrixMagician/Frank/internal/transcript"
)

func tlsProbe(t *testing.T, srv *smtptest.Server, mode TLSMode, verify bool, roots *x509.CertPool) *Result {
	t.Helper()
	return Run(Config{
		TargetHost: srv.Addr(),
		Triple: IdentityTriple{
			EnvelopeSender: NewEnvelopeSender("bounce@sender.example"),
			HeloIdentity:   "frank.invalid",
			HeaderFrom:     "author@sender.example",
		},
		Recipient:     "rcpt@target.example",
		DryRun:        true,
		TLSMode:       mode,
		TLSVerify:     verify,
		TLSServerName: smtptest.CertHostname,
		TLSRootCAs:    roots,
	})
}

func TestTLSModePolicy(t *testing.T) {
	t.Run("require aborts when starttls is unavailable", func(t *testing.T) {
		srv := smtptest.Start(t)
		res := tlsProbe(t, srv, TLSRequire, false, nil)

		if res.Err == nil {
			t.Fatal("probe succeeded, want an abort when STARTTLS is unavailable under require")
		}
		if !strings.Contains(res.Err.Error(), "starttls required") {
			t.Errorf("err = %v, want it to name the missing STARTTLS", res.Err)
		}
	})

	t.Run("prefer continues in plaintext when starttls is unavailable", func(t *testing.T) {
		srv := smtptest.Start(t)
		res := tlsProbe(t, srv, TLSPrefer, false, nil)

		if res.Err != nil {
			t.Fatalf("probe failed under prefer: %v", res.Err)
		}
		if res.Transcript.TLS != nil {
			t.Error("TLS details are populated, but no upgrade happened")
		}
		if !noteContains(res.Transcript, "continuing in plaintext") {
			t.Error("the transcript does not record that the probe continued in plaintext")
		}
	})

	t.Run("none never offers starttls even when advertised", func(t *testing.T) {
		srv := smtptest.Start(t, smtptest.WithSTARTTLS())
		res := tlsProbe(t, srv, TLSNone, false, nil)

		if res.Err != nil {
			t.Fatalf("probe failed under none: %v", res.Err)
		}
		if res.Transcript.TLS != nil {
			t.Error("TLS details are populated under mode none")
		}
		for _, e := range res.Transcript.Events {
			if e.Kind == transcript.KindSend && strings.Contains(string(e.Raw), "STARTTLS") {
				t.Error("STARTTLS was sent under mode none")
			}
		}
	})

	t.Run("prefer upgrades when starttls is advertised", func(t *testing.T) {
		srv := smtptest.Start(t, smtptest.WithSTARTTLS())
		res := tlsProbe(t, srv, TLSPrefer, false, nil)

		if res.Err != nil {
			t.Fatalf("probe failed: %v", res.Err)
		}
		if res.Transcript.TLS == nil {
			t.Fatal("TLS details are nil after an upgrade")
		}
	})
}

// TestTLSEvidenceIdenticalUnderBothVerifyModes is ADR-0004's central claim:
// the connection is made the same way either way, so the chain, version and
// cipher land in the Transcript identically whether verification passed.
func TestTLSEvidenceIdenticalUnderBothVerifyModes(t *testing.T) {
	trusting := smtptest.Start(t, smtptest.WithSTARTTLS())
	pool := x509.NewCertPool()
	pool.AddCert(trusting.Certificate())

	passing := tlsProbe(t, trusting, TLSPrefer, true, pool)
	if passing.Err != nil {
		t.Fatalf("probe with a trusted certificate failed: %v", passing.Err)
	}

	failing := tlsProbe(t, trusting, TLSPrefer, false, nil)
	if failing.Err != nil {
		t.Fatalf("probe with verification disabled failed: %v", failing.Err)
	}

	if passing.Transcript.TLS.Version != failing.Transcript.TLS.Version {
		t.Errorf("versions differ: %q against %q", passing.Transcript.TLS.Version, failing.Transcript.TLS.Version)
	}
	if passing.Transcript.TLS.Cipher != failing.Transcript.TLS.Cipher {
		t.Errorf("ciphers differ: %q against %q", passing.Transcript.TLS.Cipher, failing.Transcript.TLS.Cipher)
	}
	if len(passing.Transcript.TLS.Chain) != len(failing.Transcript.TLS.Chain) {
		t.Fatalf("chain lengths differ: %d against %d", len(passing.Transcript.TLS.Chain), len(failing.Transcript.TLS.Chain))
	}
	if passing.Transcript.TLS.Chain[0].Subject != failing.Transcript.TLS.Chain[0].Subject {
		t.Error("the captured certificate differs between verify modes")
	}

	if !passing.Transcript.TLS.Verified {
		t.Error("verification against a pool that trusts the certificate did not succeed")
	}
	if failing.Transcript.TLS.Verified {
		t.Error("verification against the system roots succeeded for a self-signed certificate")
	}
}

func TestSelfSignedCompletesWithVerifyDisabledAndRecordsTheFailure(t *testing.T) {
	srv := smtptest.Start(t, smtptest.WithSTARTTLS())
	res := tlsProbe(t, srv, TLSPrefer, false, nil)

	if res.Err != nil {
		t.Fatalf("probe aborted with --tls-verify=false: %v", res.Err)
	}
	if res.Transcript.TLS == nil {
		t.Fatal("TLS details are nil")
	}
	if res.Transcript.TLS.Verified {
		t.Error("a self-signed certificate reported as verified")
	}
	if res.Transcript.TLS.VerifyError == "" {
		t.Error("the verification failure is not recorded as a finding")
	}
	if !noteContains(res.Transcript, "verification failed") {
		t.Error("the transcript does not carry the verification failure as a note")
	}
}

func TestSelfSignedAbortsWithVerifyEnabledAndKeepsChain(t *testing.T) {
	srv := smtptest.Start(t, smtptest.WithSTARTTLS())
	res := tlsProbe(t, srv, TLSPrefer, true, nil)

	if res.Err == nil {
		t.Fatal("probe completed with --tls-verify=true against a self-signed certificate")
	}
	if res.Transcript.TLS == nil {
		t.Fatal("TLS details are nil after an aborting verification, but the chain is what a forensics user most needs")
	}
	if len(res.Transcript.TLS.Chain) == 0 {
		t.Error("the chain is missing from the transcript of an aborted probe")
	}
	if res.Transcript.TLS.Chain[0].Subject == "" {
		t.Error("the captured certificate carries no subject")
	}
}

// TestSessionResumptionDisabledCertCapturedEveryConnection guards the reason
// ADR-0004 sets SessionTicketsDisabled: VerifyPeerCertificate is not invoked
// on a resumed connection, so a resumption would produce a Transcript with no
// certificate in it at all.
func TestSessionResumptionDisabledCertCapturedEveryConnection(t *testing.T) {
	srv := smtptest.Start(t, smtptest.WithSTARTTLS())

	for i := range 4 {
		res := tlsProbe(t, srv, TLSPrefer, false, nil)
		if res.Err != nil {
			t.Fatalf("probe %d failed: %v", i+1, res.Err)
		}
		if res.Transcript.TLS == nil || len(res.Transcript.TLS.Chain) == 0 {
			t.Fatalf("probe %d captured no certificate, which is what a resumed session would look like", i+1)
		}
	}
}

// TestResumedSessionSkipsCertificateCapture is the evidence behind
// SessionTicketsDisabled in startTLS. It runs its own TLS server so it can
// share a ticket key across two handshakes, forces a resumption, and shows the
// verify hook is not invoked the second time. That is the
// Transcript-with-no-certificate ADR-0004 exists to prevent, which is why the
// setting is load-bearing rather than a stray line someone may tidy away.
func TestResumedSessionSkipsCertificateCapture(t *testing.T) {
	cert, _, err := smtptest.TestCertificate()
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := tls.Server(c, serverCfg)
				tc.Handshake()
				io.Copy(io.Discard, tc)
				tc.Close()
			}()
		}
	}()

	cache := tls.NewLRUClientSessionCache(4)
	var captures []int
	var resumed []bool

	for range 2 {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		var seen int
		tconn := tls.Client(conn, &tls.Config{
			ServerName:         smtptest.CertHostname,
			InsecureSkipVerify: true,
			ClientSessionCache: cache,
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				seen = len(raw)
				return nil
			},
		})
		if err := tconn.Handshake(); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		captures = append(captures, seen)
		resumed = append(resumed, tconn.ConnectionState().DidResume)

		// Under TLS 1.3 the ticket arrives after the handshake, so the cache is
		// only populated once the client reads from the connection.
		tconn.Write([]byte("x"))
		tconn.SetReadDeadline(time.Now().Add(time.Second))
		tconn.Read(make([]byte, 1))
		tconn.Close()
		conn.Close()
	}

	if !resumed[1] {
		t.Fatal("the second handshake did not resume, so the guard cannot be demonstrated")
	}
	if captures[0] == 0 {
		t.Fatal("the first handshake captured no certificate")
	}
	if captures[1] != 0 {
		t.Fatalf("the resumed handshake captured %d certificates, so this Go release no longer skips the hook and the ADR needs revisiting", captures[1])
	}
}

func TestServerNameIsExplicitAndRecorded(t *testing.T) {
	srv := smtptest.Start(t, smtptest.WithSTARTTLS())
	res := tlsProbe(t, srv, TLSPrefer, false, nil)

	if res.Transcript.TLS == nil {
		t.Fatal("TLS details are nil")
	}
	if res.Transcript.TLS.ServerName != smtptest.CertHostname {
		t.Errorf("ServerName = %q, want the explicitly supplied %q", res.Transcript.TLS.ServerName, smtptest.CertHostname)
	}
	if !noteContains(res.Transcript, "server name "+smtptest.CertHostname) {
		t.Error("the transcript note does not record the server name verification used")
	}
}

func TestServerNameDefaultsToTheTargetHost(t *testing.T) {
	srv := smtptest.Start(t, smtptest.WithSTARTTLS())
	res := Run(Config{
		TargetHost: srv.Addr(),
		Triple: IdentityTriple{
			EnvelopeSender: NewEnvelopeSender("a@example.com"),
			HeloIdentity:   "frank.invalid",
			HeaderFrom:     "a@example.com",
		},
		Recipient: "b@example.com",
		DryRun:    true,
		TLSMode:   TLSPrefer,
	})

	if res.Transcript.TLS == nil {
		t.Fatal("TLS details are nil")
	}
	if res.Transcript.TLS.ServerName != "127.0.0.1" {
		t.Errorf("ServerName = %q, want the host half of the target", res.Transcript.TLS.ServerName)
	}
}

func TestTLSVersionAndCipherAreRecorded(t *testing.T) {
	srv := smtptest.Start(t, smtptest.WithSTARTTLS())
	res := tlsProbe(t, srv, TLSPrefer, false, nil)

	if res.Transcript.TLS == nil {
		t.Fatal("TLS details are nil")
	}
	if !strings.HasPrefix(res.Transcript.TLS.Version, "TLS ") {
		t.Errorf("Version = %q, want a negotiated TLS version", res.Transcript.TLS.Version)
	}
	if res.Transcript.TLS.Cipher == "" {
		t.Error("Cipher is empty")
	}
}

func TestParseTLSMode(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want TLSMode
	}{
		{"prefer", TLSPrefer},
		{"require", TLSRequire},
		{"none", TLSNone},
		{"REQUIRE", TLSRequire},
	} {
		got, err := ParseTLSMode(tt.in)
		if err != nil {
			t.Errorf("ParseTLSMode(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseTLSMode(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
	if _, err := ParseTLSMode("maybe"); err == nil {
		t.Error("ParseTLSMode(\"maybe\") succeeded, want an error naming the valid modes")
	}
}

func noteContains(tr *transcript.Transcript, want string) bool {
	for _, e := range tr.Events {
		if strings.Contains(e.Note, want) {
			return true
		}
	}
	return false
}

// TestStartTLSDisablesSessionResumption checks the production path, not just
// Go's behaviour. TestResumedSessionSkipsCertificateCapture shows why the
// setting matters; this shows startTLS actually applies it, so removing the
// line fails here rather than silently producing certificate-free transcripts.
func TestStartTLSDisablesSessionResumption(t *testing.T) {
	srv := smtptest.Start(t, smtptest.WithSTARTTLS())

	res := tlsProbe(t, srv, TLSPrefer, false, nil)
	if res.Err != nil {
		t.Fatalf("probe failed: %v", res.Err)
	}
	if res.Transcript.TLS == nil {
		t.Fatal("TLS details are nil")
	}
	if !res.Transcript.TLS.ResumptionDisabled {
		t.Error("the probe negotiated TLS without disabling session resumption, so a resumed connection would capture no certificate")
	}
}
