package smtpconv

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"

	"github.com/MatrixMagician/Frank/internal/transcript"
)

// TLSMode is what --tls selects.
type TLSMode int

const (
	// TLSPrefer uses STARTTLS where advertised and continues without it where
	// it is not. This is the default.
	TLSPrefer TLSMode = iota
	// TLSRequire aborts the Probe when STARTTLS is unavailable.
	TLSRequire
	// TLSNone never issues STARTTLS, even where it is advertised.
	TLSNone
)

var tlsModeNames = [...]string{"prefer", "require", "none"}

func (m TLSMode) String() string {
	if int(m) < 0 || int(m) >= len(tlsModeNames) {
		return "unknown"
	}
	return tlsModeNames[m]
}

// ParseTLSMode turns the --tls flag value into a mode.
func ParseTLSMode(s string) (TLSMode, error) {
	for i, name := range tlsModeNames {
		if strings.EqualFold(s, name) {
			return TLSMode(i), nil
		}
	}
	return 0, fmt.Errorf("smtpconv: unknown tls mode %q, want prefer, require or none", s)
}

// startTLS upgrades conn per ADR-0004: one code path, dialed identically
// whatever --tls-verify says, with the presented chain always captured and
// verification run separately afterwards against an explicit pool. The
// verification result is recorded as a finding either way; verify decides only
// whether a failure aborts the Probe.
//
// The unconditional InsecureSkipVerify below is load-bearing, not an
// oversight. A verifying handshake that fails aborts before the Transcript has
// recorded the chain that caused it, which is the certificate a forensics user
// most needs to see.
func startTLS(tr *transcript.Transcript, res *Result, conn net.Conn, reader *bufio.Reader,
	cfg Config) (net.Conn, *bufio.Reader, bool) {

	startIdx := len(tr.Events)
	reply, ok := verb(tr, res, conn, reader, transcript.PhaseSTARTTLS, "STARTTLS")
	if !ok {
		return conn, reader, false
	}
	recordDuration(tr, res, transcript.PhaseSTARTTLS, tr.Events[len(tr.Events)-1], startIdx)

	if !reply.IsPositive() {
		res.Outcome = mustOutcome(transcript.PhaseSTARTTLS, *reply)
		return conn, reader, false
	}

	serverName := cfg.TLSServerName
	if serverName == "" {
		serverName = defaultServerName(cfg.TargetHost)
	}

	var presented []*x509.Certificate
	tconn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		// VerifyPeerCertificate is not invoked on a resumed connection, so a
		// resumption would produce a Transcript with no certificate in it.
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			for _, der := range raw {
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return err
				}
				presented = append(presented, cert)
			}
			return nil
		},
	})

	if err := tconn.Handshake(); err != nil {
		ev := tr.Append(transcript.KindError, transcript.PhaseSTARTTLS, []byte(err.Error()))
		recordDuration(tr, res, transcript.PhaseSTARTTLS, ev, startIdx)
		res.Err = fmt.Errorf("smtpconv: tls handshake: %w", err)
		return conn, reader, false
	}

	state := tconn.ConnectionState()
	details := &transcript.TLSDetails{
		Version:    tls.VersionName(state.Version),
		Cipher:     tls.CipherSuiteName(state.CipherSuite),
		ServerName: serverName,
		Chain:      describeChain(presented),
	}

	verifyErr := verifyChain(presented, serverName, cfg.TLSRootCAs)
	details.Verified = verifyErr == nil
	if verifyErr != nil {
		details.VerifyError = verifyErr.Error()
	}
	tr.TLS = details

	note := fmt.Sprintf("tls %s with %s, server name %s, verification %s",
		details.Version, details.Cipher, serverName, verificationWord(details.Verified))
	if verifyErr != nil {
		note += ": " + verifyErr.Error()
	}
	tr.Append(transcript.KindTLS, transcript.PhaseSTARTTLS, nil).Note = note

	if verifyErr != nil && cfg.TLSVerify {
		res.Err = fmt.Errorf("smtpconv: tls verification failed: %w", verifyErr)
		return tconn, bufio.NewReader(tconn), false
	}

	return tconn, bufio.NewReader(tconn), true
}

func verificationWord(ok bool) string {
	if ok {
		return "succeeded"
	}
	return "failed"
}

// verifyChain runs the verification ADR-0004 keeps separate from the
// handshake, against an explicit pool so the answer is recorded rather than
// implied by whether the Probe survived.
func verifyChain(chain []*x509.Certificate, serverName string, roots *x509.CertPool) error {
	if len(chain) == 0 {
		return fmt.Errorf("no certificate was presented")
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       serverName,
		Roots:         roots,
		Intermediates: intermediates,
	})
	return err
}

func describeChain(chain []*x509.Certificate) []transcript.TLSCertificate {
	out := make([]transcript.TLSCertificate, len(chain))
	for i, c := range chain {
		out[i] = transcript.TLSCertificate{
			Subject:      c.Subject.String(),
			Issuer:       c.Issuer.String(),
			NotBefore:    c.NotBefore,
			NotAfter:     c.NotAfter,
			DNSNames:     c.DNSNames,
			SerialNumber: c.SerialNumber.String(),
		}
	}
	return out
}

// defaultServerName is the host half of the target, so verification has a name
// to match against. ADR-0004 requires it be set explicitly rather than left to
// the transport, or the check has nothing to compare.
func defaultServerName(target string) string {
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	return target
}

func advertisesSTARTTLS(exts []transcript.Extension) bool {
	for _, e := range exts {
		if strings.EqualFold(e.Name, "STARTTLS") {
			return true
		}
	}
	return false
}
