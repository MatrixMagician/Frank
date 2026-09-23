package smtpconv

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/MatrixMagician/Frank/internal/transcript"
)

// Dialer matches net.Dial's signature. smtpconv dials through this seam so
// the in-process test double is reachable and no test touches a live network.
type Dialer func(network, address string) (net.Conn, error)

// Recipient is the single RCPT TO address of a Probe. A named type rather
// than a bare string only so a slice of them cannot silently substitute for
// it; Config carries exactly one, per the glossary.
type Recipient string

// EnvelopeSender models the MAIL FROM value. The zero value is deliberately
// unusable: NewEnvelopeSender and NullEnvelopeSender are the only ways to
// produce a set one, which is what keeps "unset" (a config error) distinct
// from "null" (`<>`, a legal Envelope Sender and the bounce path).
type EnvelopeSender struct {
	address string
	null    bool
	set     bool
}

// NewEnvelopeSender is a non-null Envelope Sender.
func NewEnvelopeSender(address string) EnvelopeSender {
	return EnvelopeSender{address: address, set: true}
}

// NullEnvelopeSender is the explicit `<>` bounce-path sender.
func NullEnvelopeSender() EnvelopeSender {
	return EnvelopeSender{null: true, set: true}
}

func (e EnvelopeSender) IsSet() bool  { return e.set }
func (e EnvelopeSender) IsNull() bool { return e.null }
func (e EnvelopeSender) Address() string {
	if e.null {
		return ""
	}
	return e.address
}

// mailFromArg is the exact bracketed value written after "MAIL FROM:".
func (e EnvelopeSender) mailFromArg() string {
	if e.null {
		return "<>"
	}
	return "<" + e.address + ">"
}

// identityValue is what appears in the Transcript's IdentityTriple: the
// address verbatim, or the literal "<>" for the null sender, so a reader of
// the Transcript sees the null sender was chosen rather than reading an
// empty field as an oversight.
func (e EnvelopeSender) identityValue() string {
	if e.null {
		return "<>"
	}
	return e.address
}

type IdentityTriple struct {
	EnvelopeSender EnvelopeSender
	HeloIdentity   string
	HeaderFrom     string
}

// Config is everything one Probe needs. Dialer, DialTimeout and Now are
// seams: a nil Dialer dials real TCP, a nil Now uses time.Now.
type Config struct {
	TargetHost  string
	Triple      IdentityTriple
	Recipient   Recipient
	DryRun      bool
	Dialer      Dialer
	DialTimeout time.Duration
	Now         func() time.Time

	// TLSMode selects prefer, require or none. The zero value is prefer.
	TLSMode TLSMode
	// TLSVerify decides only whether a verification failure aborts the Probe.
	// The chain is captured and verified either way, per ADR-0004.
	TLSVerify bool
	// TLSServerName overrides the name verification matches against, which
	// otherwise comes from the target.
	TLSServerName string
	// TLSRootCAs is the pool verification runs against, nil meaning the system
	// roots. A test seeds it with the double's self-signed certificate.
	TLSRootCAs *x509.CertPool

	// Credentials authenticate the Probe. Frank refuses to send them over a
	// connection that is not TLS-protected, per ADR-0007.
	Credentials Credentials
}

// Result is everything one Probe produced. Transcript is populated whenever
// dialing was attempted, even on failure; Outcome is nil when the Probe never
// reached a Phase whose reply carries one (a config error, a dial failure, or
// a dry run that walked cleanly through RCPT TO).
type Result struct {
	Transcript *transcript.Transcript
	Outcome    *Outcome
	Extensions []transcript.Extension
	Durations  map[transcript.Phase]time.Duration
	Err        error
}

func validate(cfg Config) error {
	if cfg.TargetHost == "" {
		return fmt.Errorf("smtpconv: target host is empty")
	}
	if cfg.Recipient == "" {
		return fmt.Errorf("smtpconv: recipient is empty")
	}
	if cfg.Triple.HeloIdentity == "" {
		return fmt.Errorf("smtpconv: helo identity is empty")
	}
	if cfg.Triple.HeaderFrom == "" {
		return fmt.Errorf("smtpconv: header from is empty")
	}
	if !cfg.Triple.EnvelopeSender.IsSet() {
		return fmt.Errorf("smtpconv: envelope sender is not set")
	}
	return nil
}

// Run conducts one Probe against cfg.TargetHost: dial, banner, EHLO with
// HELO fallback, MAIL FROM, RCPT TO, and — unless cfg.DryRun — DATA,
// end-of-data, then QUIT on every exit path.
func Run(cfg Config) *Result {
	if err := validate(cfg); err != nil {
		return &Result{Err: err}
	}

	identity := transcript.IdentityTriple{
		EnvelopeSender: cfg.Triple.EnvelopeSender.identityValue(),
		HeloIdentity:   cfg.Triple.HeloIdentity,
		HeaderFrom:     cfg.Triple.HeaderFrom,
	}
	tr := transcript.NewTranscript(cfg.TargetHost, identity, string(cfg.Recipient))
	res := &Result{Transcript: tr, Durations: map[transcript.Phase]time.Duration{}}

	dialer := cfg.Dialer
	if dialer == nil {
		dialer = (&net.Dialer{Timeout: cfg.DialTimeout}).Dial
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	tr.Append(transcript.KindDial, transcript.PhaseDial, []byte("dial "+cfg.TargetHost))
	conn, err := dialer("tcp", cfg.TargetHost)
	if err != nil {
		ev := tr.Append(transcript.KindError, transcript.PhaseDial, []byte(err.Error()))
		recordDuration(tr, res, transcript.PhaseDial, ev, 0)
		res.Err = fmt.Errorf("smtpconv: dial: %w", err)
		return res
	}
	defer conn.Close()

	if addrPort, ok := tcpAddrPort(conn.LocalAddr()); ok {
		tr.SourceAddr = transcript.NewSourceAddress(addrPort.Addr())
	}

	reader := bufio.NewReader(conn)

	defer func() {
		quit(tr, res, conn, reader)
	}()

	dialEventIdx := 0

	reply, ok := recvReply(tr, res, reader, transcript.PhaseBanner)
	if !ok {
		return res
	}
	recordDuration(tr, res, transcript.PhaseBanner, tr.Events[len(tr.Events)-1], dialEventIdx)
	if !reply.IsPositive() {
		res.Outcome = mustOutcome(transcript.PhaseBanner, *reply)
		return res
	}

	ehloIdx := len(tr.Events)
	reply, ok = ehlo(tr, res, conn, reader, cfg.Triple.HeloIdentity)
	if !ok {
		return res
	}
	recordDuration(tr, res, transcript.PhaseEHLO, tr.Events[len(tr.Events)-1], ehloIdx)
	if !reply.IsPositive() {
		res.Outcome = mustOutcome(transcript.PhaseEHLO, *reply)
		return res
	}
	res.Extensions = transcript.ParseExtensions(reply.Lines)
	if len(res.Extensions) > 0 {
		names := make([]string, len(res.Extensions))
		for i, e := range res.Extensions {
			names[i] = e.Raw
		}
		tr.Append(transcript.KindNote, transcript.PhaseEHLO, nil).Note =
			"advertised extensions: " + strings.Join(names, ", ")
	}

	switch {
	case cfg.TLSMode == TLSNone:
		tr.Append(transcript.KindNote, transcript.PhaseSTARTTLS, nil).Note =
			"tls mode none, starttls not offered"

	case advertisesSTARTTLS(res.Extensions):
		var upgraded bool
		conn, reader, upgraded = startTLS(tr, res, conn, reader, cfg)
		if !upgraded {
			return res
		}
		// The extension list from the plaintext EHLO cannot be trusted after an
		// upgrade, and RFC 3207 requires the client re-issue EHLO.
		ehloIdx = len(tr.Events)
		reply, ok = ehlo(tr, res, conn, reader, cfg.Triple.HeloIdentity)
		if !ok {
			return res
		}
		recordDuration(tr, res, transcript.PhaseEHLO, tr.Events[len(tr.Events)-1], ehloIdx)
		if !reply.IsPositive() {
			res.Outcome = mustOutcome(transcript.PhaseEHLO, *reply)
			return res
		}
		res.Extensions = transcript.ParseExtensions(reply.Lines)

	case cfg.TLSMode == TLSRequire:
		tr.Append(transcript.KindError, transcript.PhaseSTARTTLS, nil).Note =
			"starttls required but not advertised"
		res.Err = fmt.Errorf("smtpconv: starttls required but the target does not advertise it")
		return res

	default:
		tr.Append(transcript.KindNote, transcript.PhaseSTARTTLS, nil).Note =
			"starttls not advertised, continuing in plaintext"
	}

	if cfg.Credentials.isSet() {
		if !authenticate(tr, res, conn, reader, cfg.Credentials,
			authMechanisms(res.Extensions), tr.TLS != nil) {
			return res
		}
	}

	mailFromIdx := len(tr.Events)
	reply, ok = verb(tr, res, conn, reader, transcript.PhaseMailFrom,
		"MAIL FROM:"+cfg.Triple.EnvelopeSender.mailFromArg())
	if !ok {
		return res
	}
	recordDuration(tr, res, transcript.PhaseMailFrom, tr.Events[len(tr.Events)-1], mailFromIdx)
	if !reply.IsPositive() {
		res.Outcome = mustOutcome(transcript.PhaseMailFrom, *reply)
		return res
	}

	rcptToIdx := len(tr.Events)
	reply, ok = verb(tr, res, conn, reader, transcript.PhaseRcptTo,
		"RCPT TO:<"+string(cfg.Recipient)+">")
	if !ok {
		return res
	}
	recordDuration(tr, res, transcript.PhaseRcptTo, tr.Events[len(tr.Events)-1], rcptToIdx)
	if !reply.IsPositive() {
		res.Outcome = mustOutcome(transcript.PhaseRcptTo, *reply)
		return res
	}

	if cfg.DryRun {
		return res
	}

	dataIdx := len(tr.Events)
	reply, ok = verb(tr, res, conn, reader, transcript.PhaseData, "DATA")
	if !ok {
		return res
	}
	recordDuration(tr, res, transcript.PhaseData, tr.Events[len(tr.Events)-1], dataIdx)
	if reply.Code != 354 {
		res.Outcome = mustOutcome(transcript.PhaseData, *reply)
		return res
	}

	msg, err := NewProbeMessage(cfg.Triple.HeaderFrom, string(cfg.Recipient), now())
	if err != nil {
		res.Err = fmt.Errorf("smtpconv: build probe message: %w", err)
		return res
	}
	body := DotStuff(msg.Render())

	endOfDataIdx := len(tr.Events)
	tr.Append(transcript.KindSend, transcript.PhaseEndOfData, body)
	if _, err := conn.Write(body); err != nil {
		ev := tr.Append(transcript.KindError, transcript.PhaseEndOfData, []byte(err.Error()))
		recordDuration(tr, res, transcript.PhaseEndOfData, ev, endOfDataIdx)
		res.Err = fmt.Errorf("smtpconv: write message: %w", err)
		return res
	}
	reply, ok = recvReply(tr, res, reader, transcript.PhaseEndOfData)
	if !ok {
		return res
	}
	recordDuration(tr, res, transcript.PhaseEndOfData, tr.Events[len(tr.Events)-1], endOfDataIdx)
	res.Outcome = mustOutcome(transcript.PhaseEndOfData, *reply)

	return res
}

// verb sends one command line at phase and reads the reply.
func verb(tr *transcript.Transcript, res *Result, conn net.Conn, reader *bufio.Reader,
	phase transcript.Phase, line string) (*transcript.Reply, bool) {
	raw := []byte(line + "\r\n")
	tr.Append(transcript.KindSend, phase, raw)
	if _, err := conn.Write(raw); err != nil {
		ev := tr.Append(transcript.KindError, phase, []byte(err.Error()))
		recordDuration(tr, res, phase, ev, len(tr.Events)-2)
		res.Err = fmt.Errorf("smtpconv: write %s: %w", phase, err)
		return nil, false
	}
	return recvReply(tr, res, reader, phase)
}

// ehlo sends EHLO and, if refused, records the fallback and sends HELO,
// both attempts attributed to transcript.PhaseEHLO.
func ehlo(tr *transcript.Transcript, res *Result, conn net.Conn, reader *bufio.Reader,
	helo string) (*transcript.Reply, bool) {
	reply, ok := verb(tr, res, conn, reader, transcript.PhaseEHLO, "EHLO "+helo)
	if !ok {
		return nil, false
	}
	if reply.IsPositive() {
		return reply, true
	}
	tr.Append(transcript.KindNote, transcript.PhaseEHLO, nil).Note =
		"ehlo refused, falling back to helo"
	return verb(tr, res, conn, reader, transcript.PhaseEHLO, "HELO "+helo)
}

// recvReply reads one (possibly multiline) reply, records it, and parses it.
// ok is false when the read or the parse failed, in which case res.Err is
// already set and the caller should return immediately.
func recvReply(tr *transcript.Transcript, res *Result, reader *bufio.Reader,
	phase transcript.Phase) (*transcript.Reply, bool) {
	raw, err := readReplyBytes(reader)
	if err != nil {
		ev := tr.Append(transcript.KindError, phase, []byte(err.Error()))
		recordDuration(tr, res, phase, ev, len(tr.Events)-2)
		res.Err = fmt.Errorf("smtpconv: read %s reply: %w", phase, err)
		return nil, false
	}
	ev := tr.Append(transcript.KindRecv, phase, raw)
	reply, err := transcript.ParseReply(raw)
	if err != nil {
		res.Err = fmt.Errorf("smtpconv: parse %s reply: %w", phase, err)
		return nil, false
	}
	ev.Reply = reply
	return reply, true
}

// readReplyBytes reads the raw bytes of one reply, following "code-text\r\n"
// continuations to the final "code text\r\n" line.
func readReplyBytes(reader *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return buf, err
		}
		buf = append(buf, line...)
		trimmed := strings.TrimRight(line, "\r\n")
		if len(trimmed) < 4 || trimmed[3] != '-' {
			return buf, nil
		}
	}
}

// quit sends QUIT and reads the reply on a best-effort basis: a connection
// already dropped by the server must not stop QUIT from being attempted, and
// must not panic the deferred call that runs it.
func quit(tr *transcript.Transcript, res *Result, conn net.Conn, reader *bufio.Reader) {
	startIdx := len(tr.Events)
	raw := []byte("QUIT\r\n")
	tr.Append(transcript.KindSend, transcript.PhaseQuit, raw)
	if _, err := conn.Write(raw); err != nil {
		ev := tr.Append(transcript.KindError, transcript.PhaseQuit, []byte(err.Error()))
		recordDuration(tr, res, transcript.PhaseQuit, ev, startIdx)
		return
	}
	replyRaw, err := readReplyBytes(reader)
	if err != nil {
		ev := tr.Append(transcript.KindError, transcript.PhaseQuit, []byte(err.Error()))
		recordDuration(tr, res, transcript.PhaseQuit, ev, startIdx)
		return
	}
	ev := tr.Append(transcript.KindRecv, transcript.PhaseQuit, replyRaw)
	if reply, err := transcript.ParseReply(replyRaw); err == nil {
		ev.Reply = reply
	}
	recordDuration(tr, res, transcript.PhaseQuit, ev, startIdx)
}

// recordDuration records how long the Phase whose first event is at
// tr.Events[startIdx] took to reach lastEvent, using the Monotonic field
// transcript.Append already stamped on both. Durations accumulate per Phase
// because EHLO's fallback to HELO makes two round trips within one Phase.
func recordDuration(tr *transcript.Transcript, res *Result, phase transcript.Phase,
	lastEvent *transcript.Event, startIdx int) {
	if startIdx < 0 || startIdx >= len(tr.Events) {
		return
	}
	dur := lastEvent.Monotonic - tr.Events[startIdx].Monotonic
	res.Durations[phase] += dur
}

func mustOutcome(phase transcript.Phase, reply transcript.Reply) *Outcome {
	o, err := NewOutcome(phase, reply)
	if err != nil {
		return nil
	}
	return &o
}

func tcpAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := tcpAddr.AddrPort()
	if !ap.IsValid() {
		return netip.AddrPort{}, false
	}
	return ap, true
}
