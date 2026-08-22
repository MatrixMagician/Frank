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
	"time"
)

// TB is the part of *testing.T this package needs, declared here so the
// package does not import testing outside its own tests.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Cleanup(func())
}

// Received is one message the server accepted, kept so a test can assert what
// actually crossed the wire rather than what the client believes it sent.
type Received struct {
	Triple  Triple
	Data    string
	Auth    []Credential
	TLS     bool
	Ordinal int
}

// Credential is an AUTH exchange the server saw. Recording it is what lets a
// test prove the credential never reached a rendered Transcript.
type Credential struct {
	Mechanism string
	Username  string
	Password  string
}

// Server is the in-process SMTP test double.
type Server struct {
	ln       net.Listener
	cfg      *config
	rules    *table
	tlsCert  tls.Certificate
	leafCert *x509.Certificate

	mu       sync.Mutex
	connOrd  int
	received []Received
	creds    []Credential

	wg     sync.WaitGroup
	closed chan struct{}
}

// Start listens on an ephemeral loopback port and serves until the test ends.
func Start(t TB, opts ...Option) *Server {
	t.Helper()

	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("smtptest: listen: %v", err)
	}

	s := &Server{
		ln:     ln,
		cfg:    cfg,
		rules:  &table{rules: cfg.rules},
		closed: make(chan struct{}),
	}

	if cfg.startTLS {
		cert, leaf, err := generateCert()
		if err != nil {
			t.Fatalf("smtptest: %v", err)
		}
		s.tlsCert, s.leafCert = cert, leaf
	}

	s.wg.Add(1)
	go s.acceptLoop()
	t.Cleanup(s.Close)

	return s
}

// Addr is the host:port to dial.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Certificate is the leaf the server presents, so a test can seed a pool that
// trusts it and verify the same chain both ways, per ADR-0004.
func (s *Server) Certificate() *x509.Certificate { return s.leafCert }

// ConnectionCount is how many connections have been accepted. The matrix
// runner's fresh-connection-per-Cell guarantee is asserted against this.
func (s *Server) ConnectionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connOrd
}

// Received returns the messages accepted so far.
func (s *Server) Received() []Received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Received(nil), s.received...)
}

// Credentials returns the AUTH exchanges the server saw.
func (s *Server) Credentials() []Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Credential(nil), s.creds...)
}

// Close stops the server. It is registered with t.Cleanup by Start and is safe
// to call more than once.
func (s *Server) Close() {
	select {
	case <-s.closed:
		return
	default:
	}
	close(s.closed)
	s.ln.Close()
	s.wg.Wait()
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.connOrd++
		ordinal := s.connOrd
		s.mu.Unlock()

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			s.serve(conn, ordinal)
		}()
	}
}

// session is one connection's state, which is the whole point of holding it
// per connection: a reused connection would let one Cell's Outcome depend on
// the Cell before it.
type session struct {
	ordinal  int
	tls      bool
	triple   Triple
	refusals int
	creds    []Credential
	greeted  bool
}

func (s *Server) serve(conn net.Conn, ordinal int) {
	sess := &session{ordinal: ordinal}
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	if !s.replyAt(rw, sess, PhaseBanner, "", Reply{Code: 220, Text: "frank.test ESMTP test double"}) {
		return
	}

	for {
		line, err := rw.Reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb, arg := splitCommand(line)

		switch verb {
		case "EHLO":
			if s.cfg.refuseEHLO {
				if !s.replyAt(rw, sess, PhaseEHLO, arg, Reply{Code: 502, Enhanced: "5.5.1", Text: "command not implemented, use HELO"}) {
					return
				}
				continue
			}
			sess.triple.HeloIdentity = arg
			sess.greeted = true
			if r, ok := s.rules.match(PhaseEHLO, s.state(sess, arg)); ok && r.Reply.Code != 0 {
				if !s.emit(rw, sess, r) {
					return
				}
				continue
			}
			if err := s.writeEHLO(rw, sess); err != nil {
				return
			}

		case "HELO":
			sess.triple.HeloIdentity = arg
			sess.greeted = true
			if !s.replyAt(rw, sess, PhaseEHLO, arg, Reply{Code: 250, Text: "frank.test"}) {
				return
			}

		case "STARTTLS":
			if !s.cfg.startTLS {
				if !s.replyAt(rw, sess, PhaseSTARTTLS, "", Reply{Code: 454, Enhanced: "4.7.0", Text: "TLS not available"}) {
					return
				}
				continue
			}
			if r, ok := s.rules.match(PhaseSTARTTLS, s.state(sess, "")); ok && r.Reply.Code != 0 {
				if !s.emit(rw, sess, r) {
					return
				}
				continue
			}
			if err := s.write(rw, Reply{Code: 220, Enhanced: "2.0.0", Text: "ready to start TLS"}); err != nil {
				return
			}
			tconn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.tlsCert}})
			if err := tconn.Handshake(); err != nil {
				return
			}
			conn = tconn
			rw = bufio.NewReadWriter(bufio.NewReader(tconn), bufio.NewWriter(tconn))
			sess.tls = true
			sess.greeted = false
			sess.triple = Triple{}

		case "AUTH":
			if !s.handleAuth(rw, sess, arg) {
				return
			}

		case "MAIL":
			addr := extractAddress(arg)
			sess.triple.EnvelopeSender = addr
			if !s.replyAt(rw, sess, PhaseMailFrom, addr, Reply{Code: 250, Enhanced: "2.1.0", Text: "sender ok"}) {
				return
			}

		case "RCPT":
			addr := extractAddress(arg)
			if !s.replyAt(rw, sess, PhaseRcptTo, addr, Reply{Code: 250, Enhanced: "2.1.5", Text: "recipient ok"}) {
				return
			}

		case "DATA":
			if r, ok := s.rules.match(PhaseData, s.state(sess, "")); ok && r.Reply.Code != 0 {
				if !s.emit(rw, sess, r) {
					return
				}
				continue
			}
			if err := s.write(rw, Reply{Code: 354, Text: "end with <CRLF>.<CRLF>"}); err != nil {
				return
			}
			body, err := readDATA(rw)
			if err != nil {
				return
			}
			sess.triple.HeaderFrom = extractAddress(headerValue(body, "From"))
			if !s.replyAt(rw, sess, PhaseEndOfData, "", Reply{Code: 250, Enhanced: "2.0.0", Text: "message accepted"}) {
				return
			}
			s.recordReceived(sess, body)

		case "RSET":
			sess.triple = Triple{}
			if err := s.write(rw, Reply{Code: 250, Enhanced: "2.0.0", Text: "reset"}); err != nil {
				return
			}

		case "NOOP":
			if err := s.write(rw, Reply{Code: 250, Enhanced: "2.0.0", Text: "ok"}); err != nil {
				return
			}

		case "QUIT":
			s.replyAt(rw, sess, PhaseQuit, "", Reply{Code: 221, Enhanced: "2.0.0", Text: "closing connection"})
			return

		default:
			if err := s.write(rw, Reply{Code: 500, Enhanced: "5.5.2", Text: "command not recognised"}); err != nil {
				return
			}
		}
	}
}

func (s *Server) state(sess *session, arg string) State {
	return State{
		Ordinal:  sess.ordinal,
		TLS:      sess.tls,
		Arg:      arg,
		Triple:   sess.triple,
		Refusals: sess.refusals,
	}
}

// replyAt consults the rule table for this Phase and falls back to def when no
// rule matches.
func (s *Server) replyAt(rw *bufio.ReadWriter, sess *session, p Phase, arg string, def Reply) bool {
	if r, ok := s.rules.match(p, s.state(sess, arg)); ok {
		if r.Delay > 0 {
			time.Sleep(r.Delay)
		}
		if r.Close {
			return false
		}
		if r.Reply.Code != 0 {
			return s.emitReply(rw, sess, r.Reply)
		}
	}
	return s.emitReply(rw, sess, def)
}

func (s *Server) emit(rw *bufio.ReadWriter, sess *session, r Rule) bool {
	if r.Delay > 0 {
		time.Sleep(r.Delay)
	}
	if r.Close {
		return false
	}
	return s.emitReply(rw, sess, r.Reply)
}

func (s *Server) emitReply(rw *bufio.ReadWriter, sess *session, r Reply) bool {
	if r.Code >= 400 {
		sess.refusals++
	}
	return s.write(rw, r) == nil
}

func (s *Server) write(rw *bufio.ReadWriter, r Reply) error {
	if _, err := rw.Writer.WriteString(r.line(' ')); err != nil {
		return err
	}
	return rw.Writer.Flush()
}

func (s *Server) writeEHLO(rw *bufio.ReadWriter, sess *session) error {
	exts := s.effectiveExtensions(sess)
	lines := append([]string{"frank.test greets you"}, exts...)
	for i, l := range lines {
		sep := byte('-')
		if i == len(lines)-1 {
			sep = ' '
		}
		if _, err := fmt.Fprintf(rw.Writer, "250%c%s\r\n", sep, l); err != nil {
			return err
		}
	}
	return rw.Writer.Flush()
}

// effectiveExtensions drops STARTTLS once the connection is already encrypted
// and, under WithAuthOverTLSOnly, hides AUTH until it is.
func (s *Server) effectiveExtensions(sess *session) []string {
	var out []string
	for _, e := range s.cfg.extensions {
		upper := strings.ToUpper(e)
		if strings.HasPrefix(upper, "STARTTLS") && sess.tls {
			continue
		}
		if strings.HasPrefix(upper, "AUTH") && s.cfg.authOverTLSOnly && !sess.tls {
			continue
		}
		out = append(out, e)
	}
	if s.cfg.startTLS && !sess.tls && !containsPrefix(out, "STARTTLS") {
		out = append(out, "STARTTLS")
	}
	return out
}

func containsPrefix(list []string, prefix string) bool {
	for _, e := range list {
		if strings.HasPrefix(strings.ToUpper(e), prefix) {
			return true
		}
	}
	return false
}

func (s *Server) recordReceived(sess *session, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.received = append(s.received, Received{
		Triple:  sess.triple,
		Data:    body,
		Auth:    append([]Credential(nil), sess.creds...),
		TLS:     sess.tls,
		Ordinal: sess.ordinal,
	})
}

func splitCommand(line string) (verb, arg string) {
	verb, arg, _ = strings.Cut(line, " ")
	return strings.ToUpper(strings.TrimSpace(verb)), strings.TrimSpace(arg)
}

// extractAddress pulls the address out of "FROM:<a@b>" or "<a@b>" or "a@b".
// A null sender "<>" yields the empty string, which is a first-class value.
func extractAddress(arg string) string {
	if _, rest, ok := strings.Cut(arg, ":"); ok {
		arg = rest
	}
	arg = strings.TrimSpace(arg)
	if i := strings.Index(arg, "<"); i >= 0 {
		if j := strings.Index(arg[i:], ">"); j >= 0 {
			return arg[i+1 : i+j]
		}
	}
	if f := strings.Fields(arg); len(f) > 0 {
		return f[0]
	}
	return ""
}

func headerValue(body, name string) string {
	for _, line := range strings.Split(body, "\r\n") {
		if line == "" {
			return ""
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// readDATA reads to the terminating <CRLF>.<CRLF> and undoes dot-stuffing, so
// the recorded body is what the client meant to send rather than what the
// transport required.
func readDATA(rw *bufio.ReadWriter) (string, error) {
	var b strings.Builder
	for {
		line, err := rw.Reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "." {
			return b.String(), nil
		}
		if strings.HasPrefix(trimmed, ".") {
			trimmed = trimmed[1:]
		}
		b.WriteString(trimmed)
		b.WriteString("\r\n")
	}
}

func (s *Server) handleAuth(rw *bufio.ReadWriter, sess *session, arg string) bool {
	mech, initial := splitCommand(arg)

	if r, ok := s.rules.match(PhaseAuth, s.state(sess, mech)); ok && r.Reply.Code != 0 {
		return s.emit(rw, sess, r)
	}

	var cred Credential
	switch mech {
	case "PLAIN":
		payload := initial
		if payload == "" {
			if err := s.write(rw, Reply{Code: 334, Text: ""}); err != nil {
				return false
			}
			line, err := rw.Reader.ReadString('\n')
			if err != nil {
				return false
			}
			payload = strings.TrimRight(line, "\r\n")
		}
		raw, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return s.emitReply(rw, sess, Reply{Code: 501, Enhanced: "5.5.2", Text: "cannot decode AUTH PLAIN"})
		}
		parts := strings.Split(string(raw), "\x00")
		cred.Mechanism = "PLAIN"
		if len(parts) == 3 {
			cred.Username, cred.Password = parts[1], parts[2]
		}

	case "LOGIN":
		if err := s.write(rw, Reply{Code: 334, Text: base64.StdEncoding.EncodeToString([]byte("Username:"))}); err != nil {
			return false
		}
		userLine, err := rw.Reader.ReadString('\n')
		if err != nil {
			return false
		}
		user, _ := base64.StdEncoding.DecodeString(strings.TrimRight(userLine, "\r\n"))
		if err := s.write(rw, Reply{Code: 334, Text: base64.StdEncoding.EncodeToString([]byte("Password:"))}); err != nil {
			return false
		}
		passLine, err := rw.Reader.ReadString('\n')
		if err != nil {
			return false
		}
		pass, _ := base64.StdEncoding.DecodeString(strings.TrimRight(passLine, "\r\n"))
		cred.Mechanism, cred.Username, cred.Password = "LOGIN", string(user), string(pass)

	default:
		return s.emitReply(rw, sess, Reply{Code: 504, Enhanced: "5.5.4", Text: "unrecognised authentication mechanism"})
	}

	sess.creds = append(sess.creds, cred)
	s.mu.Lock()
	s.creds = append(s.creds, cred)
	s.mu.Unlock()

	return s.emitReply(rw, sess, Reply{Code: 235, Enhanced: "2.7.0", Text: "authentication succeeded"})
}
