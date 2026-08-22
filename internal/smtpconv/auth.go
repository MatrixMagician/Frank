package smtpconv

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/MatrixMagician/Frank/internal/transcript"
)

// Credentials are the SMTP AUTH username and password. Per ADR-0007 they come
// from the environment or the config file and never from a command-line
// argument, because argv is world-readable through /proc on the Linux hosts
// Frank targets and lands verbatim in shell history.
type Credentials struct {
	Username string
	Password string
}

// Env names the environment variables credentials are read from.
const (
	EnvUsername = "FRANK_SMTP_USERNAME"
	EnvPassword = "FRANK_SMTP_PASSWORD"
)

// CredentialsFromEnv reads credentials from the environment. ok is false when
// neither variable is set, which is not an error: most Probes do not
// authenticate.
func CredentialsFromEnv() (Credentials, bool) {
	u, p := os.Getenv(EnvUsername), os.Getenv(EnvPassword)
	if u == "" && p == "" {
		return Credentials{}, false
	}
	return Credentials{Username: u, Password: p}, true
}

func (c Credentials) isSet() bool { return c.Username != "" || c.Password != "" }

// ErrAuthWithoutTLS is returned when AUTH is requested over a connection that
// is not TLS-protected. Frank refuses whatever --tls says, per ADR-0007: a host
// offering AUTH only in the clear has a worse problem than the one Frank was
// called in to diagnose.
var ErrAuthWithoutTLS = fmt.Errorf("smtpconv: refusing to authenticate over a connection that is not tls-protected")

// authenticate runs AUTH at PhaseAuth. The mechanism is chosen from what the
// server advertised, preferring PLAIN.
func authenticate(tr *transcript.Transcript, res *Result, conn net.Conn, reader *bufio.Reader,
	creds Credentials, advertised []string, overTLS bool) bool {

	if !overTLS {
		tr.Append(transcript.KindError, transcript.PhaseAuth, nil).Note =
			"refused to authenticate: the connection is not tls-protected"
		res.Err = ErrAuthWithoutTLS
		return false
	}

	tr.Append(transcript.KindNote, transcript.PhaseAuth, nil).Note =
		"advertised auth mechanisms: " + mechanismList(advertised)

	mech, ok := chooseMechanism(advertised)
	if !ok {
		tr.Append(transcript.KindError, transcript.PhaseAuth, nil).Note =
			"no supported auth mechanism: frank supports plain and login, the target advertised " + mechanismList(advertised)
		res.Err = fmt.Errorf("smtpconv: no supported auth mechanism, target advertised %s", mechanismList(advertised))
		return false
	}

	authIdx := len(tr.Events)
	var reply *transcript.Reply

	switch mech {
	case "PLAIN":
		payload := base64.StdEncoding.EncodeToString(
			[]byte("\x00" + creds.Username + "\x00" + creds.Password))
		reply, ok = verb(tr, res, conn, reader, transcript.PhaseAuth, "AUTH PLAIN "+payload)
		if !ok {
			return false
		}

	case "LOGIN":
		reply, ok = verb(tr, res, conn, reader, transcript.PhaseAuth, "AUTH LOGIN")
		if !ok {
			return false
		}
		if reply.Code != 334 {
			res.Outcome = mustOutcome(transcript.PhaseAuth, *reply)
			return false
		}
		reply, ok = verb(tr, res, conn, reader, transcript.PhaseAuth,
			base64.StdEncoding.EncodeToString([]byte(creds.Username)))
		if !ok {
			return false
		}
		if reply.Code != 334 {
			res.Outcome = mustOutcome(transcript.PhaseAuth, *reply)
			return false
		}
		reply, ok = verb(tr, res, conn, reader, transcript.PhaseAuth,
			base64.StdEncoding.EncodeToString([]byte(creds.Password)))
		if !ok {
			return false
		}
	}

	recordDuration(tr, res, transcript.PhaseAuth, tr.Events[len(tr.Events)-1], authIdx)

	if !reply.IsPositive() {
		res.Outcome = mustOutcome(transcript.PhaseAuth, *reply)
		return false
	}
	tr.Append(transcript.KindNote, transcript.PhaseAuth, nil).Note =
		"authenticated with " + mech
	return true
}

// chooseMechanism picks the strongest mechanism Frank implements from what the
// server advertised.
func chooseMechanism(advertised []string) (string, bool) {
	for _, want := range []string{"PLAIN", "LOGIN"} {
		for _, got := range advertised {
			if strings.EqualFold(want, got) {
				return want, true
			}
		}
	}
	return "", false
}

func mechanismList(mechs []string) string {
	if len(mechs) == 0 {
		return "none"
	}
	return strings.Join(mechs, ", ")
}

// authMechanisms reads the mechanism list off the advertised AUTH extension.
func authMechanisms(exts []transcript.Extension) []string {
	for _, e := range exts {
		if strings.EqualFold(e.Name, "AUTH") {
			return e.Params
		}
	}
	return nil
}

// RegisterCredentials masks a credential in every rendering unconditionally,
// regardless of any --redact pattern. ADR-0007 makes the redaction hook
// load-bearing here: the in-memory Transcript stays lossless and does carry the
// AUTH exchange, and what must never carry it is either artefact that reaches
// disk.
func RegisterCredentials(r *transcript.Redactor, creds Credentials) {
	if r == nil || !creds.isSet() {
		return
	}
	r.AddLiteral(creds.Password)
	r.AddLiteral(base64.StdEncoding.EncodeToString([]byte(creds.Password)))
	r.AddLiteral(base64.StdEncoding.EncodeToString(
		[]byte("\x00" + creds.Username + "\x00" + creds.Password)))
}
