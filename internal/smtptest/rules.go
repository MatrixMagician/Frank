package smtptest

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Phase is where in the conversation a rule applies. It mirrors the glossary's
// Phases, including the split between Data and EndOfData: a refusal of the
// DATA verb is policy on the envelope, a refusal of the terminating dot is
// policy on the message.
type Phase int

const (
	PhaseBanner Phase = iota
	PhaseEHLO
	PhaseSTARTTLS
	PhaseAuth
	PhaseMailFrom
	PhaseRcptTo
	PhaseData
	PhaseEndOfData
	PhaseQuit
)

var phaseNames = [...]string{
	"banner", "ehlo", "starttls", "auth",
	"mail-from", "rcpt-to", "data", "end-of-data", "quit",
}

func (p Phase) String() string {
	if int(p) < 0 || int(p) >= len(phaseNames) {
		return "unknown"
	}
	return phaseNames[p]
}

// Reply is what a rule makes the server say. Enhanced is optional; an empty
// string omits the enhanced status code entirely, which is how a server that
// does not advertise ENHANCEDSTATUSCODES behaves.
type Reply struct {
	Code     int
	Enhanced string
	Text     string
}

func (r Reply) line(sep byte) string {
	if r.Enhanced == "" {
		return fmt.Sprintf("%d%c%s\r\n", r.Code, sep, r.Text)
	}
	return fmt.Sprintf("%d%c%s %s\r\n", r.Code, sep, r.Enhanced, r.Text)
}

// State is what a rule can see when it decides. Everything here is an
// observation the server has already made on this connection, which is what
// lets one rule table express identity matching, greylisting by connection
// ordinal, and policy that tightens after a refusal.
type State struct {
	// Ordinal is 1 for the first connection to this server, 2 for the second.
	// Greylisting is a rule that matches on Ordinal == 1.
	Ordinal int
	// TLS reports whether this connection has completed a STARTTLS upgrade.
	TLS bool
	// Arg is the argument seen at this Phase: the address in MAIL FROM or
	// RCPT TO, the name in EHLO, the mechanism in AUTH. Empty where the verb
	// takes no argument.
	Arg string
	// Triple is what the connection has revealed of the Identity Triple so
	// far. HeaderFrom is only populated once the DATA payload has been read,
	// so a rule matching on it belongs at PhaseEndOfData.
	Triple ObservedTriple
	// Refusals counts how many rules have already refused on THIS connection.
	// A rule matching on Refusals > 0 is per-connection state tightening,
	// which is what ADR-0003's fresh-connection decision exists to avoid.
	Refusals int
}

// ObservedTriple is as much of the Identity Triple as the server has observed so far.
type ObservedTriple struct {
	EnvelopeSender string
	HeloIdentity   string
	HeaderFrom     string
}

// Rule is one entry in the ordered table the server consults at each Phase.
// The first rule whose Phase matches and whose When returns true decides the
// reply. A nil When always matches.
type Rule struct {
	Phase Phase
	When  func(State) bool
	Reply Reply
	// Delay holds the reply back, so a Probe's per-Phase timing has something
	// to measure and a fixed-duration stall is reproducible.
	Delay time.Duration
	// Close drops the connection instead of replying, for testing the error
	// paths a Probe must still QUIT cleanly from.
	Close bool
}

// Option configures a Server at Start.
type Option func(*config)

type config struct {
	extensions      []string
	startTLS        bool
	authOverTLSOnly bool
	refuseEHLO      bool
	rules           []Rule
}

// WithExtensions sets the extension lines the EHLO reply advertises, each
// written as it should appear on the wire ("SIZE 10240000", "AUTH PLAIN LOGIN").
func WithExtensions(exts ...string) Option {
	return func(c *config) { c.extensions = append(c.extensions, exts...) }
}

// WithSTARTTLS advertises STARTTLS and honours the verb. Without it the server
// neither advertises nor accepts STARTTLS.
func WithSTARTTLS() Option {
	return func(c *config) { c.startTLS = true }
}

// WithAuthOverTLSOnly advertises AUTH only once the connection is encrypted,
// which is the posture ADR-0007 describes and the one Frank refuses to
// authenticate without.
func WithAuthOverTLSOnly() Option {
	return func(c *config) { c.authOverTLSOnly = true }
}

// RefuseEHLO makes the server reject EHLO, forcing a client to fall back to
// HELO.
func RefuseEHLO() Option {
	return func(c *config) { c.refuseEHLO = true }
}

// WithRule appends a rule to the table. Rules are consulted in the order they
// were added, and the first match wins.
func WithRule(r Rule) Option {
	return func(c *config) { c.rules = append(c.rules, r) }
}

// Reject refuses at a Phase with a permanent code.
func Reject(p Phase, code int, enhanced, text string) Option {
	return WithRule(Rule{Phase: p, Reply: Reply{Code: code, Enhanced: enhanced, Text: text}})
}

// RejectTriple refuses at a Phase only for one Identity Triple, accepting
// every other. An empty field in want means "any value".
func RejectTriple(p Phase, want ObservedTriple, code int, enhanced, text string) Option {
	return WithRule(Rule{
		Phase: p,
		When:  func(s State) bool { return tripleMatches(want, s.Triple) },
		Reply: Reply{Code: code, Enhanced: enhanced, Text: text},
	})
}

// Greylist defers every connection up to and including nth, then accepts.
// Emitting a Deferral first and an Acceptance later is what makes greylisting
// testable, and a Deferral proves nothing about the Identity Triple that met it.
func Greylist(p Phase, nth int, code int, enhanced, text string) Option {
	return WithRule(Rule{
		Phase: p,
		When:  func(s State) bool { return s.Ordinal <= nth },
		Reply: Reply{Code: code, Enhanced: enhanced, Text: text},
	})
}

// TightenAfterRefusal refuses once any earlier refusal has happened on the
// same connection. It exists to demonstrate the per-connection state ADR-0003
// cites as the reason a Cell gets a fresh connection.
func TightenAfterRefusal(p Phase, code int, enhanced, text string) Option {
	return WithRule(Rule{
		Phase: p,
		When:  func(s State) bool { return s.Refusals > 0 },
		Reply: Reply{Code: code, Enhanced: enhanced, Text: text},
	})
}

// Delay holds every reply at a Phase back by d.
func Delay(p Phase, d time.Duration) Option {
	return WithRule(Rule{Phase: p, Delay: d, Reply: Reply{Code: 0}})
}

func tripleMatches(want, got ObservedTriple) bool {
	if want.EnvelopeSender != "" && !strings.EqualFold(want.EnvelopeSender, got.EnvelopeSender) {
		return false
	}
	if want.HeloIdentity != "" && !strings.EqualFold(want.HeloIdentity, got.HeloIdentity) {
		return false
	}
	if want.HeaderFrom != "" && !strings.EqualFold(want.HeaderFrom, got.HeaderFrom) {
		return false
	}
	return want != ObservedTriple{}
}

// table is the ordered rule set, consulted at each Phase.
type table struct {
	mu    sync.Mutex
	rules []Rule
}

// match returns the first rule whose Phase and predicate accept this state.
func (t *table) match(p Phase, s State) (Rule, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, r := range t.rules {
		if r.Phase != p {
			continue
		}
		if r.When != nil && !r.When(s) {
			continue
		}
		return r, true
	}
	return Rule{}, false
}
