package matrix

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MatrixMagician/Frank/internal/smtpconv"
	"github.com/MatrixMagician/Frank/internal/transcript"
)

// Resolution is what a Cell resolved to. The four are distinct on purpose:
// neither Inconclusive nor Unrun is ever reported as a rejected Triple, and
// the two render distinctly because one was asked and would not answer while
// the other was never asked.
type Resolution int

const (
	// Unrun means the sweep aborted before reaching this Cell. It is not
	// evidence of anything.
	Unrun Resolution = iota
	// Accepted means some Probe for this Triple reached Acceptance.
	Accepted
	// Rejected means a Probe met a Rejection and none reached Acceptance.
	Rejected
	// Inconclusive means only Deferrals were seen. A greylisting host must not
	// read as a policy rejection.
	Inconclusive
)

var resolutionNames = [...]string{"unrun", "accepted", "rejected", "inconclusive"}

func (r Resolution) String() string {
	if int(r) < 0 || int(r) >= len(resolutionNames) {
		return "unknown"
	}
	return resolutionNames[r]
}

func (r Resolution) MarshalJSON() ([]byte, error) {
	if int(r) < 0 || int(r) >= len(resolutionNames) {
		return nil, fmt.Errorf("matrix: unknown resolution %d", int(r))
	}
	return json.Marshal(r.String())
}

// Symbol is the one-character mark used in the rendered grid, chosen so a
// reader can tell the four apart at a glance.
func (r Resolution) Symbol() string {
	switch r {
	case Accepted:
		return "."
	case Rejected:
		return "X"
	case Inconclusive:
		return "?"
	default:
		return "-"
	}
}

// Triple is one concrete filling of all three Identity Slots.
type Triple struct {
	EnvelopeSender string `json:"envelope_sender"`
	HeloIdentity   string `json:"helo_identity"`
	HeaderFrom     string `json:"header_from"`
}

func (t Triple) String() string {
	envelope := t.EnvelopeSender
	if envelope == "" {
		envelope = "<>"
	}
	return fmt.Sprintf("%s | %s | %s", envelope, t.HeloIdentity, t.HeaderFrom)
}

// ProbeRecord is one Probe run for a Cell: what was observed, and the
// Transcript that observed it.
type ProbeRecord struct {
	Outcome    *smtpconv.Outcome      `json:"-"`
	Transcript *transcript.Transcript `json:"-"`
	Err        error                  `json:"-"`

	Phase    string `json:"phase,omitempty"`
	Code     int    `json:"code,omitempty"`
	Enhanced string `json:"enhanced,omitempty"`
	Text     string `json:"text,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Cell holds every Probe run for its Triple. Resolution is computed from those
// Probes rather than stored, so it can never disagree with its own contents.
type Cell struct {
	Triple Triple        `json:"triple"`
	Probes []ProbeRecord `json:"probes"`
	// reached records whether the sweep got as far as this Cell, which is what
	// separates an Unrun Cell from one that was asked and answered nothing.
	reached bool
}

// Resolution derives the Cell's state from the Probes it holds: Accepted if
// any reached Acceptance, Rejected if one met a Rejection and none reached
// Acceptance, Inconclusive if only Deferrals were seen, Unrun if the sweep
// never reached it.
func (c *Cell) Resolution() Resolution {
	if !c.reached {
		return Unrun
	}
	var sawRejection, sawDeferral bool
	for _, p := range c.Probes {
		if p.Outcome == nil {
			continue
		}
		switch {
		case p.Outcome.IsAcceptance():
			return Accepted
		case p.Outcome.IsRejection():
			sawRejection = true
		case p.Outcome.IsDeferral():
			sawDeferral = true
		}
	}
	switch {
	case sawRejection:
		return Rejected
	case sawDeferral:
		return Inconclusive
	default:
		// Reached, but no Probe produced an Outcome at all: every attempt hit a
		// network or protocol fault. That is not evidence about the Triple.
		return Inconclusive
	}
}

// MarshalJSON renders the derived Resolution alongside the Cell's contents.
func (c *Cell) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Triple     Triple        `json:"triple"`
		Resolution Resolution    `json:"resolution"`
		Probes     []ProbeRecord `json:"probes"`
	}{c.Triple, c.Resolution(), c.Probes})
}

// Slots are the sets of values swept, one set per Identity Slot. The Recipient
// is not an Identity Slot and is never varied, so a Matrix result is always
// about the sending identities.
type Slots struct {
	EnvelopeSenders []string
	HeloIdentities  []string
	HeaderFroms     []string
}

// Triples is the Cartesian product, in a deterministic order so a rendered
// Matrix is reproducible.
func (s Slots) Triples() []Triple {
	var out []Triple
	for _, envelope := range s.EnvelopeSenders {
		for _, helo := range s.HeloIdentities {
			for _, header := range s.HeaderFroms {
				out = append(out, Triple{
					EnvelopeSender: envelope,
					HeloIdentity:   helo,
					HeaderFrom:     header,
				})
			}
		}
	}
	return out
}

func (s Slots) valid() error {
	if len(s.EnvelopeSenders) == 0 {
		return fmt.Errorf("matrix: no envelope senders to sweep")
	}
	if len(s.HeloIdentities) == 0 {
		return fmt.Errorf("matrix: no helo identities to sweep")
	}
	if len(s.HeaderFroms) == 0 {
		return fmt.Errorf("matrix: no header from addresses to sweep")
	}
	return nil
}

// Matrix is a completed or aborted sweep.
type Matrix struct {
	TargetHost string  `json:"target_host"`
	Recipient  string  `json:"recipient"`
	Slots      Slots   `json:"-"`
	Cells      []*Cell `json:"cells"`
	// Aborted names why the sweep stopped early, empty when it completed.
	Aborted string `json:"aborted,omitempty"`
}

// Counts tallies the Cells by Resolution.
func (m *Matrix) Counts() map[Resolution]int {
	out := map[Resolution]int{}
	for _, c := range m.Cells {
		out[c.Resolution()]++
	}
	return out
}

// Boundary describes where acceptance stops and rejection starts, which is what
// the sweep exists to find.
func (m *Matrix) Boundary() string {
	var accepted, rejected []Triple
	for _, c := range m.Cells {
		switch c.Resolution() {
		case Accepted:
			accepted = append(accepted, c.Triple)
		case Rejected:
			rejected = append(rejected, c.Triple)
		}
	}
	if len(rejected) == 0 {
		return "no Triple was rejected"
	}
	if len(accepted) == 0 {
		return "every Triple probed was rejected"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d of %d Triples were rejected", len(rejected), len(m.Cells))
	if slot, values := discriminatingSlot(m); slot != "" {
		fmt.Fprintf(&b, "; every rejection carried %s %s", slot, values)
	}
	return b.String()
}

// discriminatingSlot names the Identity Slot whose value is shared by every
// rejected Cell and by no accepted one, when there is exactly one such slot.
// That is the boundary in the form a reader can act on.
func discriminatingSlot(m *Matrix) (string, string) {
	slots := []struct {
		name  string
		value func(Triple) string
	}{
		{"envelope sender", func(t Triple) string { return t.EnvelopeSender }},
		{"helo identity", func(t Triple) string { return t.HeloIdentity }},
		{"header from", func(t Triple) string { return t.HeaderFrom }},
	}

	for _, slot := range slots {
		rejectedValues := map[string]bool{}
		acceptedValues := map[string]bool{}
		for _, c := range m.Cells {
			switch c.Resolution() {
			case Rejected:
				rejectedValues[slot.value(c.Triple)] = true
			case Accepted:
				acceptedValues[slot.value(c.Triple)] = true
			}
		}
		if len(rejectedValues) != 1 {
			continue
		}
		var only string
		for v := range rejectedValues {
			only = v
		}
		if acceptedValues[only] {
			continue
		}
		if only == "" {
			only = "<>"
		}
		return slot.name, only
	}
	return "", ""
}
