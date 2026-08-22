// Package dmarc fetches and parses a domain's DMARC policy record and
// computes identifier Alignment against a Header From domain, against the
// resolve.Resolver seam (issue #7), for issue #10.
package dmarc

import (
	"encoding/json"
	"fmt"

	"github.com/MatrixMagician/Frank/internal/spf"
)

// Disposition is the closed set of values the p= and sp= tags carry
// (RFC 7489 §6.3). It is never a bare string so a mistyped policy value is
// a compile error, not a silent no-op.
type Disposition int

const (
	// DispositionNone is the zero value, doubling as "no policy found" when
	// Result.Found is false and as the explicit p=none / sp=none value when
	// a record was found and parsed.
	DispositionNone Disposition = iota
	DispositionQuarantine
	DispositionReject
)

var dispositionNames = [...]string{"none", "quarantine", "reject"}

func (d Disposition) String() string {
	if int(d) < 0 || int(d) >= len(dispositionNames) {
		return "unknown"
	}
	return dispositionNames[d]
}

func (d Disposition) MarshalJSON() ([]byte, error) {
	if int(d) < 0 || int(d) >= len(dispositionNames) {
		return nil, fmt.Errorf("dmarc: unknown disposition %d", int(d))
	}
	return json.Marshal(d.String())
}

func (d *Disposition) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for i, name := range dispositionNames {
		if name == s {
			*d = Disposition(i)
			return nil
		}
	}
	return fmt.Errorf("dmarc: unknown disposition %q", s)
}

// Mode is the closed set of values the adkim= and aspf= tags carry: relaxed
// (the default) or strict.
type Mode int

const (
	ModeRelaxed Mode = iota
	ModeStrict
)

var modeNames = [...]string{"relaxed", "strict"}

func (m Mode) String() string {
	if int(m) < 0 || int(m) >= len(modeNames) {
		return "unknown"
	}
	return modeNames[m]
}

func (m Mode) MarshalJSON() ([]byte, error) {
	if int(m) < 0 || int(m) >= len(modeNames) {
		return nil, fmt.Errorf("dmarc: unknown mode %d", int(m))
	}
	return json.Marshal(m.String())
}

func (m *Mode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for i, name := range modeNames {
		if name == s {
			*m = Mode(i)
			return nil
		}
	}
	return fmt.Errorf("dmarc: unknown mode %q", s)
}

// Identifier is the closed set of authentication mechanisms DMARC aligns:
// SPF or DKIM.
type Identifier int

const (
	IdentifierSPF Identifier = iota
	IdentifierDKIM
)

var identifierNames = [...]string{"spf", "dkim"}

func (i Identifier) String() string {
	if int(i) < 0 || int(i) >= len(identifierNames) {
		return "unknown"
	}
	return identifierNames[i]
}

func (i Identifier) MarshalJSON() ([]byte, error) {
	if int(i) < 0 || int(i) >= len(identifierNames) {
		return nil, fmt.Errorf("dmarc: unknown identifier %d", int(i))
	}
	return json.Marshal(i.String())
}

// UnmarshalJSON exists so a rendered report reads back. A forensics artefact
// that cannot be reloaded is only half an artefact, and `frank explain --auth`
// reloads exactly this.
func (i *Identifier) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for n, name := range identifierNames {
		if name == s {
			*i = Identifier(n)
			return nil
		}
	}
	return fmt.Errorf("dmarc: unknown identifier %q", s)
}

// Policy is one parsed DMARC policy record.
type Policy struct {
	// Domain is the name the record was actually found at: the Header From
	// domain, or its organizational domain when FromSubdomain is true.
	Domain string
	// FromSubdomain is true when the record was found on the organizational
	// domain because none existed at the Header From domain itself, meaning
	// SP governs rather than P.
	FromSubdomain bool

	Version string
	P       Disposition
	SP      Disposition
	ADKIM   Mode
	ASPF    Mode
	Pct     int
	RUA     []string
	RUF     []string
	FO      []string
	RF      []string
	RI      int
	Raw     string
}

// Alignment is whether an authenticated domain matches the Header From
// domain, computed in both modes regardless of which mode the policy
// selects, per issue #10: a forensics user needs to see the strict-versus-
// relaxed question even when only one of them governs the Verdict.
type Alignment struct {
	Identifier          Identifier
	AuthenticatedDomain string
	HeaderFromDomain    string
	Relaxed             bool
	Strict              bool
}

// Input is what Evaluate needs: the Header From domain, the already-computed
// SPF Result (its Subject and SubjectFrom are consumed rather than
// recomputed, per the glossary's Domain Pair entry), and the DKIM signing
// domain. This package does not verify DKIM signatures itself (that is
// issue #9's Selector Discovery, not signature verification against a
// received message), so DKIMPass is supplied by the caller.
type Input struct {
	HeaderFromDomain string
	SPF              spf.Result
	DKIMDomain       string
	DKIMPass         bool
}

// Result is a DMARC Verdict: whether a policy was found, the policy itself,
// Alignment for both identifiers in both modes, whether the message passes
// DMARC, which disposition actually governs, any Caveats (the sampling rate
// among them), and which SPF subject was evaluated.
type Result struct {
	Found  bool
	Policy *Policy

	SPFAlignment  Alignment
	DKIMAlignment Alignment

	Pass bool
	// EffectivePolicy is the Disposition that governs this message:
	// Policy.P normally, or Policy.SP when Policy.FromSubdomain is true.
	EffectivePolicy Disposition

	Caveats []string

	Subject     string
	SubjectFrom string
}
