// Package spf evaluates RFC 7208 SPF records into an Evaluation Tree and a
// Verdict, against the resolve.Resolver seam (issue #7), for issue #8.
package spf

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

// Verdict is the closed set of results an SPF evaluation can reach, plus
// NotEvaluated. NotEvaluated is not an RFC 7208 result: it is what `auth`
// reports per ADR-0002 when there is no Candidate Sending IP to evaluate
// against, so the tree and the Lookup Limit finding still render without
// inventing a sending IP to get a real Verdict out of.
type Verdict int

const (
	NotEvaluated Verdict = iota
	Pass
	Fail
	SoftFail
	Neutral
	None
	PermError
	TempError
)

var verdictNames = [...]string{
	"not-evaluated", "pass", "fail", "softfail", "neutral", "none", "permerror", "temperror",
}

func (v Verdict) String() string {
	if int(v) < 0 || int(v) >= len(verdictNames) {
		return "unknown"
	}
	return verdictNames[v]
}

func (v Verdict) MarshalJSON() ([]byte, error) {
	if int(v) < 0 || int(v) >= len(verdictNames) {
		return nil, fmt.Errorf("spf: unknown verdict %d", int(v))
	}
	return json.Marshal(v.String())
}

func (v *Verdict) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for i, name := range verdictNames {
		if name == s {
			*v = Verdict(i)
			return nil
		}
	}
	return fmt.Errorf("spf: unknown verdict %q", s)
}

// Qualifier is the SPF prefix that decides what a matched mechanism means:
// +pass (the default when omitted), -fail, ~softfail, ?neutral.
type Qualifier int

const (
	QualifierPass Qualifier = iota
	QualifierFail
	QualifierSoftFail
	QualifierNeutral
)

var qualifierSymbols = [...]string{"+", "-", "~", "?"}

func (q Qualifier) String() string {
	if int(q) < 0 || int(q) >= len(qualifierSymbols) {
		return "?"
	}
	return qualifierSymbols[q]
}

// Verdict returns the Verdict a mechanism carrying this Qualifier produces
// when it matches.
func (q Qualifier) Verdict() Verdict {
	switch q {
	case QualifierFail:
		return Fail
	case QualifierSoftFail:
		return SoftFail
	case QualifierNeutral:
		return Neutral
	default:
		return Pass
	}
}

// CandidateSendingIP is the IP address an SPF Verdict is computed for, kept
// distinct from transcript.SourceAddress per ADR-0002 and
// docs/architecture.md's typed-identity rule: collapsing the two would
// default an SPF check to Frank's own observed address even when the Target
// Host relays onward, which is the confidently-wrong-Verdict case ADR-0002
// exists to prevent.
type CandidateSendingIP struct {
	addr     netip.Addr
	Observed bool
}

// NewCandidateSendingIP normalises addr with .Unmap() and rejects a zoned
// address, both at construction, per ADR-0006: doing it once here is what
// stops a matcher downstream forgetting and producing a confident wrong
// Verdict from an IPv4-mapped IPv6 address or a link-local zone.
func NewCandidateSendingIP(addr netip.Addr, observed bool) (CandidateSendingIP, error) {
	if !addr.IsValid() {
		return CandidateSendingIP{}, fmt.Errorf("spf: candidate sending ip is not valid")
	}
	if addr.Zone() != "" {
		return CandidateSendingIP{}, fmt.Errorf("spf: candidate sending ip %q carries a zone, which spf cannot evaluate", addr.String())
	}
	return CandidateSendingIP{addr: addr.Unmap(), Observed: observed}, nil
}

func (c CandidateSendingIP) Addr() netip.Addr { return c.addr }

func (c CandidateSendingIP) String() string {
	if !c.addr.IsValid() {
		return ""
	}
	return c.addr.String()
}

// MechanismKind names an RFC 7208 mechanism. It is a closed type looked up
// in the mechanism table (see eval.go), never switched on directly, so
// adding or auditing a mechanism means editing one table row.
type MechanismKind int

const (
	MechAll MechanismKind = iota
	MechInclude
	MechA
	MechMX
	MechPTR
	MechIP4
	MechIP6
	MechExists
)

var mechanismNames = [...]string{"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}

func (k MechanismKind) String() string {
	if int(k) < 0 || int(k) >= len(mechanismNames) {
		return "unknown"
	}
	return mechanismNames[k]
}

// Mechanism is one parsed term of an SPF record: either a mechanism with its
// Qualifier and arguments (IsMechanism true, Kind meaningful), or a modifier
// such as redirect= or exp= (IsMechanism false, ModifierName holds its
// name). Domain carries the domain-spec argument for include, exists,
// redirect, exp, and the optional target for a, mx, ptr (unmacroexpanded);
// for ip4/ip6 it carries the literal address/prefix text instead.
type Mechanism struct {
	Qualifier    Qualifier
	IsMechanism  bool
	Kind         MechanismKind
	ModifierName string
	Domain       string
	CIDR4        int
	HasCIDR4     bool
	CIDR6        int
	HasCIDR6     bool
	Raw          string
}

// FindingKind is the closed set of report-worthy conditions that are not
// themselves a Verdict but must survive into the rendered output alongside
// one, per issue #8: an over-limit record is a root cause in its own right,
// not merely the cause of a permerror return value that could be dropped.
type FindingKind int

const (
	FindingLookupLimitExceeded FindingKind = iota
	FindingSecondaryLimitExceeded
	FindingUnsupportedMacro
)

var findingNames = [...]string{"lookup-limit-exceeded", "secondary-limit-exceeded", "unsupported-macro"}

func (f FindingKind) String() string {
	if int(f) < 0 || int(f) >= len(findingNames) {
		return "unknown"
	}
	return findingNames[f]
}

// Finding is a report-worthy condition discovered during evaluation that
// must be visible in the output regardless of what Verdict it produced.
type Finding struct {
	Kind    FindingKind
	Domain  string
	Message string
}

// Node is one entry in an EvaluationTree: the mechanism as written, where it
// was reached from, and what evaluating it established.
type Node struct {
	Domain      string
	Term        Mechanism
	Depth       int
	CostsLookup bool
	Matched     bool
	Verdict     Verdict
	Err         error
}

// EvaluationTree is a domain's SPF record flattened into the ordered
// expansion of every mechanism reached, including through include: and
// redirect=, per the glossary's Evaluation Tree entry.
type EvaluationTree struct {
	Subject string
	Nodes   []*Node
}

// Request is the input to Evaluate.
type Request struct {
	EnvelopeSender string
	HeloIdentity   string
	ClientIP       *CandidateSendingIP
}

// Result is the outcome of evaluating a Request: the Verdict (or
// NotEvaluated), which subject domain it was computed for, the Matched
// Mechanism, the full Evaluation Tree, any Findings, and the DNS-querying
// mechanism count charged against the Lookup Limit.
type Result struct {
	Verdict     Verdict
	Subject     string
	SubjectFrom string
	Matched     *Node
	Tree        *EvaluationTree
	Findings    []Finding
	Lookups     int
	ClientIP    *CandidateSendingIP
}
