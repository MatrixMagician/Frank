package smtpconv

import (
	"fmt"

	"github.com/MatrixMagician/Frank/internal/transcript"
)

type OutcomeKind int

const (
	OutcomeAcceptance OutcomeKind = iota
	OutcomeRejection
	OutcomeDeferral
)

var outcomeKindNames = [...]string{"acceptance", "rejection", "deferral"}

func (k OutcomeKind) String() string {
	if int(k) < 0 || int(k) >= len(outcomeKindNames) {
		return "unknown"
	}
	return outcomeKindNames[k]
}

// Outcome is what a Target Host did, observed at a Phase of a Probe. There is
// no zero-value Outcome a caller can construct: NewOutcome is the only way to
// get one, and it always requires the reply that justifies it.
type Outcome struct {
	kind  OutcomeKind
	phase transcript.Phase
	reply transcript.Reply
}

// NewOutcome classifies reply's code at phase into the Outcome it evidences.
// A code outside 2xx/4xx/5xx (354, the DATA continuation, for instance)
// carries no Outcome of its own and is an error to classify.
func NewOutcome(phase transcript.Phase, reply transcript.Reply) (Outcome, error) {
	switch {
	case reply.IsPositive():
		return Outcome{kind: OutcomeAcceptance, phase: phase, reply: reply}, nil
	case reply.IsTransient():
		return Outcome{kind: OutcomeDeferral, phase: phase, reply: reply}, nil
	case reply.IsPermanent():
		return Outcome{kind: OutcomeRejection, phase: phase, reply: reply}, nil
	default:
		return Outcome{}, fmt.Errorf("smtpconv: reply code %d at %s carries no outcome", reply.Code, phase)
	}
}

func (o Outcome) Kind() OutcomeKind        { return o.kind }
func (o Outcome) Phase() transcript.Phase  { return o.phase }
func (o Outcome) Reply() transcript.Reply  { return o.reply }
func (o Outcome) IsAcceptance() bool       { return o.kind == OutcomeAcceptance }
func (o Outcome) IsRejection() bool        { return o.kind == OutcomeRejection }
func (o Outcome) IsDeferral() bool         { return o.kind == OutcomeDeferral }
