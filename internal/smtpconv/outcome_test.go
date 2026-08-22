package smtpconv

import (
	"strings"
	"testing"

	"github.com/MatrixMagician/Frank/internal/transcript"
)

func TestNewOutcomeClassifiesReplyCode(t *testing.T) {
	tests := []struct {
		code int
		want OutcomeKind
	}{
		{250, OutcomeAcceptance},
		{221, OutcomeAcceptance},
		{450, OutcomeDeferral},
		{421, OutcomeDeferral},
		{550, OutcomeRejection},
		{500, OutcomeRejection},
	}
	for _, tt := range tests {
		o, err := NewOutcome(transcript.PhaseEndOfData, transcript.Reply{Code: tt.code, Text: "x"})
		if err != nil {
			t.Fatalf("NewOutcome(%d): %v", tt.code, err)
		}
		if o.Kind() != tt.want {
			t.Errorf("NewOutcome(%d).Kind() = %v, want %v", tt.code, o.Kind(), tt.want)
		}
	}
}

func TestNewOutcomeRejectsCodeOutsideKnownClasses(t *testing.T) {
	if _, err := NewOutcome(transcript.PhaseData, transcript.Reply{Code: 354, Text: "continue"}); err == nil {
		t.Fatal("NewOutcome(354): want error, got nil")
	}
}

func TestOutcomeAlwaysCarriesItsReply(t *testing.T) {
	reply := transcript.Reply{Code: 550, Text: "no"}
	o, err := NewOutcome(transcript.PhaseRcptTo, reply)
	if err != nil {
		t.Fatalf("NewOutcome: %v", err)
	}
	if o.Reply().Code != 550 || o.Reply().Text != "no" {
		t.Errorf("Outcome.Reply() = %+v, want the reply that justified it", o.Reply())
	}
	if o.Phase() != transcript.PhaseRcptTo {
		t.Errorf("Outcome.Phase() = %v, want %v", o.Phase(), transcript.PhaseRcptTo)
	}
}

func TestOutcomeKindStringIsLowercase(t *testing.T) {
	for _, k := range []OutcomeKind{OutcomeAcceptance, OutcomeRejection, OutcomeDeferral} {
		if s := k.String(); s != strings.ToLower(s) {
			t.Errorf("OutcomeKind(%d).String() = %q, want lowercase", k, s)
		}
	}
}
