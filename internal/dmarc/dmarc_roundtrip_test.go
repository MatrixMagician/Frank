package dmarc

import (
	"encoding/json"
	"testing"
)

// TestClosedTypesRoundTripThroughJSON guards the reload path: a rendered
// report is a forensics artefact, and `frank explain --auth` reads one back.
func TestClosedTypesRoundTripThroughJSON(t *testing.T) {
	t.Run("identifier", func(t *testing.T) {
		for _, want := range []Identifier{IdentifierSPF, IdentifierDKIM} {
			raw, err := json.Marshal(want)
			if err != nil {
				t.Fatalf("marshal %v: %v", want, err)
			}
			var got Identifier
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshal %s: %v", raw, err)
			}
			if got != want {
				t.Errorf("round trip gave %v, want %v", got, want)
			}
		}
	})

	t.Run("result", func(t *testing.T) {
		want := Result{
			Found:           true,
			SPFAlignment:    Alignment{Identifier: IdentifierSPF, AuthenticatedDomain: "sender.example", HeaderFromDomain: "victim.example"},
			DKIMAlignment:   Alignment{Identifier: IdentifierDKIM},
			EffectivePolicy: DispositionReject,
			Subject:         "sender.example",
		}
		raw, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got Result
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.SPFAlignment.Identifier != want.SPFAlignment.Identifier {
			t.Errorf("spf identifier = %v, want %v", got.SPFAlignment.Identifier, want.SPFAlignment.Identifier)
		}
		if got.EffectivePolicy != want.EffectivePolicy {
			t.Errorf("effective policy = %v, want %v", got.EffectivePolicy, want.EffectivePolicy)
		}
	})
}
