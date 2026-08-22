// Package explain joins a captured Transcript to the Verdicts computed from
// DNS and states a Diagnosis, per issue #13.
package explain

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MatrixMagician/Frank/internal/dmarc"
	"github.com/MatrixMagician/Frank/internal/spf"
	"github.com/MatrixMagician/Frank/internal/transcript"
)

// Confidence is how firmly the evidence supports the Diagnosis. Ambiguity is
// stated rather than smoothed over, because a Diagnosis that overclaims is
// worse than one that says what it cannot tell.
type Confidence int

const (
	// Ambiguous means the evidence admits more than one cause, and the
	// Diagnosis names the further Probe that would separate them.
	Ambiguous Confidence = iota
	// Supported means the observed Outcome and the computed Verdicts agree on
	// one cause.
	Supported
)

var confidenceNames = [...]string{"ambiguous", "supported"}

func (c Confidence) String() string {
	if int(c) < 0 || int(c) >= len(confidenceNames) {
		return "unknown"
	}
	return confidenceNames[c]
}

func (c Confidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// Evidence is one fact the Diagnosis rests on, tagged by how Frank came to
// know it. That distinction is the one the whole safety posture rests on: an
// Observed fact is something a Target Host did, a Computed one is something
// the published records say.
type Evidence struct {
	Observed bool   `json:"observed"`
	Text     string `json:"text"`
}

func (e Evidence) String() string {
	if e.Observed {
		return "observed: " + e.Text
	}
	return "computed: " + e.Text
}

// Diagnosis is the evidential synthesis of Outcomes and Verdicts.
type Diagnosis struct {
	Summary      string     `json:"summary"`
	Confidence   Confidence `json:"confidence"`
	Evidence     []Evidence `json:"evidence"`
	NextProbe    string     `json:"next_probe,omitempty"`
	PerCellLines []string   `json:"per_cell,omitempty"`
}

// Input is everything a Diagnosis is drawn from. Auth results are optional:
// without them Frank performs the lookups itself before calling here.
type Input struct {
	Transcript *transcript.Transcript
	SPF        *spf.Result
	DMARC      *dmarc.Result
	// MatrixBoundary and MatrixCells carry a sweep's findings, so a Transcript
	// from matrix yields one Diagnosis for the run plus a line per Cell.
	MatrixBoundary string
	MatrixCells    []string
}

// Render writes the Diagnosis in the form a user pastes into a case.
func (d Diagnosis) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "diagnosis: %s\n", d.Summary)
	fmt.Fprintf(&b, "confidence: %s\n", d.Confidence)

	fmt.Fprintln(&b, "evidence:")
	for _, e := range d.Evidence {
		fmt.Fprintf(&b, "  - %s\n", e)
	}

	if len(d.PerCellLines) > 0 {
		fmt.Fprintln(&b, "cells:")
		for _, line := range d.PerCellLines {
			fmt.Fprintf(&b, "  - %s\n", line)
		}
	}

	if d.NextProbe != "" {
		fmt.Fprintf(&b, "next probe: %s\n", d.NextProbe)
	}
	return b.String()
}

// RenderJSON writes the Diagnosis as the structured document.
func (d Diagnosis) RenderJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}
