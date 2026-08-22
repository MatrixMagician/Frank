package matrix

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Render writes the Matrix as a grid a reader can scan: rows and columns are
// Identity Slot values, so the failing Triple is visually obvious.
//
// The grid is drawn per HELO Identity, with envelope senders down the side and
// header From addresses across the top, because that is the pairing the
// headline "550 anti-spoofing" diagnosis turns on.
func Render(w io.Writer, m *Matrix) error {
	var b strings.Builder

	fmt.Fprintf(&b, "target: %s\n", m.TargetHost)
	fmt.Fprintf(&b, "recipient: %s\n", m.Recipient)
	if m.Aborted != "" {
		fmt.Fprintf(&b, "sweep aborted: %s\n", m.Aborted)
	}

	counts := m.Counts()
	fmt.Fprintf(&b, "cells: %d accepted, %d rejected, %d inconclusive, %d unrun\n",
		counts[Accepted], counts[Rejected], counts[Inconclusive], counts[Unrun])
	fmt.Fprintf(&b, "boundary: %s\n", m.Boundary())
	fmt.Fprintln(&b, "key: . accepted   X rejected   ? inconclusive (asked, no answer)   - unrun (never asked)")

	byTriple := map[Triple]*Cell{}
	for _, c := range m.Cells {
		byTriple[c.Triple] = c
	}

	headers := m.Slots.HeaderFroms
	width := 0
	for _, e := range m.Slots.EnvelopeSenders {
		if n := len(displayValue(e)); n > width {
			width = n
		}
	}

	for _, helo := range m.Slots.HeloIdentities {
		fmt.Fprintf(&b, "\nhelo identity: %s\n", helo)
		fmt.Fprintf(&b, "%-*s", width+2, "")
		for i := range headers {
			fmt.Fprintf(&b, " %d", i+1)
		}
		fmt.Fprintln(&b)

		for _, envelope := range m.Slots.EnvelopeSenders {
			fmt.Fprintf(&b, "%-*s", width+2, displayValue(envelope))
			for _, header := range headers {
				cell := byTriple[Triple{EnvelopeSender: envelope, HeloIdentity: helo, HeaderFrom: header}]
				mark := Unrun.Symbol()
				if cell != nil {
					mark = cell.Resolution().Symbol()
				}
				fmt.Fprintf(&b, " %s", mark)
			}
			fmt.Fprintln(&b)
		}

		fmt.Fprintln(&b, "header from columns:")
		for i, h := range headers {
			fmt.Fprintf(&b, "  %d = %s\n", i+1, displayValue(h))
		}
	}

	fmt.Fprintln(&b, "\ncells:")
	for _, c := range m.Cells {
		fmt.Fprintf(&b, "  [%s] %s", c.Resolution(), c.Triple)
		if last, ok := lastOutcome(c); ok {
			fmt.Fprintf(&b, " -> %d", last.Code)
			if last.Enhanced != "" {
				fmt.Fprintf(&b, " %s", last.Enhanced)
			}
			fmt.Fprintf(&b, " at %s: %s", last.Phase, last.Text)
		} else if len(c.Probes) > 0 && c.Probes[len(c.Probes)-1].Error != "" {
			fmt.Fprintf(&b, " -> %s", c.Probes[len(c.Probes)-1].Error)
		}
		fmt.Fprintln(&b)
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// RenderJSON writes the Matrix as the structured document.
func RenderJSON(w io.Writer, m *Matrix) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		TargetHost string         `json:"target_host"`
		Recipient  string         `json:"recipient"`
		Aborted    string         `json:"aborted,omitempty"`
		Boundary   string         `json:"boundary"`
		Counts     map[string]int `json:"counts"`
		Cells      []*Cell        `json:"cells"`
	}{
		TargetHost: m.TargetHost,
		Recipient:  m.Recipient,
		Aborted:    m.Aborted,
		Boundary:   m.Boundary(),
		Counts:     namedCounts(m),
		Cells:      m.Cells,
	})
}

func namedCounts(m *Matrix) map[string]int {
	out := map[string]int{}
	for res, n := range m.Counts() {
		out[res.String()] = n
	}
	return out
}

func lastOutcome(c *Cell) (ProbeRecord, bool) {
	for i := len(c.Probes) - 1; i >= 0; i-- {
		if c.Probes[i].Outcome != nil {
			return c.Probes[i], true
		}
	}
	return ProbeRecord{}, false
}

// displayValue renders the null sender as <> so an empty cell label is never
// ambiguous with a missing one.
func displayValue(v string) string {
	if v == "" {
		return "<>"
	}
	return v
}
