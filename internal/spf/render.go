package spf

import (
	"fmt"
	"io"
	"strings"
)

// RenderTree writes the Evaluation Tree so a human can see exactly how the
// Verdict was reached: the subject and how it was chosen, the Candidate
// Sending IP and whether it was observed or supplied, the Verdict (or
// NotEvaluated) and its Matched Mechanism, the Lookup Limit usage, every
// Finding, and every mechanism reached in order, indented by the include or
// redirect depth that reached it.
func RenderTree(w io.Writer, res *Result) error {
	if _, err := fmt.Fprintf(w, "subject: %s (from the %s)\n", res.Subject, res.SubjectFrom); err != nil {
		return err
	}

	if res.ClientIP == nil {
		if _, err := fmt.Fprintln(w, "candidate sending ip: none supplied, so the verdict is not evaluated"); err != nil {
			return err
		}
	} else {
		origin := "supplied"
		if res.ClientIP.Observed {
			origin = "observed"
		}
		if _, err := fmt.Fprintf(w, "candidate sending ip: %s (%s)\n", res.ClientIP.String(), origin); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(w, "verdict: %s\n", res.Verdict); err != nil {
		return err
	}
	if res.Matched != nil {
		if _, err := fmt.Fprintf(w, "matched mechanism: %s (at %s, depth %d)\n", res.Matched.Term.Raw, res.Matched.Domain, res.Matched.Depth); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(w, "matched mechanism: none"); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(w, "lookups: %d/%d\n", res.Lookups, LookupLimit); err != nil {
		return err
	}

	if len(res.Findings) > 0 {
		if _, err := fmt.Fprintln(w, "findings:"); err != nil {
			return err
		}
		for _, f := range res.Findings {
			if _, err := fmt.Fprintf(w, "  - [%s] %s: %s\n", f.Kind, f.Domain, f.Message); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w, "evaluation tree:"); err != nil {
		return err
	}
	if res.Tree == nil || len(res.Tree.Nodes) == 0 {
		_, err := fmt.Fprintln(w, "  (empty)")
		return err
	}
	for _, n := range res.Tree.Nodes {
		if err := renderNode(w, n); err != nil {
			return err
		}
	}
	return nil
}

func renderNode(w io.Writer, n *Node) error {
	indent := strings.Repeat("  ", n.Depth+1)
	status := "no match"
	if n.Matched {
		status = fmt.Sprintf("matched -> %s", n.Verdict)
	}
	lookupTag := ""
	if n.CostsLookup {
		lookupTag = " [lookup]"
	}
	if _, err := fmt.Fprintf(w, "%s%s%s (%s): %s\n", indent, n.Term.Raw, lookupTag, n.Domain, status); err != nil {
		return err
	}
	if n.Err != nil {
		if _, err := fmt.Fprintf(w, "%s  error: %s\n", indent, n.Err); err != nil {
			return err
		}
	}
	return nil
}
