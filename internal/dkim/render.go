package dkim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Render writes the human-readable rendering of res: the domain, the bound
// and how many queries were actually made, the full effective Probed list
// (so a null result reads as "checked, none answered" rather than as
// silence), and each Found key with its faults.
func Render(res *Result) string {
	var buf bytes.Buffer
	_ = RenderText(&buf, res)
	return buf.String()
}

// RenderText writes the same rendering as Render to w, returning any write
// error.
func RenderText(w io.Writer, res *Result) error {
	if _, err := fmt.Fprintf(w, "domain: %s\n", res.Domain); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "selector discovery bound: %d queries (%d made)\n", res.Bound, res.QueriesMade); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "probed selectors (%d): %s\n", len(res.Probed), strings.Join(res.Probed, ", ")); err != nil {
		return err
	}

	if len(res.Found) == 0 {
		_, err := fmt.Fprintln(w, "found: none of the probed selectors answered")
		return err
	}

	if _, err := fmt.Fprintln(w, "found:"); err != nil {
		return err
	}
	for _, k := range res.Found {
		if err := renderKey(w, k); err != nil {
			return err
		}
	}
	return nil
}

func renderKey(w io.Writer, k Key) error {
	if _, err := fmt.Fprintf(w, "  - selector: %s\n", k.Selector); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "    key type: %s\n", k.KeyType); err != nil {
		return err
	}
	if k.Algorithm != "" {
		if _, err := fmt.Fprintf(w, "    algorithm: %s\n", k.Algorithm); err != nil {
			return err
		}
	}
	if len(k.Flags) > 0 {
		if _, err := fmt.Fprintf(w, "    flags: %s\n", strings.Join(k.Flags, ":")); err != nil {
			return err
		}
	}
	if len(k.Faults) == 0 {
		_, err := fmt.Fprintln(w, "    faults: none")
		return err
	}
	if _, err := fmt.Fprintln(w, "    faults:"); err != nil {
		return err
	}
	for _, f := range k.Faults {
		if _, err := fmt.Fprintf(w, "      - %s\n", f); err != nil {
			return err
		}
	}
	return nil
}

// RenderJSON writes res as JSON to w. Probed, Bound and QueriesMade are
// always present on Result, so they appear in this rendering exactly as
// they do in RenderText, satisfying "the effective list probed appears in
// both renderings".
func RenderJSON(w io.Writer, res *Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}
