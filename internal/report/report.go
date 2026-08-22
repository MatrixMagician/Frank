package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MatrixMagician/Frank/internal/dkim"
	"github.com/MatrixMagician/Frank/internal/dmarc"
	"github.com/MatrixMagician/Frank/internal/explain"
	"github.com/MatrixMagician/Frank/internal/matrix"
	"github.com/MatrixMagician/Frank/internal/spf"
	"github.com/MatrixMagician/Frank/internal/transcript"
)

// Report is the single self-contained artefact: the Transcript, the
// authentication Verdicts, the Matrix if one was run, and the Diagnosis. A
// colleague acts on it without reading source.
type Report struct {
	GeneratedAt time.Time
	Command     string

	Transcript *transcript.Transcript
	Redactor   *transcript.Redactor

	SPF   *spf.Result
	DKIM  *dkim.Result
	DMARC *dmarc.Result

	Matrix *matrix.Matrix

	Diagnosis *explain.Diagnosis
}

// RenderText writes the plain-text report.
func (r *Report) RenderText(w io.Writer) error {
	var b strings.Builder

	fmt.Fprintln(&b, "FRANK DELIVERABILITY REPORT")
	fmt.Fprintf(&b, "generated: %s\n", r.GeneratedAt.Format(time.RFC3339))
	if r.Command != "" {
		fmt.Fprintf(&b, "command: %s\n", r.Command)
	}

	if r.Diagnosis != nil {
		fmt.Fprintln(&b, "\n== DIAGNOSIS ==")
		fmt.Fprint(&b, r.Diagnosis.Render())
	}

	if r.Matrix != nil {
		fmt.Fprintln(&b, "\n== MATRIX ==")
		if err := matrix.Render(&b, r.Matrix); err != nil {
			return err
		}
	}

	if r.SPF != nil {
		fmt.Fprintln(&b, "\n== SPF ==")
		if err := spf.RenderTree(&b, r.SPF); err != nil {
			return err
		}
	}
	if r.DKIM != nil {
		fmt.Fprintln(&b, "\n== DKIM ==")
		fmt.Fprint(&b, dkim.Render(r.DKIM))
	}
	if r.DMARC != nil {
		fmt.Fprintln(&b, "\n== DMARC ==")
		fmt.Fprint(&b, dmarc.Render(r.DMARC))
	}

	if r.Transcript != nil {
		fmt.Fprintln(&b, "\n== TRANSCRIPT ==")
		if err := transcript.RenderText(&b, r.Transcript, r.Redactor); err != nil {
			return err
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// RenderJSON writes the structured report. It carries the same sections as the
// text rendering, so neither is a subset of the other.
func (r *Report) RenderJSON(w io.Writer) error {
	doc := map[string]any{
		"generated_at": r.GeneratedAt.Format(time.RFC3339),
	}
	if r.Command != "" {
		doc["command"] = r.Command
	}
	if r.Diagnosis != nil {
		doc["diagnosis"] = r.Diagnosis
	}
	if r.SPF != nil {
		doc["spf"] = r.SPF
	}
	if r.DKIM != nil {
		doc["dkim"] = r.DKIM
	}
	if r.DMARC != nil {
		doc["dmarc"] = r.DMARC
	}
	if r.Matrix != nil {
		var buf strings.Builder
		if err := matrix.RenderJSON(&buf, r.Matrix); err != nil {
			return err
		}
		var m any
		if err := json.Unmarshal([]byte(buf.String()), &m); err != nil {
			return err
		}
		doc["matrix"] = m
	}
	if r.Transcript != nil {
		var buf strings.Builder
		if err := transcript.RenderJSON(&buf, r.Transcript, r.Redactor); err != nil {
			return err
		}
		var t any
		if err := json.Unmarshal([]byte(buf.String()), &t); err != nil {
			return err
		}
		doc["transcript"] = t
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// DefaultOutputDir is the timestamped directory reports land in when --output
// was not given.
func DefaultOutputDir(now time.Time) string {
	return "./frank-" + now.UTC().Format("20060102T150405Z")
}

// Write puts both renderings in dir, always. --json changes only what reaches
// standard output; it never decides what is written to disk.
func (r *Report) Write(dir string) (textPath, jsonPath string, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}

	textPath = filepath.Join(dir, "report.txt")
	jsonPath = filepath.Join(dir, "report.json")

	textFile, err := os.Create(textPath)
	if err != nil {
		return "", "", err
	}
	defer textFile.Close()
	if err := r.RenderText(textFile); err != nil {
		return "", "", err
	}

	jsonFile, err := os.Create(jsonPath)
	if err != nil {
		return "", "", err
	}
	defer jsonFile.Close()
	if err := r.RenderJSON(jsonFile); err != nil {
		return "", "", err
	}

	return textPath, jsonPath, nil
}
