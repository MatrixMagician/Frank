package transcript

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactMasksInBothRenderings(t *testing.T) {
	tr := NewTranscript("mx.example.com", IdentityTriple{
		EnvelopeSender: "secret-user@example.com",
		HeloIdentity:   "client.example.com",
		HeaderFrom:     "header@example.com",
	}, "rcpt@example.com")
	tr.Append(KindSend, PhaseMailFrom, []byte("MAIL FROM:<secret-user@example.com>\r\n"))

	r, err := NewRedactor([]string{`secret-user@example\.com`})
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}

	var textBuf bytes.Buffer
	if err := RenderText(&textBuf, tr, r); err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	if strings.Contains(textBuf.String(), "secret-user@example.com") {
		t.Errorf("text render still contains the secret:\n%s", textBuf.String())
	}
	if !strings.Contains(textBuf.String(), "[REDACTED]") {
		t.Error("text render missing redaction mark")
	}

	r2, err := NewRedactor([]string{`secret-user@example\.com`})
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}
	var jsonBuf bytes.Buffer
	if err := RenderJSON(&jsonBuf, tr, r2); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if strings.Contains(jsonBuf.String(), "secret-user@example.com") {
		t.Errorf("json render still contains the secret:\n%s", jsonBuf.String())
	}
	if !strings.Contains(jsonBuf.String(), "[REDACTED]") {
		t.Error("json render missing redaction mark")
	}
}

func TestRedactionPathRunsWithNoPatterns(t *testing.T) {
	tr := NewTranscript("mx.example.com", IdentityTriple{}, "rcpt@example.com")
	tr.Append(KindSend, PhaseMailFrom, []byte("MAIL FROM:<user@example.com>\r\n"))

	r, err := NewRedactor(nil)
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}

	var textBuf bytes.Buffer
	if err := RenderText(&textBuf, tr, r); err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	if !strings.Contains(textBuf.String(), "user@example.com") {
		t.Error("with no patterns, the raw text must pass through unmasked")
	}
	if !strings.Contains(textBuf.String(), "redacted-spans: 0") {
		t.Errorf("report does not state a zero count:\n%s", textBuf.String())
	}

	got, n := r.Redact("nothing to mask here")
	if got != "nothing to mask here" {
		t.Errorf("Redact() = %q, want unchanged input", got)
	}
	if n != 0 {
		t.Errorf("Redact() masked %d spans, want 0 with no patterns", n)
	}
}

func TestRedactionPathRunsWithNilRedactor(t *testing.T) {
	var r *Redactor
	got, n := r.Redact("passes through unmasked")
	if got != "passes through unmasked" {
		t.Errorf("Redact() on nil Redactor = %q, want unchanged input", got)
	}
	if n != 0 {
		t.Errorf("Redact() on nil Redactor masked %d spans, want 0", n)
	}

	tr := NewTranscript("mx.example.com", IdentityTriple{}, "rcpt@example.com")
	tr.Append(KindSend, PhaseMailFrom, []byte("MAIL FROM:<user@example.com>\r\n"))

	var textBuf bytes.Buffer
	if err := RenderText(&textBuf, tr, r); err != nil {
		t.Fatalf("RenderText with nil Redactor: %v", err)
	}
	if !strings.Contains(textBuf.String(), "user@example.com") {
		t.Error("nil Redactor must still render the raw bytes through the same code path")
	}
}

func TestRedactionCountIsReported(t *testing.T) {
	tr := NewTranscript("mx.example.com", IdentityTriple{}, "")
	tr.Append(KindSend, PhaseMailFrom, []byte("MAIL FROM:<a@example.com>\r\n"))
	tr.Append(KindSend, PhaseRcptTo, []byte("RCPT TO:<b@example.com>\r\n"))

	r, err := NewRedactor([]string{`[a-z]@example\.com`})
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}

	var textBuf bytes.Buffer
	if err := RenderText(&textBuf, tr, r); err != nil {
		t.Fatalf("RenderText: %v", err)
	}

	if !strings.Contains(textBuf.String(), "redacted-spans: 2") {
		t.Errorf("report does not state the count:\n%s", textBuf.String())
	}
}

func TestRedactionCountIsPerRenderingNotCumulative(t *testing.T) {
	tr := NewTranscript("mx.example.com", IdentityTriple{}, "")
	tr.Append(KindSend, PhaseMailFrom, []byte("MAIL FROM:<a@example.com>\r\n"))
	tr.Append(KindSend, PhaseRcptTo, []byte("RCPT TO:<b@example.com>\r\n"))

	r, err := NewRedactor([]string{`[a-z]@example\.com`})
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}

	var textBuf, jsonBuf bytes.Buffer
	if err := RenderText(&textBuf, tr, r); err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	if err := RenderJSON(&jsonBuf, tr, r); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	if !strings.Contains(textBuf.String(), "redacted-spans: 2") {
		t.Errorf("text rendering does not state 2 spans:\n%s", textBuf.String())
	}
	if !strings.Contains(jsonBuf.String(), `"redacted_spans": 2`) {
		t.Errorf("json rendering does not state 2 spans, the count leaked across renderings:\n%s", jsonBuf.String())
	}
}

func TestRedactorMasksLiteralSecretsUnconditionally(t *testing.T) {
	r, err := NewRedactor(nil)
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}
	r.AddLiteral("hunter2")

	got, n := r.Redact("AUTH PLAIN hunter2 more text")
	if strings.Contains(got, "hunter2") {
		t.Errorf("Redact() = %q, still contains the literal secret", got)
	}
	if n != 1 {
		t.Errorf("Redact() masked %d spans, want 1", n)
	}
}

func TestRedactMatchesMultipleSpansInOneString(t *testing.T) {
	r, err := NewRedactor([]string{`\d+`})
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}
	got, n := r.Redact("code 250 and code 550")
	if strings.Contains(got, "250") || strings.Contains(got, "550") {
		t.Errorf("Redact() = %q, want both numbers masked", got)
	}
	if n != 2 {
		t.Errorf("Redact() masked %d spans, want 2", n)
	}
}
