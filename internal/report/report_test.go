package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MatrixMagician/Frank/internal/explain"
	"github.com/MatrixMagician/Frank/internal/transcript"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "frank.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestUnknownConfigKeyIsErrorNamingKey is half the reason ADR-0005 chose
// encoding/json: a mistyped key is an error rather than a silently ignored
// default.
func TestUnknownConfigKeyIsErrorNamingKey(t *testing.T) {
	path := writeConfig(t, `{"targt": "mx.example.com"}`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("a mistyped key was accepted")
	}
	if !strings.Contains(err.Error(), "targt") {
		t.Errorf("err = %v, want it to name the offending key", err)
	}
}

// TestZeroValueDistinctFromAbsent is the other half. A rate of 0 and a
// tls_verify of false must not be confused with the key being missing.
func TestZeroValueDistinctFromAbsent(t *testing.T) {
	t.Run("rate", func(t *testing.T) {
		set, err := Load(writeConfig(t, `{"rate": 0}`))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if set.Rate == nil {
			t.Fatal("an explicit rate of 0 decoded as absent")
		}
		if *set.Rate != 0 {
			t.Errorf("rate = %d, want 0", *set.Rate)
		}

		absent, err := Load(writeConfig(t, `{}`))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if absent.Rate != nil {
			t.Errorf("an omitted rate decoded as %d, want absent", *absent.Rate)
		}
	})

	t.Run("tls_verify", func(t *testing.T) {
		set, err := Load(writeConfig(t, `{"tls_verify": false}`))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if set.TLSVerify == nil {
			t.Fatal("an explicit tls_verify of false decoded as absent")
		}
		if *set.TLSVerify {
			t.Error("tls_verify = true, want false")
		}

		absent, err := Load(writeConfig(t, `{}`))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if absent.TLSVerify != nil {
			t.Errorf("an omitted tls_verify decoded as %v, want absent", *absent.TLSVerify)
		}
	})
}

func TestExplicitFlagBeatsConfigValue(t *testing.T) {
	fromConfig := "config.example.com"
	cfg := &Config{Target: &fromConfig}

	if got := StringOr(true, "flag.example.com", cfg.Target); got != "flag.example.com" {
		t.Errorf("StringOr with an explicit flag = %q, want the flag to win", got)
	}
	if got := StringOr(false, "", cfg.Target); got != fromConfig {
		t.Errorf("StringOr with no flag = %q, want the config value", got)
	}
	if got := StringOr(false, "default.example.com", nil); got != "default.example.com" {
		t.Errorf("StringOr with neither = %q, want the flag default", got)
	}

	configRate := 3
	if got := IntOr(true, 5, &configRate); got == nil || *got != 5 {
		t.Errorf("IntOr with an explicit flag = %v, want 5", got)
	}
	if got := IntOr(false, 0, &configRate); got == nil || *got != 3 {
		t.Errorf("IntOr with no flag = %v, want the config value 3", got)
	}
	if got := IntOr(false, 0, nil); got != nil {
		t.Errorf("IntOr with neither = %v, want nil so absent stays distinguishable", got)
	}

	configVerify := true
	if got := BoolOr(true, false, &configVerify); got {
		t.Error("BoolOr with an explicit false flag returned true")
	}
	if got := BoolOr(false, false, &configVerify); !got {
		t.Error("BoolOr with no flag did not take the config value")
	}
}

func TestRepeatableSettingsAppendRatherThanOverride(t *testing.T) {
	got := StringsOr([]string{"flag-one"}, []string{"config-one", "config-two"})
	want := []string{"flag-one", "config-one", "config-two"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestConfigDecodesEveryDocumentedKey(t *testing.T) {
	path := writeConfig(t, `{
	  "target": "smtp.example.com:587",
	  "envelope_from": "bounce@sender.example",
	  "helo": "frank.invalid",
	  "header_from": "author@sender.example",
	  "recipient": "rcpt@target.example",
	  "output": "/tmp/frank",
	  "rate": 4,
	  "tls": "require",
	  "tls_verify": true,
	  "redact": ["secret"],
	  "selectors": ["custom1"],
	  "username": "probe@sender.example",
	  "password": "hunter2",
	  "client_ip": "192.0.2.7"
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Target == nil || *cfg.Target != "smtp.example.com:587" {
		t.Errorf("target = %v", cfg.Target)
	}
	if cfg.Rate == nil || *cfg.Rate != 4 {
		t.Errorf("rate = %v", cfg.Rate)
	}
	if len(cfg.Selectors) != 1 || cfg.Selectors[0] != "custom1" {
		t.Errorf("selectors = %v", cfg.Selectors)
	}
	if cfg.Password == nil || *cfg.Password != "hunter2" {
		t.Errorf("password = %v", cfg.Password)
	}
}

func sampleReport(t *testing.T) *Report {
	t.Helper()
	tr := transcript.NewTranscript("mx.target.example:25", transcript.IdentityTriple{
		EnvelopeSender: "bounce@sender.example",
		HeloIdentity:   "frank.invalid",
		HeaderFrom:     "ceo@victim.example",
	}, "rcpt@target.example")
	ev := tr.Append(transcript.KindRecv, transcript.PhaseEndOfData, []byte("550 5.7.1 rejected\r\n"))
	reply, err := transcript.ParseReply([]byte("550 5.7.1 rejected\r\n"))
	if err != nil {
		t.Fatalf("ParseReply: %v", err)
	}
	ev.Reply = reply

	d := explain.Diagnose(explain.Input{Transcript: tr})

	redactor, err := transcript.NewRedactor(nil)
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}

	return &Report{
		GeneratedAt: time.Date(2026, 8, 22, 1, 0, 0, 0, time.UTC),
		Command:     "frank probe --target mx.target.example:25",
		Transcript:  tr,
		Redactor:    redactor,
		Diagnosis:   &d,
	}
}

func TestCombinedReportContainsAllSections(t *testing.T) {
	r := sampleReport(t)

	var text bytes.Buffer
	if err := r.RenderText(&text); err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	for _, want := range []string{"FRANK DELIVERABILITY REPORT", "== DIAGNOSIS ==", "== TRANSCRIPT ==", "550"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("the text report omits %q:\n%s", want, text.String())
		}
	}

	var jsonOut bytes.Buffer
	if err := r.RenderJSON(&jsonOut); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(jsonOut.Bytes(), &doc); err != nil {
		t.Fatalf("the json report does not parse: %v", err)
	}
	for _, want := range []string{"generated_at", "diagnosis", "transcript"} {
		if _, ok := doc[want]; !ok {
			t.Errorf("the json report omits %q", want)
		}
	}
}

func TestBothRenderingsWrittenToDefaultTimestampedDir(t *testing.T) {
	r := sampleReport(t)
	dir := filepath.Join(t.TempDir(), "out")

	textPath, jsonPath, err := r.Write(dir)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	for _, p := range []string{textPath, jsonPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", p)
		}
	}

	name := DefaultOutputDir(time.Date(2026, 8, 22, 1, 2, 3, 0, time.UTC))
	if name != "./frank-20260822T010203Z" {
		t.Errorf("DefaultOutputDir = %q, want a UTC timestamped directory", name)
	}
}

func TestReportRedactionAppliesToBothRenderings(t *testing.T) {
	r := sampleReport(t)
	redactor, err := transcript.NewRedactor([]string{`ceo@victim\.example`})
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}
	r.Redactor = redactor

	var text, jsonOut bytes.Buffer
	if err := r.RenderText(&text); err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	if err := r.RenderJSON(&jsonOut); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	if strings.Contains(text.String(), "ceo@victim.example") {
		t.Error("the text report leaks a redacted address")
	}
	if strings.Contains(jsonOut.String(), "ceo@victim.example") {
		t.Error("the json report leaks a redacted address")
	}
}
