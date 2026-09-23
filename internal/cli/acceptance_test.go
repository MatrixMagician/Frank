package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MatrixMagician/Frank/internal/gate"
	"github.com/MatrixMagician/Frank/internal/smtptest"
)

// TestMatrixExitCodes is the sweep's contract with a script: 1 if any Cell was
// Rejected, otherwise 4 if any is Inconclusive or Unrun, otherwise 0.
func TestMatrixExitCodes(t *testing.T) {
	tests := []struct {
		name string
		opts []smtptest.Option
		want Code
	}{
		{
			name: "every cell accepted exits 0",
			want: CodeAcceptance,
		},
		{
			name: "any rejected cell exits 1",
			opts: []smtptest.Option{smtptest.RejectTriple(smtptest.PhaseEndOfData,
				smtptest.ObservedTriple{HeaderFrom: "ceo@victim.example"},
				550, "5.7.1", "not allowed")},
			want: CodeRejection,
		},
		{
			name: "only deferrals exit 4",
			opts: []smtptest.Option{smtptest.Greylist(smtptest.PhaseEndOfData, 99,
				450, "4.7.1", "greylisted")},
			want: CodeInconclusive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := smtptest.Start(t, tt.opts...)
			var stdout, stderr bytes.Buffer

			got := run([]string{
				"--confirm-send", "rcpt@target.example",
				"--output", t.TempDir(),
				"matrix",
				"--target", srv.Addr(),
				"--recipient", "rcpt@target.example",
				"--envelope-from", "bounce@sender.example",
				"--helo", "frank.invalid",
				"--header-from", "ceo@victim.example",
				"--header-from", "author@sender.example",
			}, &stdout, &stderr, gate.NewFakeClockAtEpoch())

			if got != tt.want {
				t.Errorf("code = %v, want %v\nstdout: %s\nstderr: %s", got, tt.want, stdout.String(), stderr.String())
			}
		})
	}
}

func TestMatrixRateCannotBeRaisedAboveTheDefault(t *testing.T) {
	srv := smtptest.Start(t)
	var stdout, stderr bytes.Buffer

	got := Main([]string{
		"--rate", "600",
		"matrix",
		"--target", srv.Addr(),
		"--recipient", "rcpt@target.example",
		"--envelope-from", "a@sender.example",
		"--helo", "frank.invalid",
		"--header-from", "a@sender.example",
	}, &stdout, &stderr)

	if got != CodeUsage {
		t.Errorf("code = %v, want %v", got, CodeUsage)
	}
	if !strings.Contains(stderr.String(), "refused") {
		t.Errorf("stderr = %q, want the rate refused rather than clamped", stderr.String())
	}
	if srv.ConnectionCount() != 0 {
		t.Errorf("the target was dialed %d times, want the refusal before any connection", srv.ConnectionCount())
	}
}

func TestExplainUnreadableInputExitsUsage(t *testing.T) {
	dir := t.TempDir()

	notJSON := filepath.Join(dir, "not.json")
	if err := os.WriteFile(notJSON, []byte("this is not json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	emptyDoc := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(emptyDoc, []byte(`{"events": []}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tests := map[string]string{
		"malformed json":      notJSON,
		"no events":           emptyDoc,
		"file does not exist": filepath.Join(dir, "absent.json"),
	}

	for name, path := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := Main([]string{"explain", path}, &stdout, &stderr)
			if got != CodeUsage {
				t.Errorf("code = %v, want %v", got, CodeUsage)
			}
			if stderr.String() == "" {
				t.Error("stderr is empty, want the reason named")
			}
		})
	}

	t.Run("no argument", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if got := Main([]string{"explain"}, &stdout, &stderr); got != CodeUsage {
			t.Errorf("code = %v, want %v", got, CodeUsage)
		}
	})
}

// TestCredentialsFromConfigNeverFromAFlag pins ADR-0007's rule at the CLI
// boundary: the config file supplies credentials, the environment overrides it,
// and no flag anywhere accepts one.
func TestCredentialsFromConfigNeverFromAFlag(t *testing.T) {
	t.Run("read from the config file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "frank.json")
		body := `{"username": "probe@sender.example", "password": "hunter2"}`
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}

		var stderr bytes.Buffer
		opts, _, err := ParseGlobalFlags([]string{"--config", path}, &stderr)
		if err != nil {
			t.Fatalf("ParseGlobalFlags: %v", err)
		}
		if _, err := loadConfigInto(opts); err != nil {
			t.Fatalf("load config: %v", err)
		}

		got := credentials(opts)
		if got.Username != "probe@sender.example" || got.Password != "hunter2" {
			t.Errorf("credentials = %q/%q, want them read from the config", got.Username, got.Password)
		}
	})

	t.Run("the environment wins over the config", func(t *testing.T) {
		t.Setenv("FRANK_SMTP_USERNAME", "env@sender.example")
		t.Setenv("FRANK_SMTP_PASSWORD", "from-env")

		path := filepath.Join(t.TempDir(), "frank.json")
		if err := os.WriteFile(path, []byte(`{"username": "cfg@sender.example", "password": "from-cfg"}`), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}

		var stderr bytes.Buffer
		opts, _, err := ParseGlobalFlags([]string{"--config", path}, &stderr)
		if err != nil {
			t.Fatalf("ParseGlobalFlags: %v", err)
		}
		if _, err := loadConfigInto(opts); err != nil {
			t.Fatalf("load config: %v", err)
		}

		if got := credentials(opts); got.Password != "from-env" {
			t.Errorf("password = %q, want the environment to win", got.Password)
		}
	})

	t.Run("no flag accepts a credential", func(t *testing.T) {
		var stderr bytes.Buffer
		for _, name := range []string{"--username", "--password", "--credentials", "--auth-user", "--auth-password"} {
			if _, _, err := ParseGlobalFlags([]string{name, "x"}, &stderr); err == nil {
				t.Errorf("%s parsed as a global flag, but argv is world-readable through /proc", name)
			}
		}

		pf := &probeFlags{}
		fs := newProbeFlagSet(&stderr, pf)
		for _, name := range []string{"username", "password", "credentials"} {
			if fs.Lookup(name) != nil {
				t.Errorf("probe defines a --%s flag, which ADR-0007 forbids", name)
			}
		}
	})
}

// TestJSONFlagChangesOnlyStdout pins the rule that --json redirects what a
// script reads and never decides what lands on disk.
func TestJSONFlagChangesOnlyStdout(t *testing.T) {
	run := func(t *testing.T, jsonFlag bool) (stdout string, dir string) {
		t.Helper()
		srv := smtptest.Start(t)
		dir = t.TempDir()

		args := []string{"--dry-run", "--output", dir}
		if jsonFlag {
			args = append(args, "--json")
		}
		args = append(args,
			"probe",
			"--target", srv.Addr(),
			"--envelope-from", "bounce@sender.example",
			"--helo", "frank.invalid",
			"--header-from", "author@sender.example",
			"--recipient", "rcpt@target.example",
		)

		var out, errBuf bytes.Buffer
		if code := Main(args, &out, &errBuf); code != CodeAcceptance {
			t.Fatalf("code = %v, want %v\nstderr: %s", code, CodeAcceptance, errBuf.String())
		}
		return out.String(), dir
	}

	textOut, textDir := run(t, false)
	jsonOut, jsonDir := run(t, true)

	if json.Valid([]byte(textOut)) {
		t.Error("stdout without --json parsed as json, want the human log")
	}
	if !json.Valid([]byte(jsonOut)) {
		t.Errorf("stdout with --json is not valid json:\n%s", jsonOut)
	}

	// Both runs must write the same four artefacts regardless of the flag.
	want := []string{"transcript.txt", "transcript.json", "report.txt", "report.json"}
	for _, dir := range []string{textDir, jsonDir} {
		for _, name := range want {
			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil {
				t.Errorf("%s missing from %s: %v", name, dir, err)
				continue
			}
			if info.Size() == 0 {
				t.Errorf("%s in %s is empty", name, dir)
			}
		}
	}
}

// TestEndToEndReportAgainstDouble is issue #14's headline: one run against the
// double yields a report a colleague acts on without reading source, and the
// exit code says what happened.
func TestEndToEndReportAgainstDouble(t *testing.T) {
	srv := smtptest.Start(t,
		smtptest.WithExtensions("SIZE 10240000", "8BITMIME", "ENHANCEDSTATUSCODES"),
		smtptest.Reject(smtptest.PhaseEndOfData, 550, "5.7.1",
			"sender address not owned by authenticated user"),
	)
	dir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := Main([]string{
		"--confirm-send", "rcpt@target.example",
		"--output", dir,
		"probe",
		"--target", srv.Addr(),
		"--envelope-from", "bounce@sender.example",
		"--helo", "frank.invalid",
		"--header-from", "ceo@victim.example",
		"--recipient", "rcpt@target.example",
	}, &stdout, &stderr)

	if code != CodeRejection {
		t.Fatalf("code = %v, want %v for a 550 at end-of-data\nstderr: %s", code, CodeRejection, stderr.String())
	}

	raw, err := os.ReadFile(filepath.Join(dir, "report.txt"))
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	report := string(raw)

	// What a colleague needs without reading source: what was tried, what the
	// target said, where it said it, and what it means.
	for _, want := range []string{
		"FRANK DELIVERABILITY REPORT",
		"== DIAGNOSIS ==",
		"== TRANSCRIPT ==",
		"bounce@sender.example",
		"ceo@victim.example",
		"frank.invalid",
		"rcpt@target.example",
		"550",
		"5.7.1",
		"end-of-data",
		"sender address not owned by authenticated user",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the report omits %q, so a reader would have to consult the source", want)
		}
	}

	jsonRaw, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatalf("read json report: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(jsonRaw, &doc); err != nil {
		t.Fatalf("the json report does not parse: %v", err)
	}
	for _, section := range []string{"diagnosis", "transcript"} {
		if _, ok := doc[section]; !ok {
			t.Errorf("the json report omits the %q section", section)
		}
	}
}
