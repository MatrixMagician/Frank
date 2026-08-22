package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionFlagPrintsVersionAndReturnsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer

	got := Main([]string{"--version"}, &stdout, &stderr)

	if got != CodeAcceptance {
		t.Errorf("code = %v, want %v", got, CodeAcceptance)
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Error("stdout is empty, want a version string")
	}
}

func TestUnknownVerbReturnsUsageCode(t *testing.T) {
	var stdout, stderr bytes.Buffer

	got := Main([]string{"frobnicate"}, &stdout, &stderr)

	if got != CodeUsage {
		t.Errorf("code = %v, want %v", got, CodeUsage)
	}
	if stderr.String() == "" {
		t.Error("stderr is empty, want usage output")
	}
}

func TestNoArgsReturnsUsageCode(t *testing.T) {
	var stdout, stderr bytes.Buffer

	got := Main(nil, &stdout, &stderr)

	if got != CodeUsage {
		t.Errorf("code = %v, want %v", got, CodeUsage)
	}
}

func TestHelpFlagPrintsUsageAndReturnsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer

	got := Main([]string{"--help"}, &stdout, &stderr)

	if got != CodeAcceptance {
		t.Errorf("code = %v, want %v", got, CodeAcceptance)
	}
	if stdout.String() == "" {
		t.Error("stdout is empty, want usage output")
	}
}

func TestAllGlobalFlagsParse(t *testing.T) {
	var stderr bytes.Buffer

	args := []string{
		"--config", "frank.json",
		"--output", "/tmp/out",
		"--json",
		"--verbose",
		"--dry-run",
		"--rate", "3",
		"--confirm-send", "recipient@example.com",
		"--redact", "secret",
	}

	opts, rest, err := ParseGlobalFlags(args, &stderr)
	if err != nil {
		t.Fatalf("ParseGlobalFlags() error = %v", err)
	}

	if opts.Config != "frank.json" {
		t.Errorf("Config = %q, want %q", opts.Config, "frank.json")
	}
	if opts.Output != "/tmp/out" {
		t.Errorf("Output = %q, want %q", opts.Output, "/tmp/out")
	}
	if !opts.JSON {
		t.Error("JSON = false, want true")
	}
	if !opts.Verbose {
		t.Error("Verbose = false, want true")
	}
	if !opts.DryRun {
		t.Error("DryRun = false, want true")
	}
	if opts.Rate != 3 {
		t.Errorf("Rate = %d, want 3", opts.Rate)
	}
	if opts.ConfirmSend != "recipient@example.com" {
		t.Errorf("ConfirmSend = %q, want %q", opts.ConfirmSend, "recipient@example.com")
	}
	if len(opts.Redact) != 1 || opts.Redact[0] != "secret" {
		t.Errorf("Redact = %v, want [secret]", opts.Redact)
	}
	if len(rest) != 0 {
		t.Errorf("rest = %v, want empty", rest)
	}
}

func TestRedactFlagIsRepeatable(t *testing.T) {
	var stderr bytes.Buffer

	opts, _, err := ParseGlobalFlags([]string{"--redact", "one", "--redact", "two"}, &stderr)
	if err != nil {
		t.Fatalf("ParseGlobalFlags() error = %v", err)
	}

	want := []string{"one", "two"}
	if len(opts.Redact) != len(want) {
		t.Fatalf("Redact = %v, want %v", opts.Redact, want)
	}
	for i, p := range want {
		if opts.Redact[i] != p {
			t.Errorf("Redact[%d] = %q, want %q", i, opts.Redact[i], p)
		}
	}
}

func TestExplicitFlagsDistinguishZeroFromAbsent(t *testing.T) {
	var stderr bytes.Buffer

	opts, _, err := ParseGlobalFlags([]string{"--rate", "0"}, &stderr)
	if err != nil {
		t.Fatalf("ParseGlobalFlags() error = %v", err)
	}

	if !opts.Explicit["rate"] {
		t.Error(`Explicit["rate"] = false, want true for an explicit --rate 0`)
	}

	optsAbsent, _, err := ParseGlobalFlags(nil, &stderr)
	if err != nil {
		t.Fatalf("ParseGlobalFlags() error = %v", err)
	}

	if optsAbsent.Explicit["rate"] {
		t.Error(`Explicit["rate"] = true, want false when --rate was omitted`)
	}
}

func TestExplicitFlagsCoverEveryGlobalFlag(t *testing.T) {
	var stderr bytes.Buffer

	args := []string{
		"--config", "frank.json",
		"--output", "/tmp/out",
		"--json",
		"--verbose",
		"--dry-run",
		"--rate", "3",
		"--confirm-send", "recipient@example.com",
		"--redact", "secret",
	}

	opts, _, err := ParseGlobalFlags(args, &stderr)
	if err != nil {
		t.Fatalf("ParseGlobalFlags() error = %v", err)
	}

	for _, name := range []string{"config", "output", "json", "verbose", "dry-run", "rate", "confirm-send", "redact"} {
		if !opts.Explicit[name] {
			t.Errorf("Explicit[%q] = false, want true", name)
		}
	}

	optsAbsent, _, err := ParseGlobalFlags(nil, &stderr)
	if err != nil {
		t.Fatalf("ParseGlobalFlags() error = %v", err)
	}
	if len(optsAbsent.Explicit) != 0 {
		t.Errorf("Explicit = %v, want empty when no flags were given", optsAbsent.Explicit)
	}
}

func TestCodeString(t *testing.T) {
	tests := []struct {
		code Code
		want string
	}{
		{CodeAcceptance, "acceptance"},
		{CodeRejection, "rejection"},
		{CodeIncomplete, "incomplete"},
		{CodeUsage, "usage"},
		{CodeInconclusive, "inconclusive"},
	}

	for _, tt := range tests {
		if got := tt.code.String(); got != tt.want {
			t.Errorf("Code(%d).String() = %q, want %q", tt.code, got, tt.want)
		}
	}
}

// TestEveryVerbRoutesToItsOwnHandler is criterion 1.2 now that no verb is
// stubbed: each verb must reach its own command and report on its own terms.
// A verb that fell through to the default branch would say "unknown verb".
func TestEveryVerbRoutesToItsOwnHandler(t *testing.T) {
	// Each verb, given no flags, refuses with a message only that verb emits.
	want := map[string]string{
		"probe":   "--target",
		"auth":    "--envelope-from",
		"matrix":  "--target",
		"explain": "transcript",
	}

	for _, verb := range verbs {
		t.Run(verb, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			got := Main([]string{verb}, &stdout, &stderr)

			if got != CodeUsage {
				t.Errorf("code = %v, want %v for a verb given no flags", got, CodeUsage)
			}
			out := stderr.String()
			if strings.Contains(out, "unknown verb") {
				t.Fatalf("%q fell through to the default branch: %s", verb, out)
			}
			if !strings.Contains(out, "frank "+verb) {
				t.Errorf("stderr = %q, want it to name the verb that refused", out)
			}
			if !strings.Contains(out, want[verb]) {
				t.Errorf("stderr = %q, want %q from %s's own handler", out, want[verb], verb)
			}
		})
	}
}
