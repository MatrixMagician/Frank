package cli

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/MatrixMagician/Frank/internal/smtptest"
)

func TestProbeExitCodes(t *testing.T) {
	baseArgs := func(target, outputDir string) []string {
		return []string{
			"--confirm-send", "rcpt@recipient.example",
			"--output", outputDir,
			"probe",
			"--target", target,
			"--envelope-from", "envelope@sender.example",
			"--helo", "client.helo.example",
			"--header-from", "header@from.example",
			"--recipient", "rcpt@recipient.example",
		}
	}

	t.Run("acceptance", func(t *testing.T) {
		srv := smtptest.Start(t)
		var stdout, stderr bytes.Buffer

		args := baseArgs(srv.Addr(), t.TempDir())
		got := Main(args, &stdout, &stderr)

		if got != CodeAcceptance {
			t.Errorf("Main() code = %v, want %v\nstderr: %s", got, CodeAcceptance, stderr.String())
		}
	})

	t.Run("rejection", func(t *testing.T) {
		srv := smtptest.Start(t, smtptest.Reject(smtptest.PhaseEndOfData, 550, "5.7.1", "no"))
		var stdout, stderr bytes.Buffer

		args := baseArgs(srv.Addr(), t.TempDir())
		got := Main(args, &stdout, &stderr)

		if got != CodeRejection {
			t.Errorf("Main() code = %v, want %v\nstderr: %s", got, CodeRejection, stderr.String())
		}
	})

	t.Run("deferral", func(t *testing.T) {
		srv := smtptest.Start(t, smtptest.Reject(smtptest.PhaseEndOfData, 450, "4.7.1", "try later"))
		var stdout, stderr bytes.Buffer

		args := baseArgs(srv.Addr(), t.TempDir())
		got := Main(args, &stdout, &stderr)

		if got != CodeInconclusive {
			t.Errorf("Main() code = %v, want %v\nstderr: %s", got, CodeInconclusive, stderr.String())
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := ln.Addr().String()
		ln.Close()

		var stdout, stderr bytes.Buffer
		args := baseArgs(addr, t.TempDir())
		got := Main(args, &stdout, &stderr)

		if got != CodeIncomplete {
			t.Errorf("Main() code = %v, want %v\nstderr: %s", got, CodeIncomplete, stderr.String())
		}
	})
}

func TestProbeDryRunTransmitsNothing(t *testing.T) {
	srv := smtptest.Start(t)
	var stdout, stderr bytes.Buffer

	args := []string{
		"--dry-run",
		"--output", t.TempDir(),
		"probe",
		"--target", srv.Addr(),
		"--envelope-from", "envelope@sender.example",
		"--helo", "client.helo.example",
		"--header-from", "header@from.example",
		"--recipient", "rcpt@recipient.example",
	}
	got := Main(args, &stdout, &stderr)

	if got != CodeAcceptance {
		t.Errorf("Main() code = %v, want %v\nstderr: %s", got, CodeAcceptance, stderr.String())
	}
	if len(srv.Received()) != 0 {
		t.Error("message was transmitted under --dry-run")
	}
	if !strings.Contains(stdout.String(), "rcpt-to") {
		t.Error("the dry run did not reach RCPT TO, but --dry-run walks the full protocol up to DATA")
	}
}

// TestProbeWithoutConfirmSendAndWithoutTerminalRefusesBeforeDialing is the CI
// safety rule: a run that would have to prompt errors instead of hanging, and
// it does so before the target is touched. Under `go test` stdin is never a
// terminal, which is exactly the case this asserts.
func TestProbeWithoutConfirmSendAndWithoutTerminalRefusesBeforeDialing(t *testing.T) {
	srv := smtptest.Start(t)
	var stdout, stderr bytes.Buffer

	args := []string{
		"--output", t.TempDir(),
		"probe",
		"--target", srv.Addr(),
		"--envelope-from", "envelope@sender.example",
		"--helo", "client.helo.example",
		"--header-from", "header@from.example",
		"--recipient", "rcpt@recipient.example",
	}
	got := Main(args, &stdout, &stderr)

	if got != CodeUsage {
		t.Errorf("Main() code = %v, want %v", got, CodeUsage)
	}
	if !strings.Contains(stderr.String(), "not a terminal") {
		t.Errorf("stderr = %q, want it to name the missing terminal", stderr.String())
	}
	if srv.ConnectionCount() != 0 {
		t.Errorf("the target was dialed %d times, want the refusal to happen first", srv.ConnectionCount())
	}
}

func TestProbeRequiresIdentityFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer

	got := Main([]string{"probe", "--target", "example.invalid:25"}, &stdout, &stderr)

	if got != CodeUsage {
		t.Errorf("Main() code = %v, want %v", got, CodeUsage)
	}
}
