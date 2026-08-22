package cli

import (
	"bytes"
	"net"
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

func TestProbeDefaultsToDryRunWithoutConfirmSend(t *testing.T) {
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

	if got != CodeAcceptance {
		t.Errorf("Main() code = %v, want %v\nstderr: %s", got, CodeAcceptance, stderr.String())
	}
	if len(srv.Received()) != 0 {
		t.Error("message was transmitted without --confirm-send, want a dry run")
	}
}

func TestProbeRequiresIdentityFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer

	got := Main([]string{"probe", "--target", "example.invalid:25"}, &stdout, &stderr)

	if got != CodeUsage {
		t.Errorf("Main() code = %v, want %v", got, CodeUsage)
	}
}
