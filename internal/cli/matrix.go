package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/MatrixMagician/Frank/internal/gate"
	"github.com/MatrixMagician/Frank/internal/matrix"
	"github.com/MatrixMagician/Frank/internal/smtpconv"
)

type matrixFlags struct {
	target     string
	envFrom    []string
	helo       []string
	headerFrom []string
	recipient  string
	tlsMode    string
	tlsVerify  bool
	serverName string
}

func newMatrixFlagSet(stderr io.Writer, mf *matrixFlags) *flag.FlagSet {
	fs := flag.NewFlagSet("matrix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&mf.target, "target", "", "target host (or host:port) to sweep")
	fs.Var((*repeatable)(&mf.envFrom), "envelope-from", "an Envelope Sender to sweep, repeatable; <> for the null sender")
	fs.Var((*repeatable)(&mf.helo), "helo", "a HELO Identity to sweep, repeatable")
	fs.Var((*repeatable)(&mf.headerFrom), "header-from", "a Header From to sweep, repeatable")
	fs.StringVar(&mf.recipient, "recipient", "", "the single RCPT TO address, never varied")
	fs.StringVar(&mf.tlsMode, "tls", "prefer", "starttls policy: prefer, require or none")
	fs.BoolVar(&mf.tlsVerify, "tls-verify", false, "abort when certificate verification fails")
	fs.StringVar(&mf.serverName, "tls-server-name", "", "name to verify the certificate against")
	return fs
}

func matrixCmd(opts *Options, args []string, stdout, stderr io.Writer) Code {
	mf := &matrixFlags{}
	fs := newMatrixFlagSet(stderr, mf)
	if err := fs.Parse(args); err != nil {
		return CodeUsage
	}

	if mf.target == "" || mf.recipient == "" {
		fmt.Fprintln(stderr, "frank matrix: --target and --recipient are required")
		return CodeUsage
	}
	if len(mf.envFrom) == 0 || len(mf.helo) == 0 || len(mf.headerFrom) == 0 {
		fmt.Fprintln(stderr, "frank matrix: give at least one --envelope-from, one --helo and one --header-from")
		return CodeUsage
	}

	target, err := normalizeTarget(mf.target)
	if err != nil {
		fmt.Fprintf(stderr, "frank matrix: %v\n", err)
		return CodeUsage
	}

	tlsMode, err := smtpconv.ParseTLSMode(mf.tlsMode)
	if err != nil {
		fmt.Fprintf(stderr, "frank matrix: %v\n", err)
		return CodeUsage
	}

	// The rate is resolved before the send gate: a refused rate is a flag error
	// the operator can fix, and asking the confirmation question first would
	// hide it behind an unrelated message. matrix may lower the rate and can
	// never raise it, and the request is refused rather than clamped.
	var ratePtr *int
	if opts.Explicit["rate"] {
		ratePtr = &opts.Rate
	}
	rate, err := gate.ResolveRate(ratePtr)
	if err != nil {
		fmt.Fprintf(stderr, "frank matrix: %v\n", err)
		return CodeUsage
	}

	decision, err := gate.Decide(gate.Input{
		DryRunRequested: opts.DryRun,
		ConfirmSend:     opts.ConfirmSend,
		Recipient:       mf.recipient,
		StdinIsTerminal: gate.StdinIsTerminal(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "frank matrix: %v\n", err)
		return CodeUsage
	}
	limiter := gate.NewLimiter(rate, clockFor(opts))

	creds, _ := smtpconv.CredentialsFromEnv()

	m, err := matrix.Run(context.Background(), matrix.Config{
		TargetHost: target,
		Recipient:  mf.recipient,
		Slots: matrix.Slots{
			EnvelopeSenders: normalizeNullSenders(mf.envFrom),
			HeloIdentities:  mf.helo,
			HeaderFroms:     mf.headerFrom,
		},
		Base: smtpconv.Config{
			DryRun:        decision.Disposition == gate.DispositionDryRun,
			DialTimeout:   dialTimeout,
			TLSMode:       tlsMode,
			TLSVerify:     mf.tlsVerify,
			TLSServerName: mf.serverName,
			Credentials:   creds,
		},
		Limiter: limiter,
		Backoff: gate.NewBackoff(gate.BackoffConfig{}, clockFor(opts)),
	})
	if err != nil {
		fmt.Fprintf(stderr, "frank matrix: %v\n", err)
		return CodeUsage
	}

	if opts.JSON {
		matrix.RenderJSON(stdout, m)
	} else {
		matrix.Render(stdout, m)
	}

	return matrixCode(m)
}

// normalizeNullSenders maps the literal "<>" onto the empty string, so the null
// sender is one value throughout rather than two spellings of one.
func normalizeNullSenders(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		if strings.TrimSpace(v) == "<>" {
			out[i] = ""
			continue
		}
		out[i] = v
	}
	return out
}

// matrixCode is the sweep's contract with a script: 1 if any Cell was
// Rejected, otherwise 4 if any is Inconclusive or Unrun, otherwise 0.
func matrixCode(m *matrix.Matrix) Code {
	counts := m.Counts()
	switch {
	case counts[matrix.Rejected] > 0:
		return CodeRejection
	case counts[matrix.Inconclusive] > 0 || counts[matrix.Unrun] > 0:
		return CodeInconclusive
	default:
		return CodeAcceptance
	}
}
