package cli

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/MatrixMagician/Frank/internal/smtpconv"
	"github.com/MatrixMagician/Frank/internal/transcript"
)

const defaultSMTPPort = "25"
const dialTimeout = 30 * time.Second

type probeFlags struct {
	target     string
	envFrom    string
	helo       string
	headerFrom string
	recipient  string
	tlsMode    string
	tlsVerify  bool
	serverName string
}

func newProbeFlagSet(stderr io.Writer, pf *probeFlags) *flag.FlagSet {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&pf.target, "target", "", "target host (or host:port) to probe")
	fs.StringVar(&pf.envFrom, "envelope-from", "", "MAIL FROM address, or <> for the null sender")
	fs.StringVar(&pf.helo, "helo", "", "EHLO/HELO identity")
	fs.StringVar(&pf.headerFrom, "header-from", "", "Probe Message From: header address")
	fs.StringVar(&pf.recipient, "recipient", "", "the single RCPT TO address")
	fs.StringVar(&pf.tlsMode, "tls", "prefer", "starttls policy: prefer, require or none")
	fs.BoolVar(&pf.tlsVerify, "tls-verify", false, "abort when certificate verification fails; the chain is captured and verified either way")
	fs.StringVar(&pf.serverName, "tls-server-name", "", "name to verify the certificate against, defaulting to the target host")
	return fs
}

// probeCmd wires the frank probe verb to internal/smtpconv: it parses the
// probe's own flags, conducts one Probe, renders the resulting Transcript,
// and maps the Outcome to an exit Code.
func probeCmd(opts *Options, args []string, stdout, stderr io.Writer) Code {
	pf := &probeFlags{}
	fs := newProbeFlagSet(stderr, pf)
	if err := fs.Parse(args); err != nil {
		return CodeUsage
	}

	if pf.target == "" || pf.envFrom == "" || pf.helo == "" || pf.headerFrom == "" || pf.recipient == "" {
		fmt.Fprintln(stderr, "frank probe: --target, --envelope-from, --helo, --header-from and --recipient are all required")
		return CodeUsage
	}

	target, err := normalizeTarget(pf.target)
	if err != nil {
		fmt.Fprintf(stderr, "frank probe: %v\n", err)
		return CodeUsage
	}

	envelopeSender := smtpconv.NewEnvelopeSender(pf.envFrom)
	if pf.envFrom == "<>" {
		envelopeSender = smtpconv.NullEnvelopeSender()
	}

	tlsMode, err := smtpconv.ParseTLSMode(pf.tlsMode)
	if err != nil {
		fmt.Fprintf(stderr, "frank probe: %v\n", err)
		return CodeUsage
	}

	dryRun := opts.DryRun || opts.ConfirmSend == ""

	cfg := smtpconv.Config{
		TargetHost: target,
		Identities: smtpconv.Identities{
			EnvelopeSender: envelopeSender,
			HeloIdentity:   pf.helo,
			HeaderFrom:     pf.headerFrom,
		},
		Recipient:     smtpconv.Recipient(pf.recipient),
		DryRun:        dryRun,
		DialTimeout:   dialTimeout,
		TLSMode:       tlsMode,
		TLSVerify:     pf.tlsVerify,
		TLSServerName: pf.serverName,
	}

	// ADR-0007: credentials come from the environment or the config file and
	// never from a flag, because argv is world-readable through /proc.
	creds, _ := smtpconv.CredentialsFromEnv()
	cfg.Credentials = creds

	res := smtpconv.Run(cfg)

	redactor, err := transcript.NewRedactor(opts.Redact)
	if err != nil {
		fmt.Fprintf(stderr, "frank probe: %v\n", err)
		return CodeUsage
	}
	smtpconv.RegisterCredentials(redactor, creds)

	if res.Transcript != nil {
		if err := writeReports(opts.Output, res.Transcript, redactor); err != nil {
			fmt.Fprintf(stderr, "frank probe: %v\n", err)
		}
		if opts.JSON {
			transcript.RenderJSON(stdout, res.Transcript, redactor)
		} else {
			transcript.RenderText(stdout, res.Transcript, redactor)
		}
	}

	if res.Err != nil {
		fmt.Fprintf(stderr, "frank probe: %v\n", res.Err)
	}

	return mapResultToCode(res)
}

// normalizeTarget appends the default SMTP port when target names a host
// with none, and leaves an already-qualified host:port alone.
func normalizeTarget(target string) (string, error) {
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target, nil
	}
	return net.JoinHostPort(target, defaultSMTPPort), nil
}

// mapResultToCode maps a smtpconv.Result to the exit Code that is Frank's
// contract with a script: 0 Acceptance, 1 Rejection, 2 could not complete,
// 4 Inconclusive (Deferral). A Result with neither an Outcome nor an error
// completed the walk it was asked to make (a dry run stopping cleanly before
// RCPT TO) without anything going wrong, which is CodeAcceptance.
func mapResultToCode(res *smtpconv.Result) Code {
	if res.Err != nil {
		return CodeIncomplete
	}
	if res.Outcome == nil {
		return CodeAcceptance
	}
	switch res.Outcome.Kind() {
	case smtpconv.OutcomeAcceptance:
		return CodeAcceptance
	case smtpconv.OutcomeRejection:
		return CodeRejection
	case smtpconv.OutcomeDeferral:
		return CodeInconclusive
	default:
		return CodeIncomplete
	}
}

// writeReports writes both the human-readable log and the JSON document to
// dir (or a default UTC-timestamped directory), per SPEC.md's "--output":
// both artefacts are always written, regardless of --json.
func writeReports(dir string, tr *transcript.Transcript, r *transcript.Redactor) error {
	if dir == "" {
		dir = "frank-" + time.Now().UTC().Format("20060102T150405Z")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	textFile, err := os.Create(filepath.Join(dir, "transcript.txt"))
	if err != nil {
		return fmt.Errorf("create transcript.txt: %w", err)
	}
	defer textFile.Close()
	if err := transcript.RenderText(textFile, tr, r); err != nil {
		return fmt.Errorf("render transcript.txt: %w", err)
	}

	jsonFile, err := os.Create(filepath.Join(dir, "transcript.json"))
	if err != nil {
		return fmt.Errorf("create transcript.json: %w", err)
	}
	defer jsonFile.Close()
	if err := transcript.RenderJSON(jsonFile, tr, r); err != nil {
		return fmt.Errorf("render transcript.json: %w", err)
	}

	return nil
}
