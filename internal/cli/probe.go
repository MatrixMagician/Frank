package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/MatrixMagician/Frank/internal/explain"
	"github.com/MatrixMagician/Frank/internal/gate"
	"github.com/MatrixMagician/Frank/internal/report"
	"github.com/MatrixMagician/Frank/internal/resolve"
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

	// The rate is resolved first: a refused rate is a flag error the operator
	// can fix, and asking the confirmation question first would hide it behind
	// an unrelated message.
	var ratePtr *int
	if opts.Explicit["rate"] {
		ratePtr = &opts.Rate
	}
	rate, err := gate.ResolveRate(ratePtr)
	if err != nil {
		fmt.Fprintf(stderr, "frank probe: %v\n", err)
		return CodeUsage
	}

	// The gate runs before anything is dialed, so a run that would have to
	// prompt with no terminal errors before the target is touched.
	decision, err := gate.Decide(gate.Input{
		DryRunRequested: opts.DryRun,
		ConfirmSend:     opts.ConfirmSend,
		Recipient:       pf.recipient,
		StdinIsTerminal: gate.StdinIsTerminal(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "frank probe: %v\n", err)
		return CodeUsage
	}
	limiter := gate.NewLimiter(rate, clockFor(opts))
	if err := limiter.Wait(context.Background()); err != nil {
		fmt.Fprintf(stderr, "frank probe: %v\n", err)
		return CodeIncomplete
	}

	dryRun := decision.Disposition == gate.DispositionDryRun

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
	creds := credentials(opts)
	cfg.Credentials = creds

	res := smtpconv.Run(cfg)
	if res.Transcript != nil {
		res.Transcript.Append(transcript.KindNote, transcript.PhaseDial, nil).Note =
			"send disposition: " + decision.Disposition.String() + ", " + decision.Reason
	}

	redactor, err := transcript.NewRedactor(opts.Redact)
	if err != nil {
		fmt.Fprintf(stderr, "frank probe: %v\n", err)
		return CodeUsage
	}
	smtpconv.RegisterCredentials(redactor, creds)

	if res.Transcript != nil {
		// The report carries the Verdicts as well as the Outcomes, so a reader
		// gets the same synthesis `frank explain` would give without having to
		// run a second command against the file they were just handed.
		in := explain.Input{Transcript: res.Transcript}
		if err := populateVerdicts(context.Background(), &in, res.Transcript, explainFlags{}, resolve.NewSystem()); err != nil {
			fmt.Fprintf(stderr, "frank probe: %v\n", err)
		}
		diagnosis := explain.Diagnose(in)
		rep := &report.Report{
			GeneratedAt: time.Now().UTC(),
			Command:     "frank probe --target " + target,
			Transcript:  res.Transcript,
			Redactor:    redactor,
			SPF:         in.SPF,
			DMARC:       in.DMARC,
			Diagnosis:   &diagnosis,
		}
		if err := writeReports(opts.Output, res.Transcript, redactor, rep); err != nil {
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
// credentials reads SMTP AUTH credentials from the environment, falling back
// to the config file. Never from a flag: argv is world-readable through /proc
// and lands verbatim in shell history. See ADR-0007.
func credentials(opts *Options) smtpconv.Credentials {
	if creds, ok := smtpconv.CredentialsFromEnv(); ok {
		return creds
	}
	if opts.File == nil {
		return smtpconv.Credentials{}
	}
	var creds smtpconv.Credentials
	if opts.File.Username != nil {
		creds.Username = *opts.File.Username
	}
	if opts.File.Password != nil {
		creds.Password = *opts.File.Password
	}
	return creds
}

func writeReports(dir string, tr *transcript.Transcript, r *transcript.Redactor, rep *report.Report) error {
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

	// Both renderings of the combined report always land here too. --json
	// changes only what reaches standard output, never what is written.
	if rep != nil {
		if _, _, err := rep.Write(dir); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}

	return nil
}
