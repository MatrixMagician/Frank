package cli

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/MatrixMagician/Frank/internal/report"
	"github.com/MatrixMagician/Frank/internal/version"
)

// applyConfig fills in every global setting the operator did not give
// explicitly. An explicit flag always wins, which is why this consults the
// Explicit set rather than checking for a zero value.
func applyConfig(opts *Options, cfg *report.Config) {
	opts.Output = report.StringOr(opts.Explicit["output"], opts.Output, cfg.Output)
	if !opts.Explicit["rate"] && cfg.Rate != nil {
		opts.Rate = *cfg.Rate
		opts.Explicit["rate"] = true
	}
	opts.Redact = report.StringsOr(opts.Redact, cfg.Redact)
	opts.Selectors = report.StringsOr(opts.Selectors, cfg.Selectors)
}

// repeatable is a flag.Value that accumulates every occurrence, for the flags
// SPEC.md documents as repeatable: --redact and --selector.
type repeatable []string

func (r *repeatable) String() string {
	return strings.Join(*r, ",")
}

func (r *repeatable) Set(value string) error {
	*r = append(*r, value)
	return nil
}

type Options struct {
	Config      string
	Output      string
	JSON        bool
	Verbose     bool
	DryRun      bool
	Rate        int
	ConfirmSend string
	Redact      []string
	Selectors   []string
	Version     bool
	// File is the decoded config, kept so a verb can read the settings that
	// have no global flag of their own.
	File     *report.Config
	Help     bool
	Explicit map[string]bool
}

var verbs = []string{"probe", "auth", "matrix", "explain"}

func newFlagSet(stderr io.Writer, opts *Options) *flag.FlagSet {
	fs := flag.NewFlagSet("frank", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.StringVar(&opts.Config, "config", "", "path to config file")
	fs.StringVar(&opts.Output, "output", "", "output directory")
	fs.BoolVar(&opts.JSON, "json", false, "emit JSON to stdout")
	fs.BoolVar(&opts.Verbose, "verbose", false, "verbose logging")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "stop before issuing DATA")
	fs.IntVar(&opts.Rate, "rate", 0, "connections per minute")
	fs.StringVar(&opts.ConfirmSend, "confirm-send", "", "recipient confirming a real send")
	fs.Var((*repeatable)(&opts.Redact), "redact", "regexp to redact from rendered output, repeatable")
	fs.Var((*repeatable)(&opts.Selectors), "selector", "DKIM selector to probe in addition to the built-in list, repeatable")
	fs.BoolVar(&opts.Version, "version", false, "print the version and exit")
	fs.BoolVar(&opts.Help, "help", false, "print usage and exit")

	return fs
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: frank [global flags] <verb> [verb flags]")
	fmt.Fprintln(w, "verbs:")
	sorted := append([]string(nil), verbs...)
	sort.Strings(sorted)
	for _, v := range sorted {
		fmt.Fprintf(w, "  %s\n", v)
	}
	fmt.Fprintln(w, "global flags:")
	newFlagSet(w, &Options{}).PrintDefaults()
}

func ParseGlobalFlags(args []string, stderr io.Writer) (*Options, []string, error) {
	opts := &Options{Explicit: map[string]bool{}}
	fs := newFlagSet(stderr, opts)

	if err := fs.Parse(args); err != nil {
		return opts, nil, err
	}

	fs.Visit(func(f *flag.Flag) {
		opts.Explicit[f.Name] = true
	})

	return opts, fs.Args(), nil
}

func Main(args []string, stdout, stderr io.Writer) Code {
	opts, rest, err := ParseGlobalFlags(args, stderr)
	if err != nil {
		usage(stderr)
		return CodeUsage
	}

	if opts.Help {
		usage(stdout)
		return CodeAcceptance
	}

	if opts.Version {
		fmt.Fprintln(stdout, version.Version)
		return CodeAcceptance
	}

	if opts.Config != "" {
		cfg, err := report.Load(opts.Config)
		if err != nil {
			fmt.Fprintf(stderr, "frank: %v\n", err)
			return CodeUsage
		}
		opts.File = cfg
		applyConfig(opts, cfg)
	}

	if len(rest) == 0 {
		usage(stderr)
		return CodeUsage
	}

	verb, verbArgs := rest[0], rest[1:]

	switch verb {
	case "probe":
		return probeCmd(opts, verbArgs, stdout, stderr)
	case "auth":
		return runAuth(opts, verbArgs, stdout, stderr)
	case "matrix":
		return matrixCmd(opts, verbArgs, stdout, stderr)
	case "explain":
		return explainCmd(opts, verbArgs, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "frank: unknown verb %q\n", verb)
		usage(stderr)
		return CodeUsage
	}
}

func notImplemented(verb string, stderr io.Writer) Code {
	fmt.Fprintf(stderr, "frank %s: not implemented\n", verb)
	return CodeUsage
}
