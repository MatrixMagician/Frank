package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"

	"github.com/MatrixMagician/Frank/internal/resolve"
	"github.com/MatrixMagician/Frank/internal/spf"
)

// authOptions are the verb's own flags. The resolver is a field so a test can
// substitute a zone fixture without opening a socket, which is what proves
// `auth` makes no TCP connection.
type authOptions struct {
	envelopeFrom string
	helo         string
	clientIP     string
	resolver     resolve.Resolver
}

func runAuth(opts *Options, args []string, stdout, stderr io.Writer) Code {
	var a authOptions
	fs := flag.NewFlagSet("frank auth", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&a.envelopeFrom, "envelope-from", "", "the Envelope Sender to evaluate SPF for")
	fs.StringVar(&a.helo, "helo", "", "the HELO Identity, and SPF's subject when the Envelope Sender is null")
	fs.StringVar(&a.clientIP, "client-ip", "", "the Candidate Sending IP to evaluate against")

	if err := fs.Parse(args); err != nil {
		return CodeUsage
	}
	if a.envelopeFrom == "" && a.helo == "" {
		fmt.Fprintln(stderr, "frank auth: give at least one of --envelope-from or --helo")
		return CodeUsage
	}

	return runAuthWith(context.Background(), opts, a, stdout, stderr)
}

func runAuthWith(ctx context.Context, opts *Options, a authOptions, stdout, stderr io.Writer) Code {
	req := spf.Request{EnvelopeSender: a.envelopeFrom, HeloIdentity: a.helo}

	// Per ADR-0002 there is no Source Address to default to here, because auth
	// opens no connection. Without --client-ip the Verdict stays not evaluated
	// rather than being computed against an invented IP.
	if a.clientIP != "" {
		addr, err := netip.ParseAddr(a.clientIP)
		if err != nil {
			fmt.Fprintf(stderr, "frank auth: --client-ip %q is not an ip address\n", a.clientIP)
			return CodeUsage
		}
		ip, err := spf.NewCandidateSendingIP(addr, false)
		if err != nil {
			fmt.Fprintf(stderr, "frank auth: %v\n", err)
			return CodeUsage
		}
		req.ClientIP = &ip
	}

	r := a.resolver
	if r == nil {
		r = resolve.NewSystem()
	}

	res, err := spf.Evaluate(ctx, r, req)
	if err != nil {
		fmt.Fprintf(stderr, "frank auth: %v\n", err)
		return CodeIncomplete
	}

	if err := spf.RenderTree(stdout, res); err != nil {
		fmt.Fprintf(stderr, "frank auth: %v\n", err)
		return CodeIncomplete
	}

	if res.Verdict == spf.TempError {
		return CodeIncomplete
	}
	return CodeAcceptance
}
