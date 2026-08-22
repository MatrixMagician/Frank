package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/MatrixMagician/Frank/internal/dkim"
	"github.com/MatrixMagician/Frank/internal/dmarc"
	"github.com/MatrixMagician/Frank/internal/resolve"
	"github.com/MatrixMagician/Frank/internal/spf"
)

// authOptions are the verb's own flags. The resolver is a field so a test can
// substitute a zone fixture without opening a socket, which is what proves
// `auth` makes no TCP connection.
type authOptions struct {
	envelopeFrom string
	helo         string
	headerFrom   string
	clientIP     string
	dkimDomain   string
	dkimPass     bool
	selectors    []string
	resolver     resolve.Resolver
}

func runAuth(opts *Options, args []string, stdout, stderr io.Writer) Code {
	var a authOptions
	fs := flag.NewFlagSet("frank auth", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&a.envelopeFrom, "envelope-from", "", "the Envelope Sender to evaluate SPF for")
	fs.StringVar(&a.helo, "helo", "", "the HELO Identity, and SPF's subject when the Envelope Sender is null")
	fs.StringVar(&a.headerFrom, "header-from", "", "the Header From, which DMARC aligns against")
	fs.StringVar(&a.clientIP, "client-ip", "", "the Candidate Sending IP to evaluate against")
	fs.StringVar(&a.dkimDomain, "dkim-domain", "", "a DKIM signing domain to compute alignment for")
	fs.BoolVar(&a.dkimPass, "dkim-pass", false, "treat the supplied DKIM signing domain as having verified")
	selectors := (*repeatable)(&a.selectors)
	fs.Var(selectors, "selector", "a DKIM selector to probe in addition to the built-in list, repeatable")

	if err := fs.Parse(args); err != nil {
		return CodeUsage
	}
	if a.envelopeFrom == "" && a.helo == "" && a.headerFrom == "" {
		fmt.Fprintln(stderr, "frank auth: give at least one of --envelope-from, --helo or --header-from")
		return CodeUsage
	}
	a.selectors = append(a.selectors, opts.Selectors...)

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

	code := CodeAcceptance

	var spfResult *spf.Result
	if a.envelopeFrom != "" || a.helo != "" {
		res, err := spf.Evaluate(ctx, r, req)
		if err != nil {
			fmt.Fprintf(stderr, "frank auth: %v\n", err)
			return CodeIncomplete
		}
		spfResult = res
		fmt.Fprintln(stdout, "== SPF ==")
		if err := spf.RenderTree(stdout, res); err != nil {
			fmt.Fprintf(stderr, "frank auth: %v\n", err)
			return CodeIncomplete
		}
		if res.Verdict == spf.TempError {
			code = CodeIncomplete
		}
	}

	headerFromDomain := domainOf(a.headerFrom)
	dkimDomain := headerFromDomain
	if dkimDomain == "" {
		dkimDomain = domainOf(a.envelopeFrom)
	}

	if dkimDomain != "" {
		res, err := dkim.Discover(ctx, r, dkimDomain, dkim.Options{Selectors: a.selectors})
		if err != nil {
			fmt.Fprintf(stderr, "frank auth: %v\n", err)
			return CodeIncomplete
		}
		fmt.Fprintln(stdout, "\n== DKIM ==")
		fmt.Fprint(stdout, dkim.Render(res))
	}

	if headerFromDomain != "" {
		in := dmarc.Input{
			HeaderFromDomain: headerFromDomain,
			DKIMDomain:       a.dkimDomain,
			DKIMPass:         a.dkimPass,
		}
		if spfResult != nil {
			in.SPF = *spfResult
		}
		res, err := dmarc.Evaluate(ctx, r, in)
		if err != nil {
			fmt.Fprintf(stderr, "frank auth: %v\n", err)
			return CodeIncomplete
		}
		fmt.Fprintln(stdout, "\n== DMARC ==")
		fmt.Fprint(stdout, dmarc.Render(res))
	}

	return code
}

// domainOf takes the domain half of an address, or returns the input when it
// is already a bare domain.
func domainOf(addr string) string {
	if addr == "" {
		return ""
	}
	if _, d, ok := strings.Cut(addr, "@"); ok {
		return d
	}
	return addr
}
