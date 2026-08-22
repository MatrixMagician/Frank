package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// dialDNS is the single point through which every System resolver reaches the
// network. It is a package variable so ForbidNetwork can replace it in tests:
// a System builds its own net.Resolver, so a hook on net.DefaultResolver would
// leave this path open and the suite could still make a real query.
var dialDNS func(ctx context.Context, network, address string) (net.Conn, error)

// System is the Resolver backed by the standard library's DNS client. It
// forces PreferGo so the pure-Go resolver is used even on a platform or
// build where cgo is available, per ADR-0006 and issue #7: the shipped
// binary is already CGO_ENABLED=0, but PreferGo makes that explicit and
// correct regardless of how the binary happens to be built.
type System struct {
	resolver *net.Resolver
}

// NewSystem returns a System resolver. It performs no I/O; the network is
// only touched when a Lookup method is called.
func NewSystem() *System {
	return &System{resolver: &net.Resolver{PreferGo: true, Dial: dialDNS}}
}

var _ Resolver = (*System)(nil)

func (s *System) LookupTXT(ctx context.Context, name string) ([]string, error) {
	txt, err := s.resolver.LookupTXT(ctx, name)
	if err != nil {
		return nil, s.classify(ctx, err, name, "TXT")
	}
	return txt, nil
}

func (s *System) LookupAddr(ctx context.Context, name string) ([]netip.Addr, error) {
	addrs, err := s.resolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, s.classify(ctx, err, name, "A/AAAA")
	}
	out := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		out[i] = a.Unmap()
	}
	return out, nil
}

func (s *System) LookupMX(ctx context.Context, name string) ([]MX, error) {
	records, err := s.resolver.LookupMX(ctx, name)
	if err != nil {
		return nil, s.classify(ctx, err, name, "MX")
	}
	out := make([]MX, len(records))
	for i, r := range records {
		out[i] = MX{Host: r.Host, Pref: r.Pref}
	}
	return out, nil
}

func (s *System) LookupPTR(ctx context.Context, addr netip.Addr) ([]string, error) {
	names, err := s.resolver.LookupAddr(ctx, addr.String())
	if err != nil {
		return nil, s.classify(ctx, err, addr.String(), "PTR")
	}
	return names, nil
}

func (s *System) LookupNS(ctx context.Context, name string) ([]string, error) {
	records, err := s.resolver.LookupNS(ctx, name)
	if err != nil {
		return nil, s.classify(ctx, err, name, "NS")
	}
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = r.Host
	}
	return out, nil
}

// classify turns a stdlib DNS error into a *resolve.Error with a Kind
// decided by the query that produced it, per issue #7.
func (s *System) classify(ctx context.Context, err error, name, typ string) error {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return &Error{Kind: KindPermanent, Name: name, Type: typ, Err: err}
	}
	switch {
	case dnsErr.IsTimeout || dnsErr.IsTemporary:
		return &Error{Kind: KindTemporary, Name: name, Type: typ, Err: err}
	case dnsErr.IsNotFound:
		return &Error{Kind: s.disambiguateNotFound(ctx, name, typ), Name: name, Type: typ, Err: err}
	default:
		return &Error{Kind: KindPermanent, Name: name, Type: typ, Err: err}
	}
}

// disambiguateNotFound is the honest, documented answer to the NXDOMAIN vs
// NODATA problem. net.DNSError.IsNotFound is true for both: the name does
// not exist at all, and the name exists but has no record of the queried
// type. The system resolver cannot tell those apart from the failed query's
// error alone, so it asks a second, different question of the same name:
// does the name resolve at all (LookupHost), or, for an address query where
// LookupHost is the query that just failed, does it have a nameserver
// delegation (LookupNS). If that second query succeeds, the name exists and
// the original failure was NODATA (KindNoRecords). If the second query also
// reports not-found, the name itself does not exist (KindNotFound).
//
// This is still a heuristic, not a certainty: a name with only a TXT record
// and no A/AAAA and no NS delegation record will make the secondary query
// fail not-found too, misclassifying a real NODATA as NotFound. PTR queries
// get no secondary query at all: the standard library exposes no query that
// distinguishes a missing reverse delegation from an address with no PTR
// record, so an ambiguous PTR failure is reported as KindNoRecords, the
// overwhelmingly common real-world case for that query. Both simplifications
// are stated here rather than left to be discovered by a wrong Verdict.
func (s *System) disambiguateNotFound(ctx context.Context, name, typ string) ErrorKind {
	if typ == "PTR" {
		return KindNoRecords
	}

	var secondaryErr error
	if typ == "A/AAAA" {
		_, secondaryErr = s.resolver.LookupNS(ctx, name)
	} else {
		_, secondaryErr = s.resolver.LookupHost(ctx, name)
	}
	if secondaryErr == nil {
		return KindNoRecords
	}
	var dnsErr *net.DNSError
	if errors.As(secondaryErr, &dnsErr) && dnsErr.IsNotFound {
		return KindNotFound
	}
	// The secondary query failed for some other reason (timeout, SERVFAIL):
	// existence could not be established either way. Report KindTemporary
	// rather than guessing, so a flaky secondary query becomes a temperror
	// instead of a confidently wrong none or permerror.
	return KindTemporary
}
