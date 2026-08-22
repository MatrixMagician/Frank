package resolve

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestSystemResolverSatisfiesInterface is a compile-time assertion (the
// var _ Resolver = (*System)(nil) in system.go already enforces this) plus a
// construction test. It deliberately never calls a Lookup method: this
// package's TestMain forbids network access, and a System resolver
// constructed but never queried is the proof that construction alone is
// side-effect free.
func TestSystemResolverSatisfiesInterface(t *testing.T) {
	var r Resolver = NewSystem()
	if r == nil {
		t.Fatal("NewSystem returned nil")
	}
	sys, ok := r.(*System)
	if !ok {
		t.Fatalf("NewSystem() did not return a *System, got %T", r)
	}
	if !sys.resolver.PreferGo {
		t.Fatal("System resolver must set PreferGo, per ADR-0006 and issue #7 (pure-Go, no CGO)")
	}
}

func TestSystemClassifyWrapsNonDNSError(t *testing.T) {
	sys := NewSystem()
	err := sys.classify(context.Background(), net.InvalidAddrError("bad"), "example.com", "TXT")
	if !IsPermanent(err) {
		t.Fatalf("expected KindPermanent for a non-DNSError, got %v", err)
	}
}

func TestForbidNetworkAlsoBlocksTheSystemResolver(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s := NewSystem()
	for _, tc := range []struct {
		name  string
		query func() error
	}{
		{"TXT", func() error { _, err := s.LookupTXT(ctx, "example.com"); return err }},
		{"A/AAAA", func() error { _, err := s.LookupAddr(ctx, "example.com"); return err }},
		{"MX", func() error { _, err := s.LookupMX(ctx, "example.com"); return err }},
		{"NS", func() error { _, err := s.LookupNS(ctx, "example.com"); return err }},
		{"PTR", func() error { _, err := s.LookupPTR(ctx, netip.MustParseAddr("192.0.2.1")); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.query()
			if err == nil {
				t.Fatal("query succeeded, so it reached a real DNS server despite ForbidNetwork")
			}
			if !strings.Contains(err.Error(), "network access forbidden") {
				t.Fatalf("err = %v, want the ForbidNetwork guard to have refused the dial", err)
			}
		})
	}
}
