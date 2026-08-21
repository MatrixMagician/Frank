// Package resolve is the DNS seam (issue #7). It defines the Resolver
// interface that both a pure-Go standard-library implementation (System) and
// an in-memory, network-free implementation (Zone) satisfy, so every
// authentication package above it (spf, dkim, dmarc) is testable offline.
package resolve

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

// MX is one mail-exchanger record: a preference and a host name. Named
// fields rather than net.MX's so this package never re-exports a standard
// library type across the seam.
type MX struct {
	Host string
	Pref uint16
}

// Resolver is the DNS seam. Every method takes a context and a name (or, for
// LookupPTR, an address) and returns the record data or an *Error whose Kind
// states which of the four DNS-shaped facts happened: the name does not
// exist, the name exists but has no record of this type, the query failed
// transiently, or the query failed permanently. Callers decide none, fail,
// permerror or temperror from Kind, never from a string match on Err.
type Resolver interface {
	// LookupTXT returns one entry per TXT record at name. Each entry is that
	// record's character-strings already concatenated with no separator, per
	// RFC 7208 §3.3: multiple entries mean multiple separate records at that
	// name, not multiple pieces of one record, and callers must not join or
	// otherwise recombine entries. Go's net.Resolver.LookupTXT already
	// performs the within-record concatenation the system implementation
	// relies on; the fixture resolver honours the same contract by doing the
	// concatenation itself at seed time (see Zone.TXTStrings).
	LookupTXT(ctx context.Context, name string) ([]string, error)

	// LookupAddr resolves both A and AAAA records for name in a single call,
	// returned together as netip.Addr values, each already .Unmap()'d per
	// ADR-0006. SPF's `a` mechanism matches a Candidate Sending IP against
	// whichever family it turns out to be, so one call returning both
	// families is what every caller needs; two separate methods would just
	// make every caller call both and merge the slices itself.
	LookupAddr(ctx context.Context, name string) ([]netip.Addr, error)

	// LookupMX returns the mail-exchanger records for name, in no particular
	// order; callers sort by Pref if order matters to them.
	LookupMX(ctx context.Context, name string) ([]MX, error)

	// LookupPTR returns the reverse-DNS names for addr.
	LookupPTR(ctx context.Context, addr netip.Addr) ([]string, error)

	// LookupNS returns the authoritative nameserver host names for name.
	LookupNS(ctx context.Context, name string) ([]string, error)
}

// ErrorKind is the closed set of facts a DNS query can establish. It exists
// so "no SPF record" is decided by which of these four happened rather than
// by matching text in an error, which issue #7 requires explicitly.
type ErrorKind int

const (
	// KindNotFound means the name itself does not exist (NXDOMAIN).
	KindNotFound ErrorKind = iota
	// KindNoRecords means the name exists but has no record of the queried type (NODATA).
	KindNoRecords
	// KindTemporary means the query failed in a way worth retrying: timeout, SERVFAIL.
	KindTemporary
	// KindPermanent means the query failed in a way not worth retrying: malformed response, refused.
	KindPermanent
)

func (k ErrorKind) String() string {
	switch k {
	case KindNotFound:
		return "not found"
	case KindNoRecords:
		return "no records"
	case KindTemporary:
		return "temporary failure"
	case KindPermanent:
		return "permanent failure"
	default:
		return "unknown error kind"
	}
}

// Error is the closed error type every Resolver implementation returns.
// Name and Type identify the query that was made, Kind states the fact
// established about it, and Err carries the underlying cause when there is
// one worth keeping (nil for a fixture's KindNotFound / KindNoRecords).
type Error struct {
	Kind ErrorKind
	Name string
	Type string
	Err  error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("resolve %s %s: %s: %v", e.Type, e.Name, e.Kind, e.Err)
	}
	return fmt.Sprintf("resolve %s %s: %s", e.Type, e.Name, e.Kind)
}

func (e *Error) Unwrap() error { return e.Err }

// Is compares only Kind, which is what lets a caller write
// errors.Is(err, resolve.ErrNotFound) against an Error carrying a specific
// Name, Type and Err.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.Kind == t.Kind
}

// Sentinel errors for use with errors.Is. Only Kind is compared, so these
// match any *Error of that Kind regardless of Name, Type or Err.
var (
	ErrNotFound  = &Error{Kind: KindNotFound}
	ErrNoRecords = &Error{Kind: KindNoRecords}
	ErrTemporary = &Error{Kind: KindTemporary}
	ErrPermanent = &Error{Kind: KindPermanent}
)

// IsNotFound reports whether err is a resolve.Error of KindNotFound (NXDOMAIN).
func IsNotFound(err error) bool { return kindIs(err, KindNotFound) }

// IsNoRecords reports whether err is a resolve.Error of KindNoRecords (NODATA).
func IsNoRecords(err error) bool { return kindIs(err, KindNoRecords) }

// IsTemporary reports whether err is a resolve.Error of KindTemporary (retryable, temperror).
func IsTemporary(err error) bool { return kindIs(err, KindTemporary) }

// IsPermanent reports whether err is a resolve.Error of KindPermanent (permerror).
func IsPermanent(err error) bool { return kindIs(err, KindPermanent) }

func kindIs(err error, k ErrorKind) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind == k
	}
	return false
}
