package resolve

import (
	"context"
	"net/netip"
	"strings"
	"sync"
)

// QueryRecord is one entry in a Zone's query log: the name (or address, for
// PTR) queried and which record type was asked for. Issue #9 needs "the
// bound is stated in the output" for Selector Discovery's query volume, and
// this is what a test asserts the bound against.
type QueryRecord struct {
	Name string
	Type string
}

// Zone is the fixture Resolver: seeded from a table, no network access,
// deterministic. It implements Resolver directly, so a zone fixture is both
// the seeding API and the thing handed to code under test.
//
// Names are normalised case-insensitively with the trailing dot stripped, in
// normalizeName, the single place that rule is applied, so seeding and
// querying agree regardless of how either one was written.
type Zone struct {
	mu sync.Mutex

	txt   map[string][]string
	addrs map[string][]netip.Addr
	mx    map[string][]MX
	ns    map[string][]string
	ptr   map[netip.Addr][]string

	// seeded, nxdomain and temporary are keyed by normalizeName and cover
	// every domain-name-keyed record type (TXT, A/AAAA, MX, NS). PTR is
	// keyed by address instead and has no equivalent: an address with no
	// entry in ptr simply has no PTR record, which is the only fact there is
	// to state about a reverse lookup in this fixture.
	seeded    map[string]bool
	nxdomain  map[string]bool
	temporary map[string]bool

	queryCount int64
	queryLog   []QueryRecord
}

// NewZone returns an empty Zone, ready to be seeded.
func NewZone() *Zone {
	return &Zone{
		txt:       make(map[string][]string),
		addrs:     make(map[string][]netip.Addr),
		mx:        make(map[string][]MX),
		ns:        make(map[string][]string),
		ptr:       make(map[netip.Addr][]string),
		seeded:    make(map[string]bool),
		nxdomain:  make(map[string]bool),
		temporary: make(map[string]bool),
	}
}

var _ Resolver = (*Zone)(nil)

// normalizeName is the one place DNS name normalisation happens: lower-case,
// trailing dot stripped. Every seeding method and every lookup method goes
// through it, so "Example.com" and "example.com." are always the same key.
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// TXT seeds a single-character-string TXT record: one record, one string.
// Calling TXT or TXTStrings again for the same name adds a second, separate
// TXT record at that name; it does not replace the first.
func (z *Zone) TXT(name, value string) *Zone {
	return z.TXTStrings(name, value)
}

// TXTStrings seeds one TXT record made of several character-strings, joined
// with no separator, exactly as RFC 7208 §3.3 requires and exactly as
// net.Resolver.LookupTXT already delivers a real record. The concatenation
// happens here, once, at seed time, so nothing downstream can be tempted to
// re-join (or mis-join) the pieces themselves.
func (z *Zone) TXTStrings(name string, parts ...string) *Zone {
	key := normalizeName(name)
	z.mu.Lock()
	defer z.mu.Unlock()
	z.txt[key] = append(z.txt[key], strings.Join(parts, ""))
	z.seeded[key] = true
	return z
}

func mustParseAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic("resolve: invalid address " + s + ": " + err.Error())
	}
	return addr
}

// A seeds an IPv4 address for name. A and AAAA share one address list per
// name, since LookupAddr returns both families together.
func (z *Zone) A(name, ip string) *Zone {
	addr := mustParseAddr(ip)
	if addr.Is6() && !addr.Is4In6() {
		panic("resolve: A record value is not an ipv4 address: " + ip)
	}
	return z.addAddr(name, addr.Unmap())
}

// AAAA seeds an IPv6 address for name.
func (z *Zone) AAAA(name, ip string) *Zone {
	addr := mustParseAddr(ip)
	if addr.Is4() || addr.Is4In6() {
		panic("resolve: AAAA record value is not an ipv6 address: " + ip)
	}
	return z.addAddr(name, addr)
}

func (z *Zone) addAddr(name string, addr netip.Addr) *Zone {
	key := normalizeName(name)
	z.mu.Lock()
	defer z.mu.Unlock()
	z.addrs[key] = append(z.addrs[key], addr)
	z.seeded[key] = true
	return z
}

// MX seeds one mail-exchanger record for name.
func (z *Zone) MX(name string, pref uint16, host string) *Zone {
	key := normalizeName(name)
	z.mu.Lock()
	defer z.mu.Unlock()
	z.mx[key] = append(z.mx[key], MX{Host: host, Pref: pref})
	z.seeded[key] = true
	return z
}

// PTR seeds one or more reverse-DNS names for addr.
func (z *Zone) PTR(addr string, names ...string) *Zone {
	a := mustParseAddr(addr).Unmap()
	z.mu.Lock()
	defer z.mu.Unlock()
	z.ptr[a] = append(z.ptr[a], names...)
	return z
}

// NS seeds one nameserver host for name.
func (z *Zone) NS(name, host string) *Zone {
	key := normalizeName(name)
	z.mu.Lock()
	defer z.mu.Unlock()
	z.ns[key] = append(z.ns[key], host)
	z.seeded[key] = true
	return z
}

// NXDOMAIN marks name as not existing at all: every query for it returns
// KindNotFound, regardless of what else has been seeded for it.
func (z *Zone) NXDOMAIN(name string) *Zone {
	key := normalizeName(name)
	z.mu.Lock()
	defer z.mu.Unlock()
	z.nxdomain[key] = true
	return z
}

// Temporary marks name as failing every query with KindTemporary, forcing
// the temperror path in tests that need it.
func (z *Zone) Temporary(name string) *Zone {
	key := normalizeName(name)
	z.mu.Lock()
	defer z.mu.Unlock()
	z.temporary[key] = true
	return z
}

// QueryCount returns the total number of Lookup* calls made against the
// Zone so far. Safe to call concurrently with lookups.
func (z *Zone) QueryCount() int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return len(z.queryLog)
}

// Queries returns a copy of the per-query log, in call order. Safe to call
// concurrently with lookups.
func (z *Zone) Queries() []QueryRecord {
	z.mu.Lock()
	defer z.mu.Unlock()
	out := make([]QueryRecord, len(z.queryLog))
	copy(out, z.queryLog)
	return out
}

// record logs one query under the zone's lock and reports the three facts
// every lookup needs: whether the name was marked NXDOMAIN, whether it was
// marked Temporary, and whether it was seeded with some record type at all.
func (z *Zone) record(name, typ string) (isNXDOMAIN, isTemporary, wasSeeded bool) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.queryLog = append(z.queryLog, QueryRecord{Name: name, Type: typ})
	z.queryCount++
	return z.nxdomain[name], z.temporary[name], z.seeded[name]
}

func notFound(name, typ string) error  { return &Error{Kind: KindNotFound, Name: name, Type: typ} }
func noRecords(name, typ string) error { return &Error{Kind: KindNoRecords, Name: name, Type: typ} }
func temporary(name, typ string) error { return &Error{Kind: KindTemporary, Name: name, Type: typ} }

func (z *Zone) LookupTXT(_ context.Context, name string) ([]string, error) {
	key := normalizeName(name)
	nx, temp, seeded := z.record(key, "TXT")
	if temp {
		return nil, temporary(name, "TXT")
	}
	if nx {
		return nil, notFound(name, "TXT")
	}
	z.mu.Lock()
	txt, ok := z.txt[key]
	z.mu.Unlock()
	if !ok {
		if seeded {
			return nil, noRecords(name, "TXT")
		}
		return nil, notFound(name, "TXT")
	}
	out := make([]string, len(txt))
	copy(out, txt)
	return out, nil
}

func (z *Zone) LookupAddr(_ context.Context, name string) ([]netip.Addr, error) {
	key := normalizeName(name)
	nx, temp, seeded := z.record(key, "A/AAAA")
	if temp {
		return nil, temporary(name, "A/AAAA")
	}
	if nx {
		return nil, notFound(name, "A/AAAA")
	}
	z.mu.Lock()
	addrs, ok := z.addrs[key]
	z.mu.Unlock()
	if !ok {
		if seeded {
			return nil, noRecords(name, "A/AAAA")
		}
		return nil, notFound(name, "A/AAAA")
	}
	out := make([]netip.Addr, len(addrs))
	copy(out, addrs)
	return out, nil
}

func (z *Zone) LookupMX(_ context.Context, name string) ([]MX, error) {
	key := normalizeName(name)
	nx, temp, seeded := z.record(key, "MX")
	if temp {
		return nil, temporary(name, "MX")
	}
	if nx {
		return nil, notFound(name, "MX")
	}
	z.mu.Lock()
	mx, ok := z.mx[key]
	z.mu.Unlock()
	if !ok {
		if seeded {
			return nil, noRecords(name, "MX")
		}
		return nil, notFound(name, "MX")
	}
	out := make([]MX, len(mx))
	copy(out, mx)
	return out, nil
}

func (z *Zone) LookupNS(_ context.Context, name string) ([]string, error) {
	key := normalizeName(name)
	nx, temp, seeded := z.record(key, "NS")
	if temp {
		return nil, temporary(name, "NS")
	}
	if nx {
		return nil, notFound(name, "NS")
	}
	z.mu.Lock()
	ns, ok := z.ns[key]
	z.mu.Unlock()
	if !ok {
		if seeded {
			return nil, noRecords(name, "NS")
		}
		return nil, notFound(name, "NS")
	}
	out := make([]string, len(ns))
	copy(out, ns)
	return out, nil
}

func (z *Zone) LookupPTR(_ context.Context, addr netip.Addr) ([]string, error) {
	a := addr.Unmap()
	nx, temp, _ := z.record(a.String(), "PTR")
	if temp {
		return nil, temporary(a.String(), "PTR")
	}
	if nx {
		return nil, notFound(a.String(), "PTR")
	}
	z.mu.Lock()
	names, ok := z.ptr[a]
	z.mu.Unlock()
	if !ok {
		return nil, notFound(a.String(), "PTR")
	}
	out := make([]string, len(names))
	copy(out, names)
	return out, nil
}
