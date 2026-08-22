package resolve

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
)

func TestFixtureMultiStringTXTArrivesConcatenated(t *testing.T) {
	z := NewZone()
	z.TXTStrings("long.example.com", "v=spf1 ", "include:a.example ", "-all")

	got, err := z.LookupTXT(context.Background(), "long.example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	want := []string{"v=spf1 include:a.example -all"}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("LookupTXT = %q, want %q", got, want)
	}
}

func TestFixtureMultipleTXTRecordsStaySeparate(t *testing.T) {
	z := NewZone()
	z.TXT("example.com", "v=spf1 include:_spf.example.net -all")
	z.TXT("example.com", "google-site-verification=abc123")

	got, err := z.LookupTXT(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 separate TXT records, got %d: %q", len(got), got)
	}
}

func TestNotFoundAndNoRecordsAreDistinguishable(t *testing.T) {
	z := NewZone()
	z.A("mail.example.com", "192.0.2.1") // seeded, but no TXT
	z.NXDOMAIN("nowhere.example.com")    // never seeded, explicitly absent

	_, err := z.LookupTXT(context.Background(), "mail.example.com")
	if !IsNoRecords(err) {
		t.Fatalf("expected KindNoRecords for a seeded name with no TXT, got %v", err)
	}
	if IsNotFound(err) {
		t.Fatalf("KindNoRecords must not also read as KindNotFound: %v", err)
	}

	_, err = z.LookupTXT(context.Background(), "nowhere.example.com")
	if !IsNotFound(err) {
		t.Fatalf("expected KindNotFound for an NXDOMAIN name, got %v", err)
	}

	_, err = z.LookupTXT(context.Background(), "never.seeded.example.com")
	if !IsNotFound(err) {
		t.Fatalf("expected KindNotFound for a name never seeded at all, got %v", err)
	}
}

func TestFixtureNamesAreCaseInsensitiveAndDotNormalised(t *testing.T) {
	z := NewZone()
	z.TXT("Example.COM.", "v=spf1 -all")

	for _, name := range []string{"example.com", "EXAMPLE.COM", "example.com.", "Example.Com."} {
		got, err := z.LookupTXT(context.Background(), name)
		if err != nil {
			t.Fatalf("LookupTXT(%q): %v", name, err)
		}
		if len(got) != 1 || got[0] != "v=spf1 -all" {
			t.Fatalf("LookupTXT(%q) = %q, want [v=spf1 -all]", name, got)
		}
	}
}

func TestFixtureCountsQueries(t *testing.T) {
	z := NewZone()
	z.TXT("example.com", "v=spf1 -all")
	z.A("example.com", "192.0.2.1")

	ctx := context.Background()
	if _, err := z.LookupTXT(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := z.LookupAddr(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := z.LookupTXT(ctx, "other.example.com"); err == nil {
		t.Fatal("expected error for unseeded name")
	}

	if got := z.QueryCount(); got != 3 {
		t.Fatalf("QueryCount() = %d, want 3", got)
	}
	log := z.Queries()
	if len(log) != 3 {
		t.Fatalf("Queries() returned %d entries, want 3", len(log))
	}
	if log[0].Name != "example.com" || log[0].Type != "TXT" {
		t.Fatalf("Queries()[0] = %+v, want {example.com TXT}", log[0])
	}
	if log[1].Type != "A/AAAA" {
		t.Fatalf("Queries()[1].Type = %q, want A/AAAA", log[1].Type)
	}
}

func TestTemporaryFailureIsDistinguishable(t *testing.T) {
	z := NewZone()
	z.Temporary("broken.example.com")
	z.TXT("broken.example.com", "this record must be unreachable")

	_, err := z.LookupTXT(context.Background(), "broken.example.com")
	if !IsTemporary(err) {
		t.Fatalf("expected KindTemporary, got %v", err)
	}
	if IsNotFound(err) || IsNoRecords(err) || IsPermanent(err) {
		t.Fatalf("KindTemporary must not also match another kind: %v", err)
	}

	var re *Error
	if !errors.As(err, &re) {
		t.Fatalf("errors.As failed to extract *resolve.Error from %v", err)
	}
	if re.Name != "broken.example.com" || re.Type != "TXT" {
		t.Fatalf("Error{Name:%q Type:%q}, want broken.example.com/TXT", re.Name, re.Type)
	}
}

func TestFixtureIsRaceFree(t *testing.T) {
	z := NewZone()
	for i := 0; i < 50; i++ {
		z.TXT("race.example.com", "v=spf1 -all")
	}
	z.A("race.example.com", "192.0.2.1")
	z.AAAA("race.example.com", "2001:db8::1")

	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = z.LookupTXT(ctx, "race.example.com")
			_, _ = z.LookupAddr(ctx, "race.example.com")
			_ = z.QueryCount()
			_ = z.Queries()
		}()
	}
	wg.Wait()
}

func TestFixtureAAAATwinForEveryACase(t *testing.T) {
	cases := []struct {
		name string
		v4   string
		v6   string
	}{
		{"mail.example.com", "192.0.2.1", "2001:db8::1"},
		{"mx1.example.net", "203.0.113.5", "2001:db8:1::5"},
	}
	for _, c := range cases {
		z := NewZone()
		z.A(c.name, c.v4)
		z.AAAA(c.name, c.v6)

		got, err := z.LookupAddr(context.Background(), c.name)
		if err != nil {
			t.Fatalf("LookupAddr(%q): %v", c.name, err)
		}
		wantV4 := netip.MustParseAddr(c.v4)
		wantV6 := netip.MustParseAddr(c.v6)
		var haveV4, haveV6 bool
		for _, a := range got {
			if a == wantV4 {
				haveV4 = true
			}
			if a == wantV6 {
				haveV6 = true
			}
		}
		if !haveV4 || !haveV6 {
			t.Fatalf("LookupAddr(%q) = %v, want both %v and %v", c.name, got, wantV4, wantV6)
		}
	}
}

func TestFixtureMXPTRNS(t *testing.T) {
	z := NewZone()
	z.MX("example.com", 10, "mail.example.com")
	z.PTR("192.0.2.1", "mail.example.com")
	z.NS("example.com", "ns1.example.com")

	ctx := context.Background()

	mx, err := z.LookupMX(ctx, "example.com")
	if err != nil || len(mx) != 1 || mx[0].Host != "mail.example.com" || mx[0].Pref != 10 {
		t.Fatalf("LookupMX = %+v, err %v", mx, err)
	}

	ptr, err := z.LookupPTR(ctx, netip.MustParseAddr("192.0.2.1"))
	if err != nil || len(ptr) != 1 || ptr[0] != "mail.example.com" {
		t.Fatalf("LookupPTR = %v, err %v", ptr, err)
	}

	ns, err := z.LookupNS(ctx, "example.com")
	if err != nil || len(ns) != 1 || ns[0] != "ns1.example.com" {
		t.Fatalf("LookupNS = %v, err %v", ns, err)
	}
}

func TestFixturePTRNotFound(t *testing.T) {
	z := NewZone()
	_, err := z.LookupPTR(context.Background(), netip.MustParseAddr("192.0.2.99"))
	if !IsNotFound(err) {
		t.Fatalf("expected KindNotFound for an unseeded PTR address, got %v", err)
	}
}

func TestFixtureImplementsResolver(t *testing.T) {
	var _ Resolver = NewZone()
}
