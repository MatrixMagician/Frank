package spf

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/MatrixMagician/Frank/internal/resolve"
)

func mustIP(t *testing.T, s string) *CandidateSendingIP {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	ip, err := NewCandidateSendingIP(addr, false)
	if err != nil {
		t.Fatalf("NewCandidateSendingIP(%q): %v", s, err)
	}
	return &ip
}

func evaluate(t *testing.T, z *resolve.Zone, sender, helo, clientIP string) *Result {
	t.Helper()
	req := Request{EnvelopeSender: sender, HeloIdentity: helo}
	if clientIP != "" {
		req.CandidateIP = mustIP(t, clientIP)
	}
	res, err := Evaluate(context.Background(), z, req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return res
}

type evalCase struct {
	name     string
	seed     func(*resolve.Zone)
	sender   string
	clientIP string
	want     Verdict
	wantMech string
	family   string
}

// evalCases covers every Verdict class. Each case has an ip4 and an ip6 twin,
// which TestEveryIPv4CaseHasIPv6Twin asserts by walking this same slice, so a
// v4 case added without its twin fails there.
func evalCases() []evalCase {
	return []evalCase{
		{
			name:     "ip4 pass",
			seed:     func(z *resolve.Zone) { z.TXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all") },
			sender:   "a@example.com",
			clientIP: "192.0.2.10",
			want:     Pass,
			wantMech: "ip4:192.0.2.0/24",
			family:   "ip4",
		},
		{
			name:     "ip6 pass",
			seed:     func(z *resolve.Zone) { z.TXT("example.com", "v=spf1 ip6:2001:db8::/32 -all") },
			sender:   "a@example.com",
			clientIP: "2001:db8::10",
			want:     Pass,
			wantMech: "ip6:2001:db8::/32",
			family:   "ip6",
		},
		{
			name:     "ip4 fail via -all",
			seed:     func(z *resolve.Zone) { z.TXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all") },
			sender:   "a@example.com",
			clientIP: "198.51.100.7",
			want:     Fail,
			wantMech: "-all",
			family:   "ip4",
		},
		{
			name:     "ip6 fail via -all",
			seed:     func(z *resolve.Zone) { z.TXT("example.com", "v=spf1 ip6:2001:db8::/32 -all") },
			sender:   "a@example.com",
			clientIP: "2001:db9::7",
			want:     Fail,
			wantMech: "-all",
			family:   "ip6",
		},
		{
			name:     "ip4 softfail",
			seed:     func(z *resolve.Zone) { z.TXT("example.com", "v=spf1 ip4:192.0.2.0/24 ~all") },
			sender:   "a@example.com",
			clientIP: "198.51.100.7",
			want:     SoftFail,
			wantMech: "~all",
			family:   "ip4",
		},
		{
			name:     "ip6 softfail",
			seed:     func(z *resolve.Zone) { z.TXT("example.com", "v=spf1 ip6:2001:db8::/32 ~all") },
			sender:   "a@example.com",
			clientIP: "2001:db9::7",
			want:     SoftFail,
			wantMech: "~all",
			family:   "ip6",
		},
		{
			name:     "ip4 neutral",
			seed:     func(z *resolve.Zone) { z.TXT("example.com", "v=spf1 ip4:192.0.2.0/24 ?all") },
			sender:   "a@example.com",
			clientIP: "198.51.100.7",
			want:     Neutral,
			wantMech: "?all",
			family:   "ip4",
		},
		{
			name:     "ip6 neutral",
			seed:     func(z *resolve.Zone) { z.TXT("example.com", "v=spf1 ip6:2001:db8::/32 ?all") },
			sender:   "a@example.com",
			clientIP: "2001:db9::7",
			want:     Neutral,
			wantMech: "?all",
			family:   "ip6",
		},
		{
			name:     "ip4 none when no record",
			seed:     func(z *resolve.Zone) { z.A("example.com", "192.0.2.1") },
			sender:   "a@example.com",
			clientIP: "192.0.2.1",
			want:     None,
			family:   "ip4",
		},
		{
			name:     "ip6 none when no record",
			seed:     func(z *resolve.Zone) { z.AAAA("example.com", "2001:db8::1") },
			sender:   "a@example.com",
			clientIP: "2001:db8::1",
			want:     None,
			family:   "ip6",
		},
		{
			name:     "ip4 temperror on SERVFAIL",
			seed:     func(z *resolve.Zone) { z.Temporary("example.com") },
			sender:   "a@example.com",
			clientIP: "192.0.2.1",
			want:     TempError,
			family:   "ip4",
		},
		{
			name:     "ip6 temperror on SERVFAIL",
			seed:     func(z *resolve.Zone) { z.Temporary("example.com") },
			sender:   "a@example.com",
			clientIP: "2001:db8::1",
			want:     TempError,
			family:   "ip6",
		},
		{
			name:     "ip4 permerror on unknown mechanism",
			seed:     func(z *resolve.Zone) { z.TXT("example.com", "v=spf1 frobnicate:x -all") },
			sender:   "a@example.com",
			clientIP: "192.0.2.1",
			want:     PermError,
			family:   "ip4",
		},
		{
			name:     "ip6 permerror on unknown mechanism",
			seed:     func(z *resolve.Zone) { z.TXT("example.com", "v=spf1 frobnicate:x -all") },
			sender:   "a@example.com",
			clientIP: "2001:db8::1",
			want:     PermError,
			family:   "ip6",
		},
		{
			name: "ip4 a mechanism matches",
			seed: func(z *resolve.Zone) {
				z.TXT("example.com", "v=spf1 a -all")
				z.A("example.com", "192.0.2.5")
			},
			sender:   "a@example.com",
			clientIP: "192.0.2.5",
			want:     Pass,
			wantMech: "a",
			family:   "ip4",
		},
		{
			name: "ip6 a mechanism matches",
			seed: func(z *resolve.Zone) {
				z.TXT("example.com", "v=spf1 a -all")
				z.AAAA("example.com", "2001:db8::5")
			},
			sender:   "a@example.com",
			clientIP: "2001:db8::5",
			want:     Pass,
			wantMech: "a",
			family:   "ip6",
		},
		{
			name: "ip4 mx mechanism matches",
			seed: func(z *resolve.Zone) {
				z.TXT("example.com", "v=spf1 mx -all")
				z.MX("example.com", 10, "mail.example.com")
				z.A("mail.example.com", "192.0.2.9")
			},
			sender:   "a@example.com",
			clientIP: "192.0.2.9",
			want:     Pass,
			wantMech: "mx",
			family:   "ip4",
		},
		{
			name: "ip6 mx mechanism matches",
			seed: func(z *resolve.Zone) {
				z.TXT("example.com", "v=spf1 mx -all")
				z.MX("example.com", 10, "mail.example.com")
				z.AAAA("mail.example.com", "2001:db8::9")
			},
			sender:   "a@example.com",
			clientIP: "2001:db8::9",
			want:     Pass,
			wantMech: "mx",
			family:   "ip6",
		},
	}
}

func TestEvaluate(t *testing.T) {
	for _, tt := range evalCases() {
		t.Run(tt.name, func(t *testing.T) {
			z := resolve.NewZone()
			tt.seed(z)

			got := evaluate(t, z, tt.sender, "frank.invalid", tt.clientIP)
			if got.Verdict != tt.want {
				t.Errorf("Verdict = %v, want %v", got.Verdict, tt.want)
			}
			if tt.wantMech != "" {
				if got.Matched == nil {
					t.Fatalf("Matched is nil, want the mechanism %q", tt.wantMech)
				}
				if got.Matched.Term.Raw != tt.wantMech {
					t.Errorf("Matched Mechanism = %q, want %q", got.Matched.Term.Raw, tt.wantMech)
				}
			}
		})
	}
}

// TestEveryIPv4CaseHasIPv6Twin enforces ADR-0006's requirement that fixtures
// carry a v6 twin for every v4 case, by checking the table above balances.
func TestEveryIPv4CaseHasIPv6Twin(t *testing.T) {
	var v4, v6 int
	for _, c := range evalCases() {
		switch c.family {
		case "ip4":
			v4++
		case "ip6":
			v6++
		default:
			t.Errorf("case %q declares no family, so it cannot be paired", c.name)
		}
	}
	if v4 == 0 {
		t.Fatal("no ip4 cases found, the check is not measuring anything")
	}
	if v4 != v6 {
		t.Errorf("%d ip4 cases against %d ip6 cases, ADR-0006 requires a v6 twin for each", v4, v6)
	}
}

func TestNestedIncludes(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 include:one.example -all")
	z.TXT("one.example", "v=spf1 include:two.example -all")
	z.TXT("two.example", "v=spf1 include:three.example -all")
	z.TXT("three.example", "v=spf1 ip4:192.0.2.0/24 -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
	if got.Verdict != Pass {
		t.Errorf("Verdict = %v, want pass through three levels of include", got.Verdict)
	}

	var depths []int
	for _, n := range got.Tree.Nodes {
		depths = append(depths, n.Depth)
	}
	if len(depths) == 0 {
		t.Fatal("Evaluation Tree is empty")
	}
	maxDepth := 0
	for _, d := range depths {
		if d > maxDepth {
			maxDepth = d
		}
	}
	if maxDepth < 3 {
		t.Errorf("deepest node is at depth %d, want at least 3 to show the nesting", maxDepth)
	}
}

func TestIncludeResultSemantics(t *testing.T) {
	t.Run("pass inside include matches", func(t *testing.T) {
		z := resolve.NewZone()
		z.TXT("example.com", "v=spf1 include:inc.example -all")
		z.TXT("inc.example", "v=spf1 ip4:192.0.2.0/24 -all")

		got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
		if got.Verdict != Pass {
			t.Errorf("Verdict = %v, want pass: a pass inside an include makes the include match", got.Verdict)
		}
	})

	t.Run("fail inside include does not match and evaluation continues", func(t *testing.T) {
		z := resolve.NewZone()
		z.TXT("example.com", "v=spf1 include:inc.example ip4:198.51.100.0/24 -all")
		z.TXT("inc.example", "v=spf1 ip4:192.0.2.0/24 -all")

		got := evaluate(t, z, "a@example.com", "frank.invalid", "198.51.100.7")
		if got.Verdict != Pass {
			t.Errorf("Verdict = %v, want pass from the mechanism after the include", got.Verdict)
		}
		if got.Matched == nil || got.Matched.Term.Raw != "ip4:198.51.100.0/24" {
			t.Errorf("Matched = %v, want the mechanism after the non-matching include", got.Matched)
		}
	})

	t.Run("temperror inside include propagates", func(t *testing.T) {
		z := resolve.NewZone()
		z.TXT("example.com", "v=spf1 include:broken.example -all")
		z.Temporary("broken.example")

		got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
		if got.Verdict != TempError {
			t.Errorf("Verdict = %v, want temperror to propagate out of the include", got.Verdict)
		}
	})

	t.Run("nonexistent include target is permerror", func(t *testing.T) {
		z := resolve.NewZone()
		z.TXT("example.com", "v=spf1 include:missing.example -all")
		z.NXDOMAIN("missing.example")

		got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
		if got.Verdict != PermError {
			t.Errorf("Verdict = %v, want permerror for an include target with no record", got.Verdict)
		}
	})
}

func TestRedirect(t *testing.T) {
	t.Run("redirect replaces the result", func(t *testing.T) {
		z := resolve.NewZone()
		z.TXT("example.com", "v=spf1 redirect=other.example")
		z.TXT("other.example", "v=spf1 ip4:192.0.2.0/24 -all")

		got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
		if got.Verdict != Pass {
			t.Errorf("Verdict = %v, want pass from the redirect target", got.Verdict)
		}
	})

	t.Run("redirect is ignored when all is present", func(t *testing.T) {
		z := resolve.NewZone()
		z.TXT("example.com", "v=spf1 -all redirect=other.example")
		z.TXT("other.example", "v=spf1 ip4:192.0.2.0/24 -all")

		got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
		if got.Verdict != Fail {
			t.Errorf("Verdict = %v, want fail: all matched, so redirect must not apply", got.Verdict)
		}
	})

	t.Run("redirect to a domain with no record is permerror", func(t *testing.T) {
		z := resolve.NewZone()
		z.TXT("example.com", "v=spf1 redirect=empty.example")
		z.A("empty.example", "192.0.2.1")

		got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
		if got.Verdict != PermError {
			t.Errorf("Verdict = %v, want permerror when the redirect target publishes no record", got.Verdict)
		}
	})
}

func TestLookupLimitExceededIsARecordDefect(t *testing.T) {
	z := resolve.NewZone()
	var terms []string
	for i := range 11 {
		name := "inc" + string(rune('a'+i)) + ".example"
		terms = append(terms, "include:"+name)
		z.TXT(name, "v=spf1 -all")
	}
	z.TXT("example.com", "v=spf1 "+strings.Join(terms, " ")+" -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")

	if got.Verdict != PermError {
		t.Errorf("Verdict = %v, want permerror for an over-limit record", got.Verdict)
	}
	var found bool
	for _, d := range got.Defects {
		if d.Kind == DefectLookupLimitExceeded {
			found = true
		}
	}
	if !found {
		t.Errorf("Defects = %+v, want a lookup-limit defect: an over-limit record is a root cause in its own right", got.Defects)
	}
}

func TestLookupLimitIsNotChargedForIPMechanisms(t *testing.T) {
	z := resolve.NewZone()
	var terms []string
	for range 20 {
		terms = append(terms, "ip4:192.0.2.0/24")
	}
	z.TXT("example.com", "v=spf1 "+strings.Join(terms, " ")+" -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "198.51.100.1")
	if got.Verdict == PermError {
		t.Error("Verdict = permerror, but ip4 mechanisms cost no DNS lookup")
	}
	if got.Lookups != 0 {
		t.Errorf("Lookups = %d, want 0: no mechanism here queries DNS", got.Lookups)
	}
}

// TestAddressNormalisedBeforeMatching is ADR-0006's case. An IPv4-mapped IPv6
// address does not match an IPv4 prefix until it is unmapped, and skipping
// that normalisation produces a confident fail where the truth is pass.
func TestAddressNormalisedBeforeMatching(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all")

	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	if netip.MustParsePrefix("192.0.2.0/24").Contains(mapped) {
		t.Fatal("the mapped address already matches the v4 prefix, so this test proves nothing")
	}

	ip, err := NewCandidateSendingIP(mapped, true)
	if err != nil {
		t.Fatalf("NewCandidateSendingIP: %v", err)
	}
	res, err := Evaluate(context.Background(), z, Request{EnvelopeSender: "a@example.com", CandidateIP: &ip})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Verdict != Pass {
		t.Errorf("Verdict = %v, want pass: the address must be unmapped before matching", res.Verdict)
	}
}

func TestZonedAddressRejected(t *testing.T) {
	zoned, err := netip.ParseAddr("fe80::1%eth0")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := NewCandidateSendingIP(zoned, true); err == nil {
		t.Error("a zoned address was accepted, want it rejected rather than silently mismatched")
	}
}

func TestNullEnvelopeSenderMovesSubjectToHELO(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("frank.invalid", "v=spf1 ip4:192.0.2.0/24 -all")
	z.TXT("example.com", "v=spf1 -all")

	got := evaluate(t, z, "", "frank.invalid", "192.0.2.7")

	if got.Subject != "frank.invalid" {
		t.Errorf("Subject = %q, want the HELO Identity when the Envelope Sender is null", got.Subject)
	}
	if !strings.Contains(got.SubjectFrom, "helo") {
		t.Errorf("SubjectFrom = %q, want it to name the HELO Identity as the subject", got.SubjectFrom)
	}
	if got.Verdict != Pass {
		t.Errorf("Verdict = %v, want pass evaluated against the HELO domain", got.Verdict)
	}
}

func TestVerdictNamesItsSubjectForAnEnvelopeSender(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
	if got.Subject != "example.com" {
		t.Errorf("Subject = %q, want the envelope sender's domain", got.Subject)
	}
	if !strings.Contains(got.SubjectFrom, "envelope") {
		t.Errorf("SubjectFrom = %q, want it to name the envelope sender", got.SubjectFrom)
	}
}

func TestVerdictNotEvaluatedStillRendersTree(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 include:inc.example -all")
	z.TXT("inc.example", "v=spf1 ip4:192.0.2.0/24 -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "")

	if got.Verdict != NotEvaluated {
		t.Errorf("Verdict = %v, want not-evaluated without a Candidate Sending IP", got.Verdict)
	}
	if got.Tree == nil || len(got.Tree.Nodes) == 0 {
		t.Fatal("Evaluation Tree is empty, want it rendered even without a client IP")
	}
	if got.CandidateIP != nil {
		t.Error("CandidateIP is set, but auth must never invent a sending IP")
	}

	var out strings.Builder
	if err := RenderTree(&out, got); err != nil {
		t.Fatalf("RenderTree: %v", err)
	}
	if !strings.Contains(out.String(), "include:inc.example") {
		t.Errorf("rendered tree does not show the mechanisms:\n%s", out.String())
	}
}

func TestTwoSPFRecordsIsPermError(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all")
	z.TXT("example.com", "v=spf1 ip4:198.51.100.0/24 -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
	if got.Verdict != PermError {
		t.Errorf("Verdict = %v, want permerror when a domain publishes two SPF records", got.Verdict)
	}
}

func TestNonSPFTXTRecordsAreIgnored(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "google-site-verification=abc123")
	z.TXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
	if got.Verdict != Pass {
		t.Errorf("Verdict = %v, want pass: a non-SPF TXT record beside the SPF one is not a second record", got.Verdict)
	}
}

func TestMultiStringRecordIsEvaluatedAsOne(t *testing.T) {
	z := resolve.NewZone()
	z.TXTStrings("example.com", "v=spf1 ", "ip4:192.0.2.0/24 ", "-all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
	if got.Verdict != Pass {
		t.Errorf("Verdict = %v, want pass: a record split across character-strings is one record", got.Verdict)
	}
}

func TestMacroExpansion(t *testing.T) {
	tests := []struct {
		name     string
		spec     string
		sender   string
		clientIP string
		want     string
	}{
		{"domain", "%{d}", "a@example.com", "192.0.2.1", "example.com"},
		{"sender", "%{s}", "user@example.com", "192.0.2.1", "user@example.com"},
		{"local part", "%{l}", "user@example.com", "192.0.2.1", "user"},
		{"sender domain", "%{o}", "user@example.com", "192.0.2.1", "example.com"},
		{"client ip v4", "%{i}", "a@example.com", "192.0.2.1", "192.0.2.1"},
		{"literal percent", "%%", "a@example.com", "192.0.2.1", "%"},
		{"literal space", "%_", "a@example.com", "192.0.2.1", " "},
		{"url space", "%-", "a@example.com", "192.0.2.1", "%20"},
		{"reversed domain", "%{dr}", "a@example.com", "192.0.2.1", "com.example"},
		{"truncated domain", "%{d1}", "a@sub.example.com", "192.0.2.1", "com"},
		{"exists style", "%{i}._spf.%{d}", "a@example.com", "192.0.2.1", "192.0.2.1._spf.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &evaluator{subject: "example.com", envelopeSender: tt.sender, helo: "frank.invalid"}
			domain := "example.com"
			if strings.Contains(tt.sender, "sub.") {
				domain = "sub.example.com"
			}
			got, err := e.expandMacros(tt.spec, domain, netip.MustParseAddr(tt.clientIP))
			if err != nil {
				t.Fatalf("expandMacros(%q): %v", tt.spec, err)
			}
			if got != tt.want {
				t.Errorf("expandMacros(%q) = %q, want %q", tt.spec, got, tt.want)
			}
		})
	}
}

func TestUnsupportedMacroIsAnErrorNotASilentMismatch(t *testing.T) {
	e := &evaluator{subject: "example.com", envelopeSender: "a@example.com"}
	if _, err := e.expandMacros("%{p}", "example.com", netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Error("%{p} expanded without error, want it refused so the record becomes a permerror rather than a wrong lookup")
	}
}

func TestUnsupportedMacroIsAnEvaluationLimitNotARecordDefect(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 exists:%{p}.example.com -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")

	if len(got.Defects) != 0 {
		t.Errorf("Defects = %+v, want none: an unsupported macro is Frank's gap, not the domain's", got.Defects)
	}
	if len(got.Limits) != 1 || got.Limits[0].Kind != LimitUnsupportedMacro || got.Limits[0].Kind.String() != "unsupported-macro" {
		t.Errorf("Limits = %+v, want one unsupported-macro limit", got.Limits)
	}
}

func TestExistsMechanismUsesExpandedName(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 exists:%{i}._spf.example.com -all")
	z.A("192.0.2.7._spf.example.com", "127.0.0.2")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
	if got.Verdict != Pass {
		t.Errorf("Verdict = %v, want pass: the exists name must be macro-expanded before lookup", got.Verdict)
	}
}

func TestCandidateSendingIPRecordsWhetherItWasObserved(t *testing.T) {
	observed, err := NewCandidateSendingIP(netip.MustParseAddr("192.0.2.1"), true)
	if err != nil {
		t.Fatalf("NewCandidateSendingIP: %v", err)
	}
	supplied, err := NewCandidateSendingIP(netip.MustParseAddr("192.0.2.1"), false)
	if err != nil {
		t.Fatalf("NewCandidateSendingIP: %v", err)
	}
	if !observed.Observed {
		t.Error("observed address does not report itself as observed")
	}
	if supplied.Observed {
		t.Error("supplied address reports itself as observed, but ADR-0002 requires the Verdict to say which it was")
	}
}

// TestSameDomainOnTwoIncludeBranchesIsNotACycle guards the difference between
// a domain recurring on its own path, which is a real cycle, and the same
// domain named by two independent branches, which is ordinary and common.
func TestSameDomainOnTwoIncludeBranchesIsNotACycle(t *testing.T) {
	// The first branch must NOT match, so evaluation reaches the second branch
	// and asks about shared.example a second time. That second visit is what a
	// path-insensitive cycle check would wrongly call a loop.
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 include:a.example include:b.example -all")
	z.TXT("a.example", "v=spf1 include:shared.example -all")
	z.TXT("b.example", "v=spf1 include:shared.example ip4:192.0.2.0/24 -all")
	z.TXT("shared.example", "v=spf1 ip4:198.51.100.0/24 -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
	if got.Verdict != Pass {
		t.Errorf("Verdict = %v, want pass: two branches naming the same domain is not a cycle", got.Verdict)
	}
}

func TestIncludeCycleIsPermError(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 include:loop.example -all")
	z.TXT("loop.example", "v=spf1 include:example.com -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
	if got.Verdict != PermError {
		t.Errorf("Verdict = %v, want permerror for a domain recurring on its own path", got.Verdict)
	}
}
