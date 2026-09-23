package spf

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/MatrixMagician/Frank/internal/resolve"
)

// TestMatchedMechanismReported names one test per Verdict class asserting
// the exact Matched Mechanism, in addition to the reporting already
// exercised inline in TestEvaluate, so each acceptance case has an
// unambiguous, individually named proof.
func TestMatchedMechanismReported(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		clientIP string
		want     Verdict
		wantMech string
	}{
		{"pass via ip4", "v=spf1 ip4:192.0.2.0/24 -all", "192.0.2.5", Pass, "ip4:192.0.2.0/24"},
		{"fail via -all", "v=spf1 ip4:192.0.2.0/24 -all", "198.51.100.5", Fail, "-all"},
		{"softfail via ~all", "v=spf1 ip4:192.0.2.0/24 ~all", "198.51.100.5", SoftFail, "~all"},
		{"neutral via ?all", "v=spf1 ip4:192.0.2.0/24 ?all", "198.51.100.5", Neutral, "?all"},
		{"neutral via explicit qualifier on ip4", "v=spf1 ?ip4:192.0.2.0/24 -all", "192.0.2.5", Neutral, "?ip4:192.0.2.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := resolve.NewZone()
			z.TXT("example.com", tt.record)
			got := evaluate(t, z, "a@example.com", "frank.invalid", tt.clientIP)
			if got.Verdict != tt.want {
				t.Fatalf("Verdict = %v, want %v", got.Verdict, tt.want)
			}
			if got.Matched == nil {
				t.Fatal("Matched is nil, want the deciding mechanism reported")
			}
			if got.Matched.Term.Raw != tt.wantMech {
				t.Errorf("Matched Mechanism = %q, want %q", got.Matched.Term.Raw, tt.wantMech)
			}
		})
	}
}

func TestUnknownMechanismIsPermError(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 sp3cial:x -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.1")
	if got.Verdict != PermError {
		t.Errorf("Verdict = %v, want permerror for an unrecognized mechanism", got.Verdict)
	}
}

func TestUnknownMechanismIsPermErrorForIP6Specifically(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 ip9:2001:db8::/32 -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "2001:db8::1")
	if got.Verdict != PermError {
		t.Errorf("Verdict = %v, want permerror: an unrecognized mechanism naming an ip6-shaped argument is still unknown, per ADR-0006", got.Verdict)
	}
}

func TestPTRMechanismMatches(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 ptr:example.com -all")
	z.PTR("192.0.2.9", "mail.example.com")
	z.A("mail.example.com", "192.0.2.9")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.9")
	if got.Verdict != Pass {
		t.Errorf("Verdict = %v, want pass: forward-confirmed reverse DNS names example.com", got.Verdict)
	}
	if got.Matched == nil || got.Matched.Term.Kind != MechPTR {
		t.Errorf("Matched = %v, want the ptr mechanism", got.Matched)
	}
}

func TestPTRMechanismRequiresForwardConfirmation(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 ptr:example.com -all")
	z.PTR("192.0.2.9", "mail.attacker.example")
	z.A("mail.attacker.example", "198.51.100.1")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.9")
	if got.Verdict != Fail {
		t.Errorf("Verdict = %v, want fail: the PTR name resolves back to a different address, so it is not forward-confirmed", got.Verdict)
	}
}

func TestDualCIDRAOnBothFamilies(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("v4.example.com", "v=spf1 a:target.example/24 -all")
	z.TXT("v6.example.com", "v=spf1 a:target.example//64 -all")
	z.A("target.example", "192.0.2.1")
	z.AAAA("target.example", "2001:db8::1")

	got4 := evaluate(t, z, "a@v4.example.com", "frank.invalid", "192.0.2.200")
	if got4.Verdict != Pass {
		t.Errorf("ip4 dual-cidr: Verdict = %v, want pass under /24", got4.Verdict)
	}
	got6 := evaluate(t, z, "a@v6.example.com", "frank.invalid", "2001:db8::ffff")
	if got6.Verdict != Pass {
		t.Errorf("ip6 dual-cidr: Verdict = %v, want pass under //64", got6.Verdict)
	}
}

func TestSecondaryLookupLimitIsARecordDefect(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 mx -all")
	for i := 0; i < 12; i++ {
		host := "mx" + string(rune('a'+i)) + ".example.com"
		z.MX("example.com", uint16(i), host)
		z.A(host, "203.0.113.1")
	}
	z.A("mxl.example.com", "192.0.2.50")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.50")

	var found bool
	for _, d := range got.Defects {
		if d.Kind == DefectSecondaryLimitExceeded {
			found = true
		}
	}
	if !found {
		t.Errorf("Defects = %+v, want a secondary-limit defect: mx resolved more than %d hosts", got.Defects, SecondaryLookupLimit)
	}
}

// TestEvaluateExercisesEveryMechanismKindOverTheFixtureResolver evaluates a
// record touching every DNS-querying mechanism kind against resolve.Zone.
// The package-wide guarantee that this never reaches a real network comes
// from TestMain calling resolve.ForbidNetwork, which is mandatory for #8;
// this test's job is to prove the mechanism table wires up include, a, mx,
// ptr and exists together in one record.
func TestEvaluateExercisesEveryMechanismKindOverTheFixtureResolver(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 include:inc.example a mx ptr exists:%{d} ip4:192.0.2.0/24 -all")
	z.TXT("inc.example", "v=spf1 -all")
	z.A("example.com", "192.0.2.1")
	z.MX("example.com", 10, "mail.example.com")
	z.A("mail.example.com", "192.0.2.2")
	z.PTR("192.0.2.1", "example.com")
	z.A("example.com.example.com", "192.0.2.1")

	req := Request{EnvelopeSender: "a@example.com", HeloIdentity: "frank.invalid"}
	ip, err := NewCandidateSendingIP(netip.MustParseAddr("192.0.2.1"), true)
	if err != nil {
		t.Fatalf("NewCandidateSendingIP: %v", err)
	}
	req.CandidateIP = &ip

	if _, err := Evaluate(context.Background(), z, req); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
}

func TestExpandMacrosRejectsBareTrailingPercent(t *testing.T) {
	e := &evaluator{subject: "example.com", envelopeSender: "a@example.com"}
	if _, err := e.expandMacros("foo%", "example.com", netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Error("a bare trailing %% expanded without error")
	}
}

func TestIsSPFRecordRequiresWordBoundary(t *testing.T) {
	if IsSPFRecord("v=spf10-not-actually-spf1") {
		t.Error("v=spf10... was accepted as an spf1 record, want it rejected: v=spf1 must be the whole token or followed by a space")
	}
	if !IsSPFRecord("v=spf1") {
		t.Error("bare v=spf1 with no terms was rejected, want it accepted")
	}
	if !IsSPFRecord("v=spf1 -all") {
		t.Error("v=spf1 -all was rejected")
	}
}

func TestRedirectAlsoObeysLookupLimit(t *testing.T) {
	z := resolve.NewZone()
	var terms []string
	for i := 0; i < 10; i++ {
		name := "inc" + string(rune('a'+i)) + ".redirtest"
		terms = append(terms, "include:"+name)
		z.TXT(name, "v=spf1 -all")
	}
	z.TXT("example.com", "v=spf1 "+strings.Join(terms, " ")+" redirect=other.example")
	z.TXT("other.example", "v=spf1 ip4:192.0.2.0/24 -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
	if got.Verdict != PermError {
		t.Errorf("Verdict = %v, want permerror: redirect itself is the 11th dns-querying mechanism", got.Verdict)
	}
}

// TestSameDomainIncludedFromTwoBranchesIsNotACycle guards against a cycle
// detector keyed on "every domain ever seen in this evaluation" rather than
// "the current include/redirect path": two independent include mechanisms
// naming the same domain is ordinary and must not be mistaken for a loop.
// Both branch-a and branch-b include shared.example, which does not match
// the test's client IP (so evaluation of each branch continues past its
// include to its own -all), forcing shared.example to be evaluated twice on
// two independent paths rather than short-circuiting after the first.
func TestSameDomainIncludedFromTwoBranchesIsNotACycle(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("example.com", "v=spf1 include:branch-a.example include:branch-b.example -all")
	z.TXT("branch-a.example", "v=spf1 include:shared.example -all")
	z.TXT("branch-b.example", "v=spf1 include:shared.example -all")
	z.TXT("shared.example", "v=spf1 -all")

	got := evaluate(t, z, "a@example.com", "frank.invalid", "192.0.2.7")
	if got.Verdict != Fail {
		t.Fatalf("Verdict = %v, want fail from example.com's own -all: a false cycle detection would instead surface as permerror", got.Verdict)
	}
	if got.Matched == nil || got.Matched.Domain != "example.com" {
		t.Errorf("Matched = %v, want the top-level -all, since neither include matched", got.Matched)
	}
}

func TestActualIncludeCycleIsPermError(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("a.example", "v=spf1 include:b.example -all")
	z.TXT("b.example", "v=spf1 include:a.example -all")

	got := evaluate(t, z, "x@a.example", "frank.invalid", "192.0.2.7")
	if got.Verdict != PermError {
		t.Errorf("Verdict = %v, want permerror: a.example includes b.example includes a.example is a real cycle", got.Verdict)
	}
}
