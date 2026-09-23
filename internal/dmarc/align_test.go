package dmarc

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/MatrixMagician/Frank/internal/resolve"
	"github.com/MatrixMagician/Frank/internal/spf"
)

func TestAlignment(t *testing.T) {
	tests := []struct {
		name          string
		identifier    Identifier
		authenticated string
		headerFrom    string
		wantRelaxed   bool
		wantStrict    bool
	}{
		{"spf identical", IdentifierSPF, "example.com", "example.com", true, true},
		{"spf relaxed only", IdentifierSPF, "mail.example.com", "example.com", true, false},
		{"spf relaxed only reversed", IdentifierSPF, "example.com", "mail.example.com", true, false},
		{"spf unrelated", IdentifierSPF, "example.com", "example.org", false, false},
		{"spf case insensitive", IdentifierSPF, "Example.COM", "example.com", true, true},
		{"dkim identical", IdentifierDKIM, "example.com", "example.com", true, true},
		{"dkim relaxed only", IdentifierDKIM, "mail.example.com", "example.com", true, false},
		{"dkim unrelated", IdentifierDKIM, "example.com", "example.org", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := computeAlignment(tt.identifier, tt.authenticated, tt.headerFrom)
			if a.Relaxed != tt.wantRelaxed {
				t.Errorf("Relaxed = %v, want %v", a.Relaxed, tt.wantRelaxed)
			}
			if a.Strict != tt.wantStrict {
				t.Errorf("Strict = %v, want %v", a.Strict, tt.wantStrict)
			}
			if a.Identifier != tt.identifier {
				t.Errorf("Identifier = %s, want %s", a.Identifier, tt.identifier)
			}
			if a.AuthenticatedDomain != tt.authenticated {
				t.Errorf("AuthenticatedDomain = %q, want %q", a.AuthenticatedDomain, tt.authenticated)
			}
			if a.HeaderFromDomain != tt.headerFrom {
				t.Errorf("HeaderFromDomain = %q, want %q", a.HeaderFromDomain, tt.headerFrom)
			}
		})
	}
}

func TestPolicyResolution(t *testing.T) {
	t.Run("record on domain itself", func(t *testing.T) {
		z := resolve.NewZone()
		z.TXT("_dmarc.example.com", "v=DMARC1; p=reject")

		res, err := Evaluate(context.Background(), z, Input{HeaderFromDomain: "example.com"})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !res.Found {
			t.Fatal("Found = false, want true")
		}
		if res.Policy.FromSubdomain {
			t.Error("FromSubdomain = true, want false: record was found on the domain itself")
		}
		if res.Policy.Domain != "example.com" {
			t.Errorf("Policy.Domain = %q, want example.com", res.Policy.Domain)
		}
		if res.EffectivePolicy != DispositionReject {
			t.Errorf("EffectivePolicy = %s, want reject", res.EffectivePolicy)
		}
	})

	t.Run("record only on parent applies sp", func(t *testing.T) {
		z := resolve.NewZone()
		z.TXT("_dmarc.example.com", "v=DMARC1; p=reject; sp=quarantine")

		res, err := Evaluate(context.Background(), z, Input{HeaderFromDomain: "mail.example.com"})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !res.Found {
			t.Fatal("Found = false, want true")
		}
		if !res.Policy.FromSubdomain {
			t.Error("FromSubdomain = false, want true: record was found on the organizational domain")
		}
		if res.Policy.Domain != "example.com" {
			t.Errorf("Policy.Domain = %q, want example.com", res.Policy.Domain)
		}
		if res.EffectivePolicy != DispositionQuarantine {
			t.Errorf("EffectivePolicy = %s, want quarantine (sp=, not p=)", res.EffectivePolicy)
		}
	})

	t.Run("missing record resolves to none", func(t *testing.T) {
		z := resolve.NewZone()

		res, err := Evaluate(context.Background(), z, Input{HeaderFromDomain: "example.com"})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if res.Found {
			t.Fatal("Found = true, want false")
		}
		if res.Policy != nil {
			t.Errorf("Policy = %+v, want nil", res.Policy)
		}
		if res.EffectivePolicy != DispositionNone {
			t.Errorf("EffectivePolicy = %s, want none", res.EffectivePolicy)
		}
	})
}

func TestMissingRecordResolvesToNone(t *testing.T) {
	z := resolve.NewZone()
	z.NXDOMAIN("_dmarc.example.com")
	z.NXDOMAIN("_dmarc.example.org")

	res, err := Evaluate(context.Background(), z, Input{HeaderFromDomain: "mail.example.org"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Found {
		t.Fatal("Found = true, want false")
	}
	if res.Pass {
		t.Error("Pass = true, want false: no policy means nothing to align against as governing")
	}
}

func TestSamplingRateReportedNotApplied(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("_dmarc.example.com", "v=DMARC1; p=reject; pct=10")
	z.TXT("example.com", "v=spf1 ip4:192.0.2.1 -all")

	spfRes := evaluateSPF(t, z, "bounce@example.com", "mail.example.com", "192.0.2.1")

	in := Input{
		HeaderFromDomain: "example.com",
		SPF:              *spfRes,
		DKIMDomain:       "example.com",
		DKIMPass:         false,
	}

	var results []*Result
	for i := 0; i < 100; i++ {
		res, err := Evaluate(context.Background(), z, in)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		results = append(results, res)
	}

	first := results[0]
	for i, res := range results[1:] {
		if res.Pass != first.Pass {
			t.Fatalf("run %d: Pass = %v, want %v (identical to run 0)", i+1, res.Pass, first.Pass)
		}
		if res.EffectivePolicy != first.EffectivePolicy {
			t.Fatalf("run %d: EffectivePolicy = %s, want %s", i+1, res.EffectivePolicy, first.EffectivePolicy)
		}
		if len(res.Caveats) != len(first.Caveats) {
			t.Fatalf("run %d: Caveats = %v, want %v", i+1, res.Caveats, first.Caveats)
		}
	}

	if len(first.Caveats) == 0 {
		t.Fatal("Caveats is empty, want a pct caveat since pct=10")
	}
	found := false
	for _, c := range first.Caveats {
		if strings.Contains(c, "pct=10") && strings.Contains(c, "sample") {
			found = true
		}
	}
	if !found {
		t.Errorf("Caveats = %v, want an entry mentioning pct=10 and sampling", first.Caveats)
	}
}

func TestNullEnvelopeSenderMovesSubjectToHELO(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("_dmarc.example.com", "v=DMARC1; p=reject")
	z.TXT("mail.example.com", "v=spf1 ip4:192.0.2.1 -all")

	spfRes := evaluateSPF(t, z, "", "mail.example.com", "192.0.2.1")
	if spfRes.Subject != "mail.example.com" {
		t.Fatalf("setup: spf Subject = %q, want mail.example.com", spfRes.Subject)
	}

	res, err := Evaluate(context.Background(), z, Input{
		HeaderFromDomain: "example.com",
		SPF:              *spfRes,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Subject != "mail.example.com" {
		t.Errorf("Result.Subject = %q, want mail.example.com (the HELO Identity, envelope sender was null)", res.Subject)
	}
	if !strings.Contains(res.SubjectFrom, "helo") {
		t.Errorf("Result.SubjectFrom = %q, want it to name the HELO Identity", res.SubjectFrom)
	}
	if res.SPFAlignment.AuthenticatedDomain != "mail.example.com" {
		t.Errorf("SPFAlignment.AuthenticatedDomain = %q, want mail.example.com", res.SPFAlignment.AuthenticatedDomain)
	}
}

func TestDMARCPassRequiresAuthenticatedAndAligned(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("_dmarc.example.com", "v=DMARC1; p=reject")
	z.TXT("example.com", "v=spf1 ip4:192.0.2.1 -all")

	spfRes := evaluateSPF(t, z, "bounce@example.com", "mail.example.com", "203.0.113.9")
	if spfRes.Verdict != spf.Fail {
		t.Fatalf("setup: spf Verdict = %v, want fail", spfRes.Verdict)
	}

	res, err := Evaluate(context.Background(), z, Input{
		HeaderFromDomain: "example.com",
		SPF:              *spfRes,
		DKIMDomain:       "",
		DKIMPass:         false,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !res.SPFAlignment.Strict {
		t.Fatal("setup: SPFAlignment.Strict = false, want true (envelope-from and header-from are both example.com)")
	}
	if res.Pass {
		t.Error("Pass = true, want false: spf is aligned but did not actually pass")
	}
}

func TestDMARCPassesWhenSPFPassesAndAligns(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("_dmarc.example.com", "v=DMARC1; p=reject")
	z.TXT("example.com", "v=spf1 ip4:192.0.2.1 -all")

	spfRes := evaluateSPF(t, z, "bounce@example.com", "mail.example.com", "192.0.2.1")
	if spfRes.Verdict != spf.Pass {
		t.Fatalf("setup: spf Verdict = %v, want pass", spfRes.Verdict)
	}

	res, err := Evaluate(context.Background(), z, Input{
		HeaderFromDomain: "example.com",
		SPF:              *spfRes,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !res.Pass {
		t.Error("Pass = false, want true: spf passed and is strictly aligned")
	}
}

func TestDMARCPassesWhenDKIMPassesAndAligns(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("_dmarc.example.com", "v=DMARC1; p=reject")

	res, err := Evaluate(context.Background(), z, Input{
		HeaderFromDomain: "example.com",
		DKIMDomain:       "mail.example.com",
		DKIMPass:         true,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !res.DKIMAlignment.Relaxed {
		t.Fatal("setup: DKIMAlignment.Relaxed = false, want true")
	}
	if !res.Pass {
		t.Error("Pass = false, want true: dkim passed and is relaxed-aligned")
	}
}

func TestDMARCFailsWhenDKIMPassesButStrictRequiredAndNotAligned(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("_dmarc.example.com", "v=DMARC1; p=reject; adkim=s")

	res, err := Evaluate(context.Background(), z, Input{
		HeaderFromDomain: "example.com",
		DKIMDomain:       "mail.example.com",
		DKIMPass:         true,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.DKIMAlignment.Strict {
		t.Fatal("setup: DKIMAlignment.Strict = true, want false")
	}
	if res.Pass {
		t.Error("Pass = true, want false: adkim=s requires strict alignment, mail.example.com != example.com")
	}
}

func evaluateSPF(t *testing.T, z *resolve.Zone, sender, helo, clientIP string) *spf.Result {
	t.Helper()
	req := spf.Request{EnvelopeSender: sender, HeloIdentity: helo}
	if clientIP != "" {
		addr, err := netip.ParseAddr(clientIP)
		if err != nil {
			t.Fatalf("parse client ip %q: %v", clientIP, err)
		}
		ip, err := spf.NewCandidateSendingIP(addr, false)
		if err != nil {
			t.Fatalf("NewCandidateSendingIP: %v", err)
		}
		req.CandidateIP = &ip
	}
	res, err := spf.Evaluate(context.Background(), z, req)
	if err != nil {
		t.Fatalf("spf.Evaluate: %v", err)
	}
	return res
}
