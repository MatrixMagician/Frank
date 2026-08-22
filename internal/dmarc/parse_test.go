package dmarc

import "testing"

func TestParsePolicyRecord(t *testing.T) {
	txt := "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=r; pct=50; rua=mailto:agg@example.com,mailto:agg2@example.com; ruf=mailto:forensic@example.com"

	p, err := ParseRecord(txt)
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	if p.P != DispositionReject {
		t.Errorf("P = %s, want reject", p.P)
	}
	if p.SP != DispositionQuarantine {
		t.Errorf("SP = %s, want quarantine", p.SP)
	}
	if p.ADKIM != ModeStrict {
		t.Errorf("ADKIM = %s, want strict", p.ADKIM)
	}
	if p.ASPF != ModeRelaxed {
		t.Errorf("ASPF = %s, want relaxed", p.ASPF)
	}
	if p.Pct != 50 {
		t.Errorf("Pct = %d, want 50", p.Pct)
	}
	if len(p.RUA) != 2 || p.RUA[0] != "mailto:agg@example.com" || p.RUA[1] != "mailto:agg2@example.com" {
		t.Errorf("RUA = %v, want two mailto addresses", p.RUA)
	}
	if len(p.RUF) != 1 || p.RUF[0] != "mailto:forensic@example.com" {
		t.Errorf("RUF = %v, want one mailto address", p.RUF)
	}
}

func TestParsePolicyRecordSPDefaultsToP(t *testing.T) {
	p, err := ParseRecord("v=DMARC1; p=quarantine")
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	if p.SP != DispositionQuarantine {
		t.Errorf("SP = %s, want quarantine (defaulted from p=)", p.SP)
	}
}

func TestParsePolicyRecordDefaults(t *testing.T) {
	p, err := ParseRecord("v=DMARC1; p=none")
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	if p.ADKIM != ModeRelaxed {
		t.Errorf("ADKIM default = %s, want relaxed", p.ADKIM)
	}
	if p.ASPF != ModeRelaxed {
		t.Errorf("ASPF default = %s, want relaxed", p.ASPF)
	}
	if p.Pct != 100 {
		t.Errorf("Pct default = %d, want 100", p.Pct)
	}
}

func TestParsePolicyRecordFoAndRf(t *testing.T) {
	p, err := ParseRecord("v=DMARC1; p=none; fo=0:1:d:s; rf=afrf")
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	if len(p.FO) != 4 {
		t.Errorf("FO = %v, want 4 entries", p.FO)
	}
	if len(p.RF) != 1 || p.RF[0] != "afrf" {
		t.Errorf("RF = %v, want [afrf]", p.RF)
	}
}

func TestParsePolicyRecordRequiresP(t *testing.T) {
	if _, err := ParseRecord("v=DMARC1; pct=50"); err == nil {
		t.Fatal("ParseRecord: want error for missing p=")
	}
}

func TestRecordNotStartingWithV1IsNotADMARCRecord(t *testing.T) {
	cases := []string{
		"p=reject; v=DMARC1",
		"v=DMARC2; p=reject",
		"some other text entirely",
		"v=spf1 -all",
	}
	for _, txt := range cases {
		if IsDMARCRecord(txt) {
			t.Errorf("IsDMARCRecord(%q) = true, want false", txt)
		}
		if _, err := ParseRecord(txt); err == nil {
			t.Errorf("ParseRecord(%q): want error, got none", txt)
		}
	}
}

func TestIsDMARCRecordAcceptsExactPrefix(t *testing.T) {
	if !IsDMARCRecord("v=DMARC1; p=none") {
		t.Error("IsDMARCRecord: want true for well-formed record")
	}
	if !IsDMARCRecord("v=DMARC1") {
		t.Error("IsDMARCRecord: want true for bare v= tag")
	}
}
