package spf

import "testing"

func TestParseRecordQualifiers(t *testing.T) {
	terms, err := ParseRecord("v=spf1 +a -mx ~ptr ?exists:x.example all")
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	want := []Qualifier{QualifierPass, QualifierFail, QualifierSoftFail, QualifierNeutral, QualifierPass}
	if len(terms) != len(want) {
		t.Fatalf("got %d terms, want %d", len(terms), len(want))
	}
	for i, q := range want {
		if terms[i].Qualifier != q {
			t.Errorf("term %d qualifier = %v, want %v", i, terms[i].Qualifier, q)
		}
	}
}

func TestParseRecordDualCIDR(t *testing.T) {
	tests := []struct {
		raw      string
		hasCIDR4 bool
		cidr4    int
		hasCIDR6 bool
		cidr6    int
	}{
		{"a:example.com", false, 0, false, 0},
		{"a:example.com/24", true, 24, false, 0},
		{"a:example.com//64", false, 0, true, 64},
		{"a:example.com/24//64", true, 24, true, 64},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			terms, err := ParseRecord("v=spf1 " + tt.raw + " -all")
			if err != nil {
				t.Fatalf("ParseRecord(%q): %v", tt.raw, err)
			}
			got := terms[0]
			if got.HasCIDR4 != tt.hasCIDR4 || got.CIDR4 != tt.cidr4 {
				t.Errorf("CIDR4 = (%v,%d), want (%v,%d)", got.HasCIDR4, got.CIDR4, tt.hasCIDR4, tt.cidr4)
			}
			if got.HasCIDR6 != tt.hasCIDR6 || got.CIDR6 != tt.cidr6 {
				t.Errorf("CIDR6 = (%v,%d), want (%v,%d)", got.HasCIDR6, got.CIDR6, tt.hasCIDR6, tt.cidr6)
			}
		})
	}
}

func TestParseRecordRedirectModifier(t *testing.T) {
	terms, err := ParseRecord("v=spf1 -all redirect=other.example")
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	if len(terms) != 2 {
		t.Fatalf("got %d terms, want 2", len(terms))
	}
	redirect := terms[1]
	if redirect.IsMechanism {
		t.Error("redirect parsed as a mechanism, want a modifier")
	}
	if redirect.ModifierName != "redirect" || redirect.Domain != "other.example" {
		t.Errorf("redirect = %+v, want name=redirect domain=other.example", redirect)
	}
}

func TestParseRecordUnknownModifierIsIgnored(t *testing.T) {
	terms, err := ParseRecord("v=spf1 unknown=whatever -all")
	if err != nil {
		t.Fatalf("ParseRecord: %v, want unknown modifiers ignored per RFC 7208 section 6", err)
	}
	if len(terms) != 2 {
		t.Fatalf("got %d terms, want 2 (the ignored modifier plus -all)", len(terms))
	}
	if terms[0].IsMechanism {
		t.Error("unknown=whatever parsed as a mechanism")
	}
}

func TestParseRecordAllTakesNoArgument(t *testing.T) {
	if _, err := ParseRecord("v=spf1 all:x"); err == nil {
		t.Error("all:x parsed without error, want a parse error: all takes no argument")
	}
}

func TestParseRecordIncludeRequiresDomain(t *testing.T) {
	if _, err := ParseRecord("v=spf1 include -all"); err == nil {
		t.Error("bare include parsed without error, want a parse error: include requires a domain")
	}
}

func TestParseRecordRejectsNonSPFText(t *testing.T) {
	if _, err := ParseRecord("google-site-verification=abc123"); err == nil {
		t.Error("a non-spf TXT string was parsed as a record")
	}
}
