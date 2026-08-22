package dmarc

import (
	"fmt"
	"strings"
)

// Render writes a human-readable summary of res, structured so a forensics
// user can see both alignment modes and the reasons a Domain Pair did or
// did not pass, per issue #10's "explain the mismatch" purpose.
func Render(res *Result) string {
	var b strings.Builder

	fmt.Fprintf(&b, "subject: %s (from the %s)\n", res.Subject, res.SubjectFrom)

	if !res.Found {
		fmt.Fprintln(&b, "policy: none found")
	} else {
		p := res.Policy
		fmt.Fprintf(&b, "policy: domain=%s p=%s sp=%s adkim=%s aspf=%s pct=%d\n", p.Domain, p.P, p.SP, p.ADKIM, p.ASPF, p.Pct)
		if p.FromSubdomain {
			fmt.Fprintln(&b, "policy found on organizational domain, applying sp= to this subdomain message")
		}
		if len(p.RUA) > 0 {
			fmt.Fprintf(&b, "rua: %v\n", p.RUA)
		}
		if len(p.RUF) > 0 {
			fmt.Fprintf(&b, "ruf: %v\n", p.RUF)
		}
	}

	renderAlignment(&b, "spf", res.SPFAlignment)
	renderAlignment(&b, "dkim", res.DKIMAlignment)

	fmt.Fprintf(&b, "effective policy: %s\n", res.EffectivePolicy)
	fmt.Fprintf(&b, "dmarc: %s\n", passLabel(res.Pass))

	for _, c := range res.Caveats {
		fmt.Fprintf(&b, "caveat: %s\n", c)
	}

	return b.String()
}

func renderAlignment(b *strings.Builder, label string, a Alignment) {
	fmt.Fprintf(b, "%s alignment: authenticated=%q header-from=%q relaxed=%t strict=%t\n", label, a.AuthenticatedDomain, a.HeaderFromDomain, a.Relaxed, a.Strict)
}

func passLabel(pass bool) string {
	if pass {
		return "pass"
	}
	return "fail"
}
