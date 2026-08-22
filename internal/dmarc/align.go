package dmarc

import (
	"context"
	"fmt"
	"strings"

	"github.com/MatrixMagician/Frank/internal/resolve"
	"github.com/MatrixMagician/Frank/internal/spf"
)

// Evaluate discovers the DMARC policy for in.HeaderFromDomain (walking up to
// the organizational domain approximation when no record exists at the
// domain itself, see orgDomain), computes SPF and DKIM Alignment in both
// modes, and decides whether the message passes DMARC. It never returns a
// probabilistic result: Pct is reported in Caveats and never consulted to
// decide Pass, so repeated calls with the same Input always agree.
func Evaluate(ctx context.Context, r resolve.Resolver, in Input) (*Result, error) {
	if in.HeaderFromDomain == "" {
		return nil, fmt.Errorf("dmarc: header from domain is required")
	}

	policy, fromSubdomain, domainUsed, err := discoverPolicy(ctx, r, in.HeaderFromDomain)
	if err != nil {
		return nil, err
	}
	if policy != nil {
		policy.Domain = domainUsed
		policy.FromSubdomain = fromSubdomain
	}

	spfAlignment := computeAlignment(IdentifierSPF, in.SPF.Subject, in.HeaderFromDomain)
	dkimAlignment := computeAlignment(IdentifierDKIM, in.DKIMDomain, in.HeaderFromDomain)

	aspf, adkim := ModeRelaxed, ModeRelaxed
	var effective Disposition
	var caveats []string
	if policy != nil {
		aspf, adkim = policy.ASPF, policy.ADKIM
		if fromSubdomain {
			effective = policy.SP
		} else {
			effective = policy.P
		}
		if policy.Pct < 100 {
			caveats = append(caveats, fmt.Sprintf("pct=%d: receivers apply this policy to only %d%% of messages that fail; this report describes what applies when a message is selected, not whether it is selected, since a verdict never samples", policy.Pct, policy.Pct))
		}
	}

	spfAligned := alignedFor(aspf, spfAlignment)
	dkimAligned := alignedFor(adkim, dkimAlignment)
	pass := (in.SPF.Verdict == spf.Pass && spfAligned) || (in.DKIMPass && dkimAligned)

	return &Result{
		Found:           policy != nil,
		Policy:          policy,
		SPFAlignment:    spfAlignment,
		DKIMAlignment:   dkimAlignment,
		Pass:            pass,
		EffectivePolicy: effective,
		Caveats:         caveats,
		Subject:         in.SPF.Subject,
		SubjectFrom:     in.SPF.SubjectFrom,
	}, nil
}

func alignedFor(mode Mode, a Alignment) bool {
	if mode == ModeStrict {
		return a.Strict
	}
	return a.Relaxed
}

// discoverPolicy looks up _dmarc.<domain>, falling back to the
// organizational-domain approximation (see orgDomain) when nothing valid is
// found there. It returns a nil Policy, not an error, when no valid record
// exists at either name.
func discoverPolicy(ctx context.Context, r resolve.Resolver, domain string) (policy *Policy, fromSubdomain bool, domainUsed string, err error) {
	p, err := lookupPolicy(ctx, r, domain)
	if err != nil {
		return nil, false, "", err
	}
	if p != nil {
		return p, false, domain, nil
	}

	org := orgDomain(domain)
	if strings.EqualFold(org, domain) {
		return nil, false, "", nil
	}

	p, err = lookupPolicy(ctx, r, org)
	if err != nil {
		return nil, false, "", err
	}
	if p == nil {
		return nil, false, "", nil
	}
	return p, true, org, nil
}

// lookupPolicy queries _dmarc.<domain> and returns the single valid DMARC
// record found there, or nil if the name has no records, does not exist, or
// (per RFC 7489 §6.6.3) carries more than one v=DMARC1 TXT record, which
// receivers are required to treat as no valid policy.
func lookupPolicy(ctx context.Context, r resolve.Resolver, domain string) (*Policy, error) {
	txts, err := r.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		if resolve.IsNotFound(err) || resolve.IsNoRecords(err) {
			return nil, nil
		}
		return nil, err
	}

	var found *Policy
	count := 0
	for _, t := range txts {
		if !IsDMARCRecord(t) {
			continue
		}
		count++
		p, perr := ParseRecord(t)
		if perr != nil {
			continue
		}
		found = p
	}
	if count != 1 {
		return nil, nil
	}
	return found, nil
}

// orgDomain approximates a domain's organizational domain by stripping the
// single leftmost label, treating a two-label (or shorter) name as already
// organizational. Go's standard library ships no public suffix list, and
// this package may not add a dependency to get one, so this is a documented
// approximation, not a real one: it is wrong for any public suffix with more
// than one label (co.uk, github.io, ...), and for a Header From nested more
// than one label below its true organizational domain it only walks up a
// single level. Callers relying on DMARC subdomain-policy resolution across
// such domains will see the wrong record. State this limitation whenever
// discoverPolicy's behaviour is reported.
func orgDomain(domain string) string {
	labels := strings.Split(strings.Trim(domain, "."), ".")
	if len(labels) <= 2 {
		return strings.ToLower(domain)
	}
	return strings.ToLower(strings.Join(labels[1:], "."))
}

func computeAlignment(id Identifier, authenticated, headerFrom string) Alignment {
	a := Alignment{
		Identifier:          id,
		AuthenticatedDomain: authenticated,
		HeaderFromDomain:    headerFrom,
	}
	if authenticated == "" || headerFrom == "" {
		return a
	}
	a.Strict = strings.EqualFold(authenticated, headerFrom)
	a.Relaxed = strings.EqualFold(orgDomain(authenticated), orgDomain(headerFrom))
	return a
}
