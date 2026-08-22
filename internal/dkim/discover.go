package dkim

import (
	"context"
	"fmt"

	"github.com/MatrixMagician/Frank/internal/resolve"
)

// builtinSelectors is the compiled-in common-selector list SPEC.md's
// `--selector` paragraph requires: there is no selector file, so this table
// plus any explicit --selector values is the entire candidate set. Held as
// a table per docs/architecture.md's "Illegal states" rule for repeated
// data, not built up by scattered append calls.
var builtinSelectors = []string{
	"default", "google", "selector1", "selector2", "s1", "s2", "k1", "k2",
	"mail", "dkim", "mandrill", "mailjet", "sendgrid", "zoho",
	"everlytickey1", "everlytickey2", "smtp", "key1", "key2", "mx",
	"protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3",
	"amazonses", "postmark", "sparkpost", "mtasv", "turbo-smtp", "ctct1", "ctct2",
}

// effectiveSelectors returns the built-in list followed by any explicit
// selectors not already present in it, deduplicated and in a deterministic
// order, so a forensics artefact is reproducible run to run.
func effectiveSelectors(explicit []string) []string {
	seen := make(map[string]bool, len(builtinSelectors)+len(explicit))
	out := make([]string, 0, len(builtinSelectors)+len(explicit))
	for _, s := range builtinSelectors {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range explicit {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// Discover probes domain for DKIM key records, per selector, over the
// effective selector list (the built-in list plus opts.Selectors,
// deduplicated). Probed always holds the full effective list regardless of
// how many queries the Bound allowed, so a null Found still reads as
// "these were checked and none answered" per the glossary's Selector
// Discovery entry.
func Discover(ctx context.Context, r resolve.Resolver, domain string, opts Options) (*Result, error) {
	probed := effectiveSelectors(opts.Selectors)

	bound := opts.Bound
	if bound <= 0 {
		bound = len(probed)
	}

	res := &Result{
		Domain: domain,
		Probed: probed,
		Bound:  bound,
	}

	for _, selector := range probed {
		if res.QueriesMade >= bound {
			break
		}
		res.QueriesMade++

		name := fmt.Sprintf("%s._domainkey.%s", selector, domain)
		txts, err := r.LookupTXT(ctx, name)
		if err != nil {
			if resolve.IsTemporary(err) {
				return nil, err
			}
			continue
		}

		for _, txt := range txts {
			k := ParseKeyRecord(txt)
			k.Selector = selector
			k.Present = true
			res.Found = append(res.Found, k)
		}
	}

	return res, nil
}
