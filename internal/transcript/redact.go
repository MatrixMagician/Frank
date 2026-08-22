package transcript

import (
	"regexp"
	"strings"
)

const redactionMask = "[REDACTED]"

// Redactor masks matches of a set of RE2 patterns and a set of literal
// secrets at render time. It never touches a Transcript in memory; renderers
// call it only while writing bytes out.
//
// A Redactor is immutable, so the same one can be handed to both renderers.
// The masked-span count belongs to a single rendering, not to the Redactor,
// because both artefacts are always written and a count that accumulated
// across them would report a different number in each.
type Redactor struct {
	patterns []*regexp.Regexp
	literals []string
}

// NewRedactor compiles patterns once. A nil or empty Redactor is legal and
// still routes through Redact, so the redaction code path is exercised even
// when no pattern was supplied.
func NewRedactor(patterns []string) (*Redactor, error) {
	r := &Redactor{}
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		r.patterns = append(r.patterns, re)
	}
	return r, nil
}

// AddLiteral registers a secret to mask unconditionally, regardless of any
// --redact pattern. Issue #11 (SMTP AUTH, ADR-0007) uses this to mask
// credentials even when the operator supplied no --redact flag.
func (r *Redactor) AddLiteral(secret string) {
	if secret == "" {
		return
	}
	r.literals = append(r.literals, secret)
}

// pass is one rendering's worth of redaction. It carries the count so a
// Redactor stays reusable across both renderers.
type pass struct {
	r      *Redactor
	masked int
}

func (r *Redactor) newPass() *pass { return &pass{r: r} }

// mask masks every match of every pattern and literal in s, counting the spans
// it masks. On a pass over a nil Redactor it returns s unchanged: the count
// stays at zero and the same call path runs either way.
func (p *pass) mask(s string) string {
	if p.r == nil {
		return s
	}
	for _, literal := range p.r.literals {
		s = maskLiteral(s, literal, &p.masked)
	}
	for _, re := range p.r.patterns {
		s = re.ReplaceAllStringFunc(s, func(string) string {
			p.masked++
			return redactionMask
		})
	}
	return s
}

func (p *pass) count() int { return p.masked }

func maskLiteral(s, literal string, count *int) string {
	if literal == "" {
		return s
	}
	var out strings.Builder
	for {
		idx := strings.Index(s, literal)
		if idx < 0 {
			out.WriteString(s)
			break
		}
		out.WriteString(s[:idx])
		out.WriteString(redactionMask)
		*count++
		s = s[idx+len(literal):]
	}
	return out.String()
}

// Redact masks a single string and reports how many spans it masked, for
// callers outside the renderers.
func (r *Redactor) Redact(s string) (string, int) {
	p := r.newPass()
	return p.mask(s), p.count()
}
