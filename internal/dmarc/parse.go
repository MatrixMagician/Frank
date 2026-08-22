package dmarc

import (
	"fmt"
	"strconv"
	"strings"
)

const dmarcPrefix = "v=DMARC1"

// IsDMARCRecord reports whether a TXT record's text is a DMARC record: the
// first tag is literally v=DMARC1, per RFC 7489 §6.3 which requires v= to
// be first and requires this exact value. A record whose v= tag is anywhere
// else, or carries any other value, is not a DMARC record.
func IsDMARCRecord(txt string) bool {
	first, _, _ := strings.Cut(txt, ";")
	return strings.EqualFold(strings.TrimSpace(first), dmarcPrefix)
}

// ParseRecord parses a DMARC policy record's tag=value pairs, already
// confirmed by IsDMARCRecord to start with v=DMARC1. Unknown tags are
// ignored per RFC 7489 §6.3's "unknown tags MUST be ignored". p= is
// required; every other tag has a default.
func ParseRecord(txt string) (*Policy, error) {
	if !IsDMARCRecord(txt) {
		return nil, fmt.Errorf("dmarc: not a dmarc record: %q", txt)
	}

	p := &Policy{
		Version: dmarcPrefix,
		ADKIM:   ModeRelaxed,
		ASPF:    ModeRelaxed,
		Pct:     100,
		RI:      86400,
		Raw:     txt,
	}

	sawP := false
	for _, field := range strings.Split(txt, ";") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		tag, value, ok := strings.Cut(field, "=")
		if !ok {
			return nil, fmt.Errorf("dmarc: malformed tag %q", field)
		}
		tag = strings.TrimSpace(tag)
		value = strings.TrimSpace(value)
		if strings.EqualFold(tag, "v") {
			continue
		}

		switch strings.ToLower(tag) {
		case "p":
			d, err := parseDisposition(value)
			if err != nil {
				return nil, err
			}
			p.P = d
			p.SP = d
			sawP = true
		case "sp":
			d, err := parseDisposition(value)
			if err != nil {
				return nil, err
			}
			p.SP = d
		case "adkim":
			m, err := parseMode(value)
			if err != nil {
				return nil, err
			}
			p.ADKIM = m
		case "aspf":
			m, err := parseMode(value)
			if err != nil {
				return nil, err
			}
			p.ASPF = m
		case "pct":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 100 {
				return nil, fmt.Errorf("dmarc: invalid pct %q", value)
			}
			p.Pct = n
		case "rua":
			p.RUA = splitCommaList(value)
		case "ruf":
			p.RUF = splitCommaList(value)
		case "fo":
			p.FO = splitColonList(value)
		case "rf":
			p.RF = splitColonList(value)
		case "ri":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("dmarc: invalid ri %q", value)
			}
			p.RI = n
		}
	}

	if !sawP {
		return nil, fmt.Errorf("dmarc: missing required p= tag")
	}
	return p, nil
}

func parseDisposition(value string) (Disposition, error) {
	switch strings.ToLower(value) {
	case "none":
		return DispositionNone, nil
	case "quarantine":
		return DispositionQuarantine, nil
	case "reject":
		return DispositionReject, nil
	default:
		return 0, fmt.Errorf("dmarc: unknown disposition %q", value)
	}
}

func parseMode(value string) (Mode, error) {
	switch strings.ToLower(value) {
	case "r":
		return ModeRelaxed, nil
	case "s":
		return ModeStrict, nil
	default:
		return 0, fmt.Errorf("dmarc: unknown alignment mode %q", value)
	}
}

// splitCommaList splits rua= and ruf=, whose values are comma-separated
// mailto: URIs per RFC 7489 §6.2.
func splitCommaList(value string) []string {
	return splitTrimmed(value, ",")
}

// splitColonList splits fo= and rf=, whose values are colon-separated
// tokens per RFC 7489 §6.3.
func splitColonList(value string) []string {
	return splitTrimmed(value, ":")
}

func splitTrimmed(value, sep string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
