package spf

import (
	"fmt"
	"strconv"
	"strings"
)

var mechanismKindByName = func() map[string]MechanismKind {
	m := make(map[string]MechanismKind, len(mechanismNames))
	for i, name := range mechanismNames {
		m[name] = MechanismKind(i)
	}
	return m
}()

const spfPrefix = "v=spf1"

// IsSPFRecord reports whether a TXT record's text is an SPF record: it
// starts with the literal "v=spf1" and is either exactly that or followed
// by a space, per RFC 7208 §4.5. A prefix match alone would wrongly accept
// "v=spf10...".
func IsSPFRecord(txt string) bool {
	if !strings.HasPrefix(txt, spfPrefix) {
		return false
	}
	return len(txt) == len(spfPrefix) || txt[len(spfPrefix)] == ' '
}

// ParseRecord parses the terms of an SPF record whose text has already been
// confirmed by IsSPFRecord. Terms are separated by runs of whitespace, per
// RFC 7208's ABNF.
func ParseRecord(txt string) ([]Mechanism, error) {
	if !IsSPFRecord(txt) {
		return nil, fmt.Errorf("spf: not an spf record: %q", txt)
	}
	fields := strings.Fields(txt)
	terms := make([]Mechanism, 0, len(fields))
	for _, f := range fields[1:] {
		term, err := parseTerm(f)
		if err != nil {
			return nil, err
		}
		terms = append(terms, term)
	}
	return terms, nil
}

func parseTerm(raw string) (Mechanism, error) {
	rest := raw
	qualifier := QualifierPass
	hasQualifier := false
	if rest != "" {
		switch rest[0] {
		case '+':
			qualifier, hasQualifier, rest = QualifierPass, true, rest[1:]
		case '-':
			qualifier, hasQualifier, rest = QualifierFail, true, rest[1:]
		case '~':
			qualifier, hasQualifier, rest = QualifierSoftFail, true, rest[1:]
		case '?':
			qualifier, hasQualifier, rest = QualifierNeutral, true, rest[1:]
		}
	}
	if rest == "" {
		return Mechanism{}, fmt.Errorf("spf: empty term %q", raw)
	}

	nameEnd := len(rest)
	sep := byte(0)
	for i := 0; i < len(rest); i++ {
		if rest[i] == ':' || rest[i] == '=' || rest[i] == '/' {
			nameEnd = i
			sep = rest[i]
			break
		}
	}
	name := strings.ToLower(rest[:nameEnd])

	// A modifier never carries a qualifier: "+redirect=..." is not valid
	// syntax, so a qualifier prefix commits the term to being a mechanism.
	if !hasQualifier && sep == '=' {
		value := rest[nameEnd+1:]
		modName := name
		if modName != "redirect" && modName != "exp" {
			// Unrecognized modifiers MUST be ignored per RFC 7208 §6,
			// unlike unrecognized mechanisms, which are a permerror.
			return Mechanism{IsMechanism: false, ModifierName: modName, Domain: value, Raw: raw}, nil
		}
		return Mechanism{IsMechanism: false, ModifierName: modName, Domain: value, Raw: raw}, nil
	}

	kind, ok := mechanismKindByName[name]
	if !ok {
		return Mechanism{}, fmt.Errorf("spf: unknown mechanism %q", name)
	}
	return parseMechanismBody(qualifier, kind, rest[nameEnd:], raw)
}

func parseMechanismBody(qualifier Qualifier, kind MechanismKind, body, raw string) (Mechanism, error) {
	m := Mechanism{Qualifier: qualifier, IsMechanism: true, Kind: kind, Raw: raw}
	switch kind {
	case MechAll:
		if body != "" {
			return Mechanism{}, fmt.Errorf("spf: all mechanism takes no argument in %q", raw)
		}
	case MechInclude, MechExists:
		if len(body) < 2 || body[0] != ':' {
			return Mechanism{}, fmt.Errorf("spf: %s mechanism requires a domain in %q", mechanismNames[kind], raw)
		}
		m.Domain = body[1:]
	case MechIP4, MechIP6:
		if len(body) < 2 || body[0] != ':' {
			return Mechanism{}, fmt.Errorf("spf: %s mechanism requires an address in %q", mechanismNames[kind], raw)
		}
		m.Domain = body[1:]
	case MechA, MechMX:
		cidrPart := body
		if strings.HasPrefix(body, ":") {
			rest := body[1:]
			domainPart := rest
			if idx := strings.IndexByte(rest, '/'); idx >= 0 {
				domainPart = rest[:idx]
				cidrPart = rest[idx:]
			} else {
				cidrPart = ""
			}
			if domainPart == "" {
				return Mechanism{}, fmt.Errorf("spf: %s mechanism has an empty domain in %q", mechanismNames[kind], raw)
			}
			m.Domain = domainPart
		}
		cidr4, hasCIDR4, cidr6, hasCIDR6, err := parseDualCIDR(cidrPart)
		if err != nil {
			return Mechanism{}, fmt.Errorf("spf: %s mechanism: %w in %q", mechanismNames[kind], err, raw)
		}
		m.CIDR4, m.HasCIDR4, m.CIDR6, m.HasCIDR6 = cidr4, hasCIDR4, cidr6, hasCIDR6
	case MechPTR:
		if strings.HasPrefix(body, ":") {
			m.Domain = body[1:]
			if m.Domain == "" {
				return Mechanism{}, fmt.Errorf("spf: ptr mechanism has an empty domain in %q", raw)
			}
		} else if body != "" {
			return Mechanism{}, fmt.Errorf("spf: ptr mechanism takes no cidr length in %q", raw)
		}
	}
	return m, nil
}

// parseDualCIDR parses the dual-cidr-length suffix of an a/mx mechanism:
// "", "/24", "//64" or "/24//64", per RFC 7208 §5.6's ABNF. There is no
// separator between the ip4 and ip6 parts other than the second slash
// belonging to ip6-cidr-length itself, which is what makes "/24//64" and
// "//64" (v6-only) parse unambiguously against this grammar.
func parseDualCIDR(raw string) (cidr4 int, hasCIDR4 bool, cidr6 int, hasCIDR6 bool, err error) {
	if raw == "" {
		return 0, false, 0, false, nil
	}
	if strings.HasPrefix(raw, "//") {
		cidr6, err = parseCIDRDigits(raw[2:], 128)
		if err != nil {
			return 0, false, 0, false, err
		}
		return 0, false, cidr6, true, nil
	}
	if !strings.HasPrefix(raw, "/") {
		return 0, false, 0, false, fmt.Errorf("spf: malformed cidr length %q", raw)
	}
	rest := raw[1:]
	if idx := strings.Index(rest, "//"); idx >= 0 {
		cidr4, err = parseCIDRDigits(rest[:idx], 32)
		if err != nil {
			return 0, false, 0, false, err
		}
		cidr6, err = parseCIDRDigits(rest[idx+2:], 128)
		if err != nil {
			return 0, false, 0, false, err
		}
		return cidr4, true, cidr6, true, nil
	}
	cidr4, err = parseCIDRDigits(rest, 32)
	if err != nil {
		return 0, false, 0, false, err
	}
	return cidr4, true, 0, false, nil
}

func parseCIDRDigits(s string, max int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("cidr length %q is not a number", s)
	}
	if n < 0 || n > max {
		return 0, fmt.Errorf("cidr length %d out of range 0-%d", n, max)
	}
	return n, nil
}
