package spf

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// expandMacros implements RFC 7208 §7 macro expansion. It is applied to the
// domain-spec of every mechanism that takes one, because a record is free to
// write `exists:%{i}._spf.example.com` and refusing to expand it would turn a
// valid record into a permerror.
//
// An unsupported or malformed macro returns an error rather than the literal
// text: a silently unexpanded %{p} would be looked up as a name containing a
// percent sign, which fails in a way that reads like a missing record instead
// of like the unsupported feature it is.
func (e *evaluator) expandMacros(spec, domain string, clientIP netip.Addr) (string, error) {
	if !strings.Contains(spec, "%") {
		return spec, nil
	}

	var out strings.Builder
	for i := 0; i < len(spec); {
		if spec[i] != '%' {
			out.WriteByte(spec[i])
			i++
			continue
		}
		if i+1 >= len(spec) {
			return "", fmt.Errorf("trailing %% in macro string %q", spec)
		}
		switch spec[i+1] {
		case '%':
			out.WriteByte('%')
			i += 2
		case '_':
			out.WriteByte(' ')
			i += 2
		case '-':
			out.WriteString("%20")
			i += 2
		case '{':
			end := strings.IndexByte(spec[i:], '}')
			if end < 0 {
				return "", fmt.Errorf("unterminated macro in %q", spec)
			}
			expanded, err := e.expandOne(spec[i+2:i+end], domain, clientIP)
			if err != nil {
				return "", err
			}
			out.WriteString(expanded)
			i += end + 1
		default:
			return "", fmt.Errorf("unknown macro escape %q in %q", spec[i:i+2], spec)
		}
	}
	return out.String(), nil
}

// expandOne expands the body of one %{...} macro: a letter, an optional digit
// count, an optional "r" to reverse, and optional delimiter characters.
func (e *evaluator) expandOne(body, domain string, clientIP netip.Addr) (string, error) {
	if body == "" {
		return "", fmt.Errorf("empty macro")
	}

	letter := body[0]
	rest := body[1:]

	value, err := e.macroValue(letter, domain, clientIP)
	if err != nil {
		return "", err
	}

	digits := 0
	for len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
		digits = digits*10 + int(rest[0]-'0')
		rest = rest[1:]
	}

	reverse := false
	if len(rest) > 0 && (rest[0] == 'r' || rest[0] == 'R') {
		reverse = true
		rest = rest[1:]
	}

	delimiters := "."
	if rest != "" {
		for _, c := range rest {
			if !strings.ContainsRune(".-+,/_=", c) {
				return "", fmt.Errorf("invalid macro delimiter %q", string(c))
			}
		}
		delimiters = rest
	}

	parts := splitAny(value, delimiters)
	if reverse {
		for l, r := 0, len(parts)-1; l < r; l, r = l+1, r-1 {
			parts[l], parts[r] = parts[r], parts[l]
		}
	}
	if digits > 0 && digits < len(parts) {
		parts = parts[len(parts)-digits:]
	}
	return strings.Join(parts, "."), nil
}

// macroValue resolves one macro letter. The uppercase forms are URL-escaped
// in RFC 7208; Frank only ever uses expanded specs as DNS names, where the
// escaping does not apply, so both cases resolve to the same value.
func (e *evaluator) macroValue(letter byte, domain string, clientIP netip.Addr) (string, error) {
	sender := e.subject
	if e.envelopeSender != "" {
		sender = e.envelopeSender
	}
	local, senderDomain := splitAddress(sender)

	switch letter {
	case 's', 'S':
		if sender == "" {
			return "postmaster@" + e.subject, nil
		}
		if !strings.Contains(sender, "@") {
			return "postmaster@" + sender, nil
		}
		return sender, nil
	case 'l', 'L':
		if local == "" {
			return "postmaster", nil
		}
		return local, nil
	case 'o', 'O':
		if senderDomain == "" {
			return e.subject, nil
		}
		return senderDomain, nil
	case 'd', 'D':
		return domain, nil
	case 'i', 'I':
		return dottedAddress(clientIP), nil
	case 'v', 'V':
		if clientIP.Is4() {
			return "in-addr", nil
		}
		return "ip6", nil
	case 'h', 'H':
		if e.helo == "" {
			return domain, nil
		}
		return e.helo, nil
	case 'c', 'C', 'r', 'R', 't', 'T':
		// These are only legal in exp= text, which Frank reports rather than
		// resolves, so reaching them from a mechanism is a malformed record.
		return "", fmt.Errorf("macro %%{%c} is not permitted outside exp=", letter)
	case 'p', 'P':
		// %{p} requires a validated PTR lookup, which RFC 7208 §7.3 itself
		// discourages. Refusing it is a permerror, which is honest; expanding
		// it to something plausible would produce a confident wrong Verdict.
		err := fmt.Errorf("macro %%{p} is not supported")
		e.limits = append(e.limits, Limit{Kind: LimitUnsupportedMacro, Domain: domain, Message: "spf: " + err.Error()})
		return "", err
	default:
		return "", fmt.Errorf("unknown macro letter %q", string(letter))
	}
}

// dottedAddress renders an address for %{i}: an IPv4 address in dotted-quad
// form, an IPv6 address as dot-separated nibbles per RFC 7208 §7.3.
func dottedAddress(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	b := addr.As16()
	nibbles := make([]string, 0, 32)
	for _, x := range b {
		nibbles = append(nibbles, strconv.FormatUint(uint64(x>>4), 16), strconv.FormatUint(uint64(x&0x0f), 16))
	}
	return strings.Join(nibbles, ".")
}

func splitAddress(addr string) (local, domain string) {
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return addr[:i], addr[i+1:]
	}
	return "", addr
}

func splitAny(s, delimiters string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return strings.ContainsRune(delimiters, r)
	})
}
