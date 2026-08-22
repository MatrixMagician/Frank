package dkim

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

// ParseKeyRecord parses a DKIM key record's TXT text per RFC 6376 §3.6.1:
// semicolon-separated tag=value pairs, whitespace around tag names and
// values insignificant. It never returns an error; a record that cannot be
// read as tag=value pairs at all comes back with FaultUnparseableRecord and
// no other fields populated, since a DKIM fault is data to report, not a
// condition to propagate as a Go error.
func ParseKeyRecord(raw string) Key {
	k := Key{Raw: raw}

	tags, ok := parseTagValue(raw)
	if !ok {
		k.Faults = append(k.Faults, FaultUnparseableRecord)
		return k
	}

	if v, hasV := tags["v"]; hasV {
		k.Version = v
		if v != "DKIM1" {
			k.Faults = append(k.Faults, FaultUnsupportedVersion)
		}
	}

	k.KeyType = tags["k"]
	if k.KeyType == "" {
		k.KeyType = "rsa"
	}

	if t, hasT := tags["t"]; hasT {
		for _, flag := range strings.Split(t, ":") {
			flag = strings.TrimSpace(flag)
			if flag == "" {
				continue
			}
			k.Flags = append(k.Flags, flag)
			if flag == "y" {
				k.Faults = append(k.Faults, FaultTestMode)
			}
		}
	}

	p, hasP := tags["p"]
	switch {
	case !hasP:
		k.Faults = append(k.Faults, FaultMissingPublicKey)
	case stripWhitespace(p) == "":
		// An explicit empty p= is RFC 6376's revocation signal: the domain
		// published the tag and deliberately left it empty, a distinct
		// fact from never publishing p= at all (FaultMissingPublicKey).
		k.Faults = append(k.Faults, FaultRevoked)
	default:
		cleaned := stripWhitespace(p)
		algorithm, ok := decodePublicKey(k.KeyType, cleaned)
		if !ok {
			k.Faults = append(k.Faults, FaultInvalidPublicKey)
		} else {
			k.PublicKey = cleaned
			k.Algorithm = algorithm
		}
	}

	return k
}

// parseTagValue splits raw into its tag=value pairs. ok is false when a
// non-empty segment between semicolons has no "=" at all, which is not a
// tag-value pair by any reading of the ABNF.
func parseTagValue(raw string) (map[string]string, bool) {
	tags := make(map[string]string)
	any := false
	for _, segment := range strings.Split(raw, ";") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		idx := strings.IndexByte(segment, '=')
		if idx < 0 {
			return nil, false
		}
		name := strings.TrimSpace(segment[:idx])
		value := strings.TrimSpace(segment[idx+1:])
		if name == "" {
			return nil, false
		}
		tags[name] = value
		any = true
	}
	if !any {
		return nil, false
	}
	return tags, true
}

func stripWhitespace(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// decodePublicKey base64-decodes cleaned and reports the key's algorithm
// and size. RSA DKIM keys are published as a full X.509 SubjectPublicKeyInfo
// (RFC 6376 §3.6.1), so x509.ParsePKIXPublicKey is the primary path. Ed25519
// DKIM keys (RFC 8463) are published as the bare 32-byte key instead, never
// PKIX-wrapped, so that is tried as a fallback when keyType says ed25519.
func decodePublicKey(keyType, cleaned string) (algorithm string, ok bool) {
	der, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return "", false
	}

	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		switch pk := pub.(type) {
		case *rsa.PublicKey:
			return fmt.Sprintf("RSA-%d", pk.N.BitLen()), true
		case ed25519.PublicKey:
			return "Ed25519", true
		default:
			return "", true
		}
	}

	if keyType == "ed25519" && len(der) == ed25519.PublicKeySize {
		return "Ed25519", true
	}

	return "", false
}
