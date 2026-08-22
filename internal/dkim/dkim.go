// Package dkim parses DKIM key records (RFC 6376 §3.6.1) and performs
// Selector Discovery (issue #9) against the resolve.Resolver seam (issue #7).
package dkim

import (
	"encoding/json"
	"fmt"
)

// Fault is the closed set of obvious problems a DKIM key record can carry.
// Modelled as a closed type with a String method, per docs/architecture.md's
// "Illegal states" rule, rather than a free-form string a caller could
// mistype or fail to check for.
type Fault int

const (
	// FaultUnparseableRecord means the TXT record's text could not be read
	// as any tag=value pairs at all.
	FaultUnparseableRecord Fault = iota
	// FaultUnsupportedVersion means v= was present and was not DKIM1.
	FaultUnsupportedVersion
	// FaultMissingPublicKey means the record had no p= tag at all.
	FaultMissingPublicKey
	// FaultRevoked means p= was present but empty: RFC 6376 §3.6.1 defines
	// this as the domain explicitly revoking the key, which is a distinct
	// fact from FaultMissingPublicKey (the domain never published a p= tag)
	// even though both leave PublicKey empty.
	FaultRevoked
	// FaultInvalidPublicKey means p= was present and non-empty but was not
	// valid base64, or did not parse as a public key of the declared type.
	FaultInvalidPublicKey
	// FaultTestMode means t= included the y flag.
	FaultTestMode
)

var faultNames = [...]string{
	"unparseable-record",
	"unsupported-version",
	"missing-public-key",
	"revoked",
	"invalid-public-key",
	"test-mode",
}

func (f Fault) String() string {
	if int(f) < 0 || int(f) >= len(faultNames) {
		return "unknown fault"
	}
	return faultNames[f]
}

func (f Fault) MarshalJSON() ([]byte, error) {
	if int(f) < 0 || int(f) >= len(faultNames) {
		return nil, fmt.Errorf("dkim: unknown fault %d", int(f))
	}
	return json.Marshal(f.String())
}

func (f *Fault) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for i, name := range faultNames {
		if name == s {
			*f = Fault(i)
			return nil
		}
	}
	return fmt.Errorf("dkim: unknown fault %q", s)
}

// Key is one parsed DKIM key record found at a selector.
type Key struct {
	Selector  string   `json:"selector"`
	Present   bool     `json:"present"`
	Version   string   `json:"version,omitempty"`
	KeyType   string   `json:"key_type,omitempty"`
	Algorithm string   `json:"algorithm,omitempty"`
	PublicKey string   `json:"public_key,omitempty"`
	Flags     []string `json:"flags,omitempty"`
	Faults    []Fault  `json:"faults,omitempty"`
	Raw       string   `json:"raw"`
}

// Options controls Selector Discovery: Selectors is added to the built-in
// common-selector list (SPEC.md's `--selector`, repeatable), and Bound caps
// the number of DNS queries Discover will make. A zero Bound means "no
// additional bound beyond the effective candidate list itself".
type Options struct {
	Selectors []string
	Bound     int
}

// Result is the outcome of Discover. Probed is the effective list of
// selectors actually queried and is always populated, per the glossary's
// Selector Discovery entry: a null Found reads as "these were checked and
// none answered" rather than as silence. Bound and QueriesMade make the
// query volume's cap and actual cost forensically visible alongside it.
type Result struct {
	Domain      string   `json:"domain"`
	Probed      []string `json:"probed"`
	Bound       int      `json:"bound"`
	QueriesMade int      `json:"queries_made"`
	Found       []Key    `json:"found"`
}
