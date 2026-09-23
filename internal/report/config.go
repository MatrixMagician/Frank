// Package report holds Frank's config decoding and the single combined
// artefact a user pastes into a case, per issue #14.
package report

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is the JSON config file. Every field is a pointer so an absent key
// stays distinguishable from a key set to zero, which matters directly for
// `rate: 0` and `tls_verify: false`. See ADR-0005.
type Config struct {
	Target       *string  `json:"target,omitempty"`
	EnvelopeFrom *string  `json:"envelope_from,omitempty"`
	Helo         *string  `json:"helo,omitempty"`
	HeaderFrom   *string  `json:"header_from,omitempty"`
	Recipient    *string  `json:"recipient,omitempty"`
	Output       *string  `json:"output,omitempty"`
	Rate         *int     `json:"rate,omitempty"`
	TLS          *string  `json:"tls,omitempty"`
	TLSVerify    *bool    `json:"tls_verify,omitempty"`
	Redact       []string `json:"redact,omitempty"`
	Selectors    []string `json:"selectors,omitempty"`
	Username     *string  `json:"username,omitempty"`
	Password     *string  `json:"password,omitempty"`
	CandidateIP  *string  `json:"candidate_ip,omitempty"`
}

// Load reads and strictly decodes a config file. DisallowUnknownFields turns a
// mistyped key into an error naming it rather than a silently ignored default,
// which is half the reason ADR-0005 chose encoding/json in the first place.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &cfg, nil
}

// StringOr resolves a string setting: an explicitly-given flag wins, then the
// config, then the flag's own default.
func StringOr(explicit bool, flagValue string, configValue *string) string {
	if explicit {
		return flagValue
	}
	if configValue != nil {
		return *configValue
	}
	return flagValue
}

// IntOr resolves an int setting the same way, returning nil when neither the
// flag nor the config set it so a caller can still tell absent from zero.
func IntOr(explicit bool, flagValue int, configValue *int) *int {
	if explicit {
		v := flagValue
		return &v
	}
	return configValue
}

// BoolOr resolves a bool setting the same way.
func BoolOr(explicit bool, flagValue bool, configValue *bool) bool {
	if explicit {
		return flagValue
	}
	if configValue != nil {
		return *configValue
	}
	return flagValue
}

// StringsOr appends the config's list to the flag's, since both --redact and
// --selector are additive rather than overriding.
func StringsOr(flagValues []string, configValues []string) []string {
	out := append([]string(nil), flagValues...)
	return append(out, configValues...)
}
