package dkim

import (
	"reflect"
	"testing"
)

const realWorldRSAPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvHdY3ZC+2F6VEaTlUhLg+MrdX5Rikk69X8U6Z2G99JAXF4JFulcEkcFi2KfhiMxjLwSXcCBL3Zb0ONpcxx+2ic+DOJMiQBer2MDigyXl02Vi+Gstr2uMk7u5LaabJ4nE2YVrUwdzqhMNUbxja8EdbRA0l3/pAVzNpg5+Tn8tOvXGb3hCYrAqJWRkujE7s6dzVsbHZ2UBqDftOBmbL1PtaukmDM2DgHA67zGWT/4CUU/8R4xZ7OVJ5C3WKhKLgFmrK2XXBulv4zHttNUWkTCDVbEU4BmF5Wf2Zt5IYGAEjTMZcqytVmJ6eEoNdUFQxhf7vUXQBfJN8gHNTVyYEVLiRwIDAQAB"

const realWorldEd25519PublicKey = "tQ2Y/WKM0qdqNoeDpEyFsYZfwlPSNjwryzpY+SZvS8I="

func TestParseKeyRecord(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want Key
	}{
		{
			name: "rsa key with flags",
			raw:  "v=DKIM1; k=rsa; p=" + realWorldRSAPublicKey + "; t=y:s",
			want: Key{
				Version:   "DKIM1",
				KeyType:   "rsa",
				Algorithm: "RSA-2048",
				PublicKey: realWorldRSAPublicKey,
				Flags:     []string{"y", "s"},
				Faults:    []Fault{FaultTestMode},
			},
		},
		{
			name: "ed25519 key defaults to no flags",
			raw:  "v=DKIM1; k=ed25519; p=" + realWorldEd25519PublicKey,
			want: Key{
				Version:   "DKIM1",
				KeyType:   "ed25519",
				Algorithm: "Ed25519",
				PublicKey: realWorldEd25519PublicKey,
			},
		},
		{
			name: "missing k= defaults to rsa",
			raw:  "v=DKIM1; p=" + realWorldRSAPublicKey,
			want: Key{
				Version:   "DKIM1",
				KeyType:   "rsa",
				Algorithm: "RSA-2048",
				PublicKey: realWorldRSAPublicKey,
			},
		},
		{
			name: "whitespace inside p= is insignificant",
			raw:  "v=DKIM1; k=rsa; p=  " + realWorldRSAPublicKey[:20] + "\n  " + realWorldRSAPublicKey[20:] + "  ",
			want: Key{
				Version:   "DKIM1",
				KeyType:   "rsa",
				Algorithm: "RSA-2048",
				PublicKey: realWorldRSAPublicKey,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseKeyRecord(tt.raw)
			got.Raw = ""
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseKeyRecord(%q) = %+v, want %+v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestRealWorldKeyRecordParses(t *testing.T) {
	raw := "v=DKIM1; k=rsa; p=" + realWorldRSAPublicKey
	k := ParseKeyRecord(raw)

	if len(k.Faults) != 0 {
		t.Fatalf("expected no faults, got %v", k.Faults)
	}
	if k.Algorithm != "RSA-2048" {
		t.Fatalf("Algorithm = %q, want RSA-2048", k.Algorithm)
	}
	if k.PublicKey != realWorldRSAPublicKey {
		t.Fatalf("PublicKey mismatch")
	}
}

func TestKeyFaultsReported(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantFault Fault
	}{
		{
			name:      "revoked: empty p=",
			raw:       "v=DKIM1; k=rsa; p=",
			wantFault: FaultRevoked,
		},
		{
			name:      "revoked: whitespace-only p=",
			raw:       "v=DKIM1; k=rsa; p=   ",
			wantFault: FaultRevoked,
		},
		{
			name:      "missing p= entirely",
			raw:       "v=DKIM1; k=rsa",
			wantFault: FaultMissingPublicKey,
		},
		{
			name:      "test mode t=y",
			raw:       "v=DKIM1; k=rsa; p=" + realWorldRSAPublicKey + "; t=y",
			wantFault: FaultTestMode,
		},
		{
			name:      "bad base64",
			raw:       "v=DKIM1; k=rsa; p=not-valid-base64!!!",
			wantFault: FaultInvalidPublicKey,
		},
		{
			name:      "valid base64 but not a parseable key",
			raw:       "v=DKIM1; k=rsa; p=AAAA",
			wantFault: FaultInvalidPublicKey,
		},
		{
			name:      "wrong version",
			raw:       "v=DKIM2; k=rsa; p=" + realWorldRSAPublicKey,
			wantFault: FaultUnsupportedVersion,
		},
		{
			name:      "unparseable record",
			raw:       "this has no tag value pairs whatsoever",
			wantFault: FaultUnparseableRecord,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := ParseKeyRecord(tt.raw)
			found := false
			for _, f := range k.Faults {
				if f == tt.wantFault {
					found = true
				}
			}
			if !found {
				t.Fatalf("ParseKeyRecord(%q).Faults = %v, want to contain %s", tt.raw, k.Faults, tt.wantFault)
			}
		})
	}
}

func TestRevokedAndMissingAreDistinctFaults(t *testing.T) {
	revoked := ParseKeyRecord("v=DKIM1; k=rsa; p=")
	missing := ParseKeyRecord("v=DKIM1; k=rsa")

	if len(revoked.Faults) != 1 || revoked.Faults[0] != FaultRevoked {
		t.Fatalf("revoked record faults = %v, want [%s]", revoked.Faults, FaultRevoked)
	}
	if len(missing.Faults) != 1 || missing.Faults[0] != FaultMissingPublicKey {
		t.Fatalf("missing-p record faults = %v, want [%s]", missing.Faults, FaultMissingPublicKey)
	}
}

func TestFaultStringAndJSONRoundTrip(t *testing.T) {
	for f := FaultUnparseableRecord; f <= FaultTestMode; f++ {
		data, err := f.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON(%d): %v", int(f), err)
		}
		var got Fault
		if err := got.UnmarshalJSON(data); err != nil {
			t.Fatalf("UnmarshalJSON(%s): %v", data, err)
		}
		if got != f {
			t.Fatalf("round trip = %s, want %s", got, f)
		}
	}
}
