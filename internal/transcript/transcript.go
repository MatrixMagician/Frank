package transcript

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

type Kind int

const (
	KindDial Kind = iota
	KindTLS
	KindSend
	KindRecv
	KindNote
	KindError
)

var kindNames = [...]string{"dial", "tls", "send", "recv", "note", "error"}

func (k Kind) String() string {
	if int(k) < 0 || int(k) >= len(kindNames) {
		return "unknown"
	}
	return kindNames[k]
}

func (k Kind) MarshalJSON() ([]byte, error) {
	if int(k) < 0 || int(k) >= len(kindNames) {
		return nil, fmt.Errorf("transcript: unknown kind %d", int(k))
	}
	return json.Marshal(k.String())
}

func (k *Kind) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for i, name := range kindNames {
		if name == s {
			*k = Kind(i)
			return nil
		}
	}
	return fmt.Errorf("transcript: unknown kind %q", s)
}

type Phase int

const (
	PhaseDial Phase = iota
	PhaseBanner
	PhaseEHLO
	PhaseSTARTTLS
	PhaseAuth
	PhaseMailFrom
	PhaseRcptTo
	PhaseData
	PhaseEndOfData
	PhaseQuit
)

var phaseNames = [...]string{
	"dial", "banner", "ehlo", "starttls", "auth",
	"mail-from", "rcpt-to", "data", "end-of-data", "quit",
}

func (p Phase) String() string {
	if int(p) < 0 || int(p) >= len(phaseNames) {
		return "unknown"
	}
	return phaseNames[p]
}

func (p Phase) MarshalJSON() ([]byte, error) {
	if int(p) < 0 || int(p) >= len(phaseNames) {
		return nil, fmt.Errorf("transcript: unknown phase %d", int(p))
	}
	return json.Marshal(p.String())
}

func (p *Phase) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for i, name := range phaseNames {
		if name == s {
			*p = Phase(i)
			return nil
		}
	}
	return fmt.Errorf("transcript: unknown phase %q", s)
}

// rawToLatin1 maps each byte 1:1 onto the Unicode code point of the same
// value. Every byte 0-255 is a valid rune, so the result is always valid
// UTF-8 and round-trips exactly, and ASCII SMTP traffic (the vast majority
// of what crosses the wire) renders as itself in the JSON document.
func rawToLatin1(raw []byte) string {
	runes := make([]rune, len(raw))
	for i, b := range raw {
		runes[i] = rune(b)
	}
	return string(runes)
}

func latin1ToRaw(s string) ([]byte, error) {
	runes := []rune(s)
	raw := make([]byte, len(runes))
	for i, r := range runes {
		if r < 0 || r > 0xff {
			return nil, fmt.Errorf("transcript: raw byte string contains out-of-range rune %U", r)
		}
		raw[i] = byte(r)
	}
	return raw, nil
}

type Event struct {
	Kind      Kind
	Phase     Phase
	Monotonic time.Duration
	Wall      time.Time
	Raw       []byte
	Reply     *Reply
	Note      string
}

type eventJSON struct {
	Kind      Kind          `json:"kind"`
	Phase     Phase         `json:"phase"`
	Monotonic time.Duration `json:"monotonic_ns"`
	Wall      time.Time     `json:"wall"`
	Raw       string        `json:"raw"`
	Reply     *Reply        `json:"reply,omitempty"`
	Note      string        `json:"note,omitempty"`
}

func (e Event) MarshalJSON() ([]byte, error) {
	return json.Marshal(eventJSON{
		Kind:      e.Kind,
		Phase:     e.Phase,
		Monotonic: e.Monotonic,
		Wall:      e.Wall,
		Raw:       rawToLatin1(e.Raw),
		Reply:     e.Reply,
		Note:      e.Note,
	})
}

func (e *Event) UnmarshalJSON(data []byte) error {
	var aux eventJSON
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	raw, err := latin1ToRaw(aux.Raw)
	if err != nil {
		return err
	}
	*e = Event{
		Kind:      aux.Kind,
		Phase:     aux.Phase,
		Monotonic: aux.Monotonic,
		Wall:      aux.Wall,
		Raw:       raw,
		Reply:     aux.Reply,
		Note:      aux.Note,
	}
	return nil
}

type IdentityTriple struct {
	EnvelopeSender string `json:"envelope_sender"`
	HeloIdentity   string `json:"helo_identity"`
	HeaderFrom     string `json:"header_from"`
}

// SourceAddress is the address Frank actually dialled the Target Host from,
// kept as a distinct type from any future Candidate Sending IP per
// docs/architecture.md's typed-identity rule, so the two can never collapse
// into one field by accident.
type SourceAddress struct {
	addr netip.Addr
}

func NewSourceAddress(addr netip.Addr) SourceAddress {
	return SourceAddress{addr: addr.Unmap()}
}

func (s SourceAddress) Addr() netip.Addr { return s.addr }

func (s SourceAddress) String() string {
	if !s.addr.IsValid() {
		return ""
	}
	return s.addr.String()
}

func (s SourceAddress) MarshalJSON() ([]byte, error) {
	if !s.addr.IsValid() {
		return json.Marshal("")
	}
	return json.Marshal(s.addr)
}

func (s *SourceAddress) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == "" {
		s.addr = netip.Addr{}
		return nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return err
	}
	s.addr = addr
	return nil
}

// TLSDetails is a placeholder issue #5 fills in. It stays a nil-able pointer
// on Transcript so an absent TLS negotiation renders as null/absent rather
// than as a zero-valued struct that looks like a claim about a real session.
type TLSDetails struct{}

type Transcript struct {
	Start      time.Time
	Events     []*Event
	TargetHost string
	Identity   IdentityTriple
	Recipient  string
	SourceAddr SourceAddress
	TLS        *TLSDetails
}

func NewTranscript(targetHost string, identity IdentityTriple, recipient string) *Transcript {
	return &Transcript{
		Start:      time.Now(),
		TargetHost: targetHost,
		Identity:   identity,
		Recipient:  recipient,
	}
}

// Append stamps both clocks so a caller cannot forget one, and returns the
// Event so Reply and Note can be filled in once the server answers. Events are
// held by pointer because a slice of values reallocates as it grows, which
// would silently discard a write through a pointer handed out earlier.
func (t *Transcript) Append(kind Kind, phase Phase, raw []byte) *Event {
	e := &Event{
		Kind:      kind,
		Phase:     phase,
		Monotonic: time.Since(t.Start),
		Wall:      time.Now(),
		Raw:       append([]byte(nil), raw...),
	}
	t.Events = append(t.Events, e)
	return e
}
