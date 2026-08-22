package transcript

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPhaseAndKindMarshalAsNames(t *testing.T) {
	kindTests := []struct {
		k    Kind
		want string
	}{
		{KindDial, `"dial"`},
		{KindTLS, `"tls"`},
		{KindSend, `"send"`},
		{KindRecv, `"recv"`},
		{KindNote, `"note"`},
		{KindError, `"error"`},
	}
	for _, tt := range kindTests {
		got, err := json.Marshal(tt.k)
		if err != nil {
			t.Fatalf("Marshal(%v): %v", tt.k, err)
		}
		if string(got) != tt.want {
			t.Errorf("Marshal(%v) = %s, want %s", tt.k, got, tt.want)
		}
		var back Kind
		if err := json.Unmarshal(got, &back); err != nil {
			t.Fatalf("Unmarshal(%s): %v", got, err)
		}
		if back != tt.k {
			t.Errorf("round trip = %v, want %v", back, tt.k)
		}
	}

	phaseTests := []struct {
		p    Phase
		want string
	}{
		{PhaseDial, `"dial"`},
		{PhaseBanner, `"banner"`},
		{PhaseEHLO, `"ehlo"`},
		{PhaseSTARTTLS, `"starttls"`},
		{PhaseAuth, `"auth"`},
		{PhaseMailFrom, `"mail-from"`},
		{PhaseRcptTo, `"rcpt-to"`},
		{PhaseData, `"data"`},
		{PhaseEndOfData, `"end-of-data"`},
		{PhaseQuit, `"quit"`},
	}
	for _, tt := range phaseTests {
		got, err := json.Marshal(tt.p)
		if err != nil {
			t.Fatalf("Marshal(%v): %v", tt.p, err)
		}
		if string(got) != tt.want {
			t.Errorf("Marshal(%v) = %s, want %s", tt.p, got, tt.want)
		}
		var back Phase
		if err := json.Unmarshal(got, &back); err != nil {
			t.Fatalf("Unmarshal(%s): %v", got, err)
		}
		if back != tt.p {
			t.Errorf("round trip = %v, want %v", back, tt.p)
		}
	}
}

func TestPhaseDataAndEndOfDataAreDistinctConstants(t *testing.T) {
	if PhaseData == PhaseEndOfData {
		t.Fatal("PhaseData and PhaseEndOfData must be separate constants")
	}
	if PhaseData.String() == PhaseEndOfData.String() {
		t.Fatal("PhaseData and PhaseEndOfData must render distinctly")
	}
}

func TestEveryEventCarriesBothClocksAndOrderIsMonotonic(t *testing.T) {
	tr := NewTranscript("mx.example.com", IdentityTriple{}, "rcpt@example.com")

	tr.Append(KindDial, PhaseDial, []byte("dial"))
	time.Sleep(time.Millisecond)
	tr.Append(KindRecv, PhaseBanner, []byte("220 mx.example.com ESMTP\r\n"))
	time.Sleep(time.Millisecond)
	tr.Append(KindSend, PhaseEHLO, []byte("EHLO client.example.com\r\n"))

	if len(tr.Events) != 3 {
		t.Fatalf("len(Events) = %d, want 3", len(tr.Events))
	}

	for i, e := range tr.Events {
		if e.Wall.IsZero() {
			t.Errorf("Events[%d].Wall is zero", i)
		}
		if i > 0 && e.Monotonic < tr.Events[i-1].Monotonic {
			t.Errorf("Events[%d].Monotonic = %v < Events[%d].Monotonic = %v, want non-decreasing",
				i, e.Monotonic, i-1, tr.Events[i-1].Monotonic)
		}
		if i > 0 && !e.Wall.After(tr.Events[i-1].Wall) && e.Wall != tr.Events[i-1].Wall {
			t.Errorf("Events[%d].Wall = %v not after Events[%d].Wall = %v", i, e.Wall, i-1, tr.Events[i-1].Wall)
		}
	}
}

func TestAppendReturnsPointerIntoTranscriptForFillIn(t *testing.T) {
	tr := NewTranscript("mx.example.com", IdentityTriple{}, "rcpt@example.com")
	ev := tr.Append(KindRecv, PhaseBanner, []byte("220 hi\r\n"))
	reply, err := ParseReply([]byte("220 hi\r\n"))
	if err != nil {
		t.Fatalf("ParseReply: %v", err)
	}
	ev.Reply = reply

	if tr.Events[0].Reply == nil || tr.Events[0].Reply.Code != 220 {
		t.Fatalf("Events[0].Reply = %+v, want code 220 filled in via the returned pointer", tr.Events[0].Reply)
	}
}

func buildSampleTranscript() *Transcript {
	tr := NewTranscript("mx.example.com", IdentityTriple{
		EnvelopeSender: "envelope@example.com",
		HeloIdentity:   "client.example.com",
		HeaderFrom:     "header@example.com",
	}, "rcpt@example.com")

	tr.Append(KindDial, PhaseDial, []byte("dial mx.example.com:25"))
	e := tr.Append(KindRecv, PhaseBanner, []byte("220 mx.example.com ESMTP\r\n"))
	e.Reply, _ = ParseReply(e.Raw)

	tr.Append(KindSend, PhaseEHLO, []byte("EHLO client.example.com\r\n"))
	e = tr.Append(KindRecv, PhaseEHLO, []byte("250-mx.example.com\r\n250-STARTTLS\r\n250 SIZE 10240000\r\n"))
	e.Reply, _ = ParseReply(e.Raw)

	e = tr.Append(KindRecv, PhaseEndOfData, []byte("550 5.7.1 Sender rejected\r\n"))
	e.Reply, _ = ParseReply(e.Raw)
	e.Note = "rejected at end-of-data"

	return tr
}

func TestHandConstructedTranscriptRendersBothFormats(t *testing.T) {
	tr := buildSampleTranscript()
	r, err := NewRedactor(nil)
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}

	var textBuf bytes.Buffer
	if err := RenderText(&textBuf, tr, r); err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	text := textBuf.String()
	if !strings.Contains(text, "mx.example.com") {
		t.Error("text render missing target host")
	}
	if !strings.Contains(text, "end-of-data") {
		t.Error("text render missing end-of-data phase")
	}
	if !strings.Contains(text, "550") {
		t.Error("text render missing rejection code")
	}

	var jsonBuf bytes.Buffer
	if err := RenderJSON(&jsonBuf, tr, r); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(jsonBuf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v\n%s", err, jsonBuf.String())
	}
	if decoded["target_host"] != "mx.example.com" {
		t.Errorf("target_host = %v, want mx.example.com", decoded["target_host"])
	}
	events, ok := decoded["events"].([]interface{})
	if !ok || len(events) != 5 {
		t.Fatalf("events = %v, want 5 entries", decoded["events"])
	}
}

func TestRenderingLeavesTranscriptUnchanged(t *testing.T) {
	tr := buildSampleTranscript()
	r, err := NewRedactor([]string{`example\.com`})
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}

	before := make([]string, len(tr.Events))
	for i, e := range tr.Events {
		before[i] = string(e.Raw)
	}

	var textBuf, jsonBuf bytes.Buffer
	if err := RenderText(&textBuf, tr, r); err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	if err := RenderJSON(&jsonBuf, tr, r); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	if !strings.Contains(textBuf.String(), "[REDACTED]") {
		t.Fatal("expected the redaction pattern to have matched in the text render")
	}

	for i, e := range tr.Events {
		if string(e.Raw) != before[i] {
			t.Errorf("Events[%d].Raw changed after rendering: got %q, want %q", i, e.Raw, before[i])
		}
	}
}

func TestJSONRoundTripsRawBytes(t *testing.T) {
	raw := []byte{0x00, 0x01, 0xff, 0xfe, 'h', 'i', '\r', '\n', 0x80, 0xc3, 0x28}
	e := Event{
		Kind:      KindRecv,
		Phase:     PhaseBanner,
		Monotonic: 5 * time.Millisecond,
		Wall:      time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC),
		Raw:       raw,
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var back Event
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !bytes.Equal(back.Raw, raw) {
		t.Errorf("round-tripped Raw = %v, want %v", back.Raw, raw)
	}
}

func TestSourceAddressAbsentRendersEmpty(t *testing.T) {
	var s SourceAddress
	if s.String() != "" {
		t.Errorf("zero SourceAddress.String() = %q, want empty", s.String())
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(data) != `""` {
		t.Errorf("Marshal(zero SourceAddress) = %s, want empty string", data)
	}
}

func TestTLSDetailsNilRendersAbsent(t *testing.T) {
	tr := buildSampleTranscript()
	if tr.TLS != nil {
		t.Fatal("TLS field must default to nil until issue #5 fills it in")
	}
	r, _ := NewRedactor(nil)
	var buf bytes.Buffer
	if err := RenderJSON(&buf, tr, r); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded["tls"] != nil {
		t.Errorf("tls = %v, want null/absent", decoded["tls"])
	}
}

func TestAppendedEventStaysWritableAfterLaterAppends(t *testing.T) {
	tr := NewTranscript("smtp.example.com", IdentityTriple{}, "rcpt@example.com")

	first := tr.Append(KindSend, PhaseEHLO, []byte("EHLO frank.invalid\r\n"))
	for range 8 {
		tr.Append(KindSend, PhaseMailFrom, []byte("MAIL FROM:<a@example.com>\r\n"))
	}
	first.Note = "filled in once the server answered"

	if tr.Events[0].Note != "filled in once the server answered" {
		t.Fatalf("Events[0].Note = %q, want the note written through the returned pointer", tr.Events[0].Note)
	}
}
