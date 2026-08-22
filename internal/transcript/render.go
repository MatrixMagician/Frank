package transcript

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func directionMark(k Kind) string {
	switch k {
	case KindSend:
		return "-->"
	case KindRecv:
		return "<--"
	case KindDial:
		return "***"
	case KindTLS:
		return "+++"
	case KindError:
		return "!!!"
	default:
		return "..."
	}
}

// RenderText writes a human-readable annotated log. It never mutates t;
// redaction happens only on the bytes written to w.
func RenderText(w io.Writer, t *Transcript, r *Redactor) error {
	p := r.newPass()
	var body bytes.Buffer
	fmt.Fprintf(&body, "target: %s\n", t.TargetHost)
	fmt.Fprintf(&body, "recipient: %s\n", p.mask(t.Recipient))
	fmt.Fprintf(&body, "envelope-sender: %s\n", p.mask(t.Identity.EnvelopeSender))
	fmt.Fprintf(&body, "helo-identity: %s\n", p.mask(t.Identity.HeloIdentity))
	fmt.Fprintf(&body, "header-from: %s\n", p.mask(t.Identity.HeaderFrom))
	fmt.Fprintf(&body, "source-address: %s\n", t.SourceAddr.String())
	fmt.Fprintln(&body, "---")

	for _, e := range t.Events {
		raw := p.mask(rawToLatin1(e.Raw))
		fmt.Fprintf(&body, "[%12s] %-11s %s %s\n", e.Monotonic, e.Phase, directionMark(e.Kind), quoteForText(raw))
		if e.Note != "" {
			fmt.Fprintf(&body, "%25s note: %s\n", "", p.mask(e.Note))
		}
		if e.Reply != nil {
			enh := "-"
			if e.Reply.Enhanced != nil {
				enh = e.Reply.Enhanced.String()
			}
			fmt.Fprintf(&body, "%25s reply: code=%d enhanced=%s text=%q\n", "", e.Reply.Code, enh, p.mask(e.Reply.Text))
		}
	}

	fmt.Fprintln(&body, "---")
	fmt.Fprintf(&body, "redacted-spans: %d\n", p.count())

	_, err := w.Write(body.Bytes())
	return err
}

func quoteForText(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch b := s[i]; b {
		case '\r':
			out = append(out, '\\', 'r')
		case '\n':
			out = append(out, '\\', 'n')
		default:
			out = append(out, b)
		}
	}
	return string(out)
}

type transcriptJSON struct {
	Start         string         `json:"start"`
	TargetHost    string         `json:"target_host"`
	Identity      IdentityTriple `json:"identity"`
	Recipient     string         `json:"recipient"`
	SourceAddress string         `json:"source_address"`
	TLS           *TLSDetails    `json:"tls"`
	Events        []eventJSON    `json:"events"`
	RedactedSpans int            `json:"redacted_spans"`
}

// RenderJSON writes the JSON document. It never mutates t: every string
// that reaches the encoder is a redacted copy, built directly rather than
// by mutating and re-marshalling an Event, so t's own bytes are untouched.
func RenderJSON(w io.Writer, t *Transcript, r *Redactor) error {
	p := r.newPass()
	events := make([]eventJSON, len(t.Events))
	for i, e := range t.Events {
		ej := eventJSON{
			Kind:      e.Kind,
			Phase:     e.Phase,
			Monotonic: e.Monotonic,
			Wall:      e.Wall,
			Raw:       p.mask(rawToLatin1(e.Raw)),
			Note:      p.mask(e.Note),
		}
		if e.Reply != nil {
			replyCopy := *e.Reply
			replyCopy.Text = p.mask(e.Reply.Text)
			ej.Reply = &replyCopy
		}
		events[i] = ej
	}

	doc := transcriptJSON{
		Start:      t.Start.Format(rfc3339Nano),
		TargetHost: t.TargetHost,
		Identity: IdentityTriple{
			EnvelopeSender: p.mask(t.Identity.EnvelopeSender),
			HeloIdentity:   p.mask(t.Identity.HeloIdentity),
			HeaderFrom:     p.mask(t.Identity.HeaderFrom),
		},
		Recipient:     p.mask(t.Recipient),
		SourceAddress: t.SourceAddr.String(),
		TLS:           t.TLS,
		Events:        events,
		RedactedSpans: p.count(),
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

const rfc3339Nano = "2006-01-02T15:04:05.999999999Z07:00"
