package smtpconv

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	probeSubject = "Frank deliverability probe"
	probeXHeader = "X-Frank-Probe"
	probeXValue  = "yes"
)

// ProbeMessage is the fixed, minimal, self-identifying diagnostic message
// Frank transmits during DATA. Never arbitrary content: only the Header From
// Identity Slot, the Recipient, and the timestamp vary.
type ProbeMessage struct {
	HeaderFrom string
	Recipient  string
	Sent       time.Time
	MessageID  string
}

// NewProbeMessage builds the fixed Probe Message. headerFrom is the Header
// From Identity Slot, set independently of the Envelope Sender.
func NewProbeMessage(headerFrom, recipient string, sent time.Time) (ProbeMessage, error) {
	if headerFrom == "" {
		return ProbeMessage{}, fmt.Errorf("smtpconv: header from is empty")
	}
	if recipient == "" {
		return ProbeMessage{}, fmt.Errorf("smtpconv: recipient is empty")
	}
	id, err := randomMessageID()
	if err != nil {
		return ProbeMessage{}, err
	}
	return ProbeMessage{HeaderFrom: headerFrom, Recipient: recipient, Sent: sent, MessageID: id}, nil
}

func randomMessageID() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("smtpconv: generate message id: %w", err)
	}
	return hex.EncodeToString(buf) + "@frank.probe", nil
}

// Render renders the message's headers and body, CRLF-terminated per line.
// The result is never dot-stuffed itself; pass it to DotStuff before writing
// it during DATA.
func (m ProbeMessage) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Date: %s\r\n", m.Sent.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s>\r\n", m.MessageID)
	fmt.Fprintf(&b, "Subject: %s\r\n", probeSubject)
	fmt.Fprintf(&b, "From: <%s>\r\n", m.HeaderFrom)
	fmt.Fprintf(&b, "To: <%s>\r\n", m.Recipient)
	fmt.Fprintf(&b, "%s: %s\r\n", probeXHeader, probeXValue)
	b.WriteString("\r\n")
	b.WriteString("This message is a Frank deliverability probe.\r\n")
	b.WriteString("It is a diagnostic instrument, not a real communication, and requires no action.\r\n")
	// A line beginning with a dot, so every real Probe exercises dot-stuffing
	// rather than leaving it to a unit test on DotStuff alone. A host that
	// mishandles it corrupts this line, which is visible in the Transcript.
	b.WriteString(".This line begins with a dot, which the protocol requires be doubled in transit.\r\n")
	return b.String()
}

// DotStuff transforms a CRLF-terminated message into the exact bytes a
// conversation writes during DATA: every line beginning with "." gains a
// second leading ".", and the whole thing is terminated by <CRLF>.<CRLF>.
func DotStuff(message string) []byte {
	lines := strings.Split(message, "\r\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	var b strings.Builder
	for _, line := range lines {
		if strings.HasPrefix(line, ".") {
			b.WriteByte('.')
		}
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	b.WriteString(".\r\n")
	return []byte(b.String())
}
