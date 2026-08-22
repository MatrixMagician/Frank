package transcript

import (
	"fmt"
	"strconv"
	"strings"
)

type EnhancedStatus struct {
	Class   int `json:"class"`
	Subject int `json:"subject"`
	Detail  int `json:"detail"`
}

func (e EnhancedStatus) String() string {
	return fmt.Sprintf("%d.%d.%d", e.Class, e.Subject, e.Detail)
}

type Extension struct {
	Name   string   `json:"name"`
	Params []string `json:"params,omitempty"`
	Raw    string   `json:"raw"`
}

type Reply struct {
	Code     int             `json:"code"`
	Enhanced *EnhancedStatus `json:"enhanced,omitempty"`
	Text     string          `json:"text"`
	Lines    []string        `json:"lines,omitempty"`
}

func (r *Reply) IsPositive() bool {
	return r.Code >= 200 && r.Code < 300
}

func (r *Reply) IsTransient() bool {
	return r.Code >= 400 && r.Code < 500
}

func (r *Reply) IsPermanent() bool {
	return r.Code >= 500 && r.Code < 600
}

// ParseReply parses one SMTP server reply, which may span multiple lines
// joined by "code-text\r\n" continuations and terminated by "code text\r\n".
// raw is the exact bytes as they arrived, CRLF-terminated per line.
func ParseReply(raw []byte) (*Reply, error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return nil, fmt.Errorf("transcript: empty reply")
	}
	rawLines := strings.Split(text, "\n")

	var code int
	var lines []string
	for i, line := range rawLines {
		if len(line) < 3 {
			return nil, fmt.Errorf("transcript: reply line %q too short", line)
		}
		lineCode, err := strconv.Atoi(line[:3])
		if err != nil {
			return nil, fmt.Errorf("transcript: reply line %q has non-numeric code", line)
		}
		if i == 0 {
			code = lineCode
		} else if lineCode != code {
			return nil, fmt.Errorf("transcript: mismatched continuation code %d, want %d", lineCode, code)
		}

		var sep byte
		var rest string
		if len(line) == 3 {
			sep = ' '
			rest = ""
		} else {
			sep = line[3]
			rest = line[4:]
		}
		if sep != '-' && sep != ' ' {
			return nil, fmt.Errorf("transcript: reply line %q has invalid separator %q", line, sep)
		}
		isLast := sep == ' '
		if !isLast && i == len(rawLines)-1 {
			return nil, fmt.Errorf("transcript: reply truncated mid-continuation at %q", line)
		}
		if isLast && i != len(rawLines)-1 {
			return nil, fmt.Errorf("transcript: reply line %q ends the reply but more lines follow", line)
		}

		lines = append(lines, rest)
	}

	reply := &Reply{
		Code:  code,
		Text:  strings.Join(lines, "\n"),
		Lines: lines,
	}

	if enhanced, remainder, ok := parseEnhancedStatus(reply.Text, code); ok {
		reply.Enhanced = &enhanced
		reply.Text = remainder
	}

	return reply, nil
}

func parseEnhancedStatus(text string, code int) (EnhancedStatus, string, bool) {
	fields := strings.SplitN(text, " ", 2)
	head := fields[0]
	parts := strings.SplitN(head, ".", 3)
	if len(parts) != 3 {
		return EnhancedStatus{}, "", false
	}
	if len(parts[0]) != 1 || len(parts[1]) < 1 || len(parts[1]) > 3 || len(parts[2]) < 1 || len(parts[2]) > 3 {
		return EnhancedStatus{}, "", false
	}
	class, err := strconv.Atoi(parts[0])
	if err != nil {
		return EnhancedStatus{}, "", false
	}
	subject, err := strconv.Atoi(parts[1])
	if err != nil {
		return EnhancedStatus{}, "", false
	}
	detail, err := strconv.Atoi(parts[2])
	if err != nil {
		return EnhancedStatus{}, "", false
	}
	if class != code/100 {
		return EnhancedStatus{}, "", false
	}
	remainder := ""
	if len(fields) == 2 {
		remainder = fields[1]
	}
	return EnhancedStatus{Class: class, Subject: subject, Detail: detail}, remainder, true
}

// ParseExtensions parses the EHLO extension list out of a (already-parsed)
// multiline reply's Lines, skipping the greeting line (the domain/greeting
// text with no parameters of its own).
func ParseExtensions(lines []string) []Extension {
	var exts []Extension
	for i, line := range lines {
		if i == 0 {
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		exts = append(exts, Extension{
			Name:   strings.ToUpper(fields[0]),
			Params: fields[1:],
			Raw:    line,
		})
	}
	return exts
}
