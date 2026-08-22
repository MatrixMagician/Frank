package transcript

import (
	"strings"
	"testing"
)

func TestParseReplySingleLine(t *testing.T) {
	r, err := ParseReply([]byte("250 OK\r\n"))
	if err != nil {
		t.Fatalf("ParseReply: %v", err)
	}
	if r.Code != 250 {
		t.Errorf("Code = %d, want 250", r.Code)
	}
	if r.Text != "OK" {
		t.Errorf("Text = %q, want %q", r.Text, "OK")
	}
	if !r.IsPositive() {
		t.Error("IsPositive() = false, want true")
	}
	if r.Enhanced != nil {
		t.Errorf("Enhanced = %v, want nil", r.Enhanced)
	}
}

func TestParseReplyMultilineContinuation(t *testing.T) {
	raw := "250-STARTTLS\r\n250-SIZE 10240000\r\n250 HELP\r\n"
	r, err := ParseReply([]byte(raw))
	if err != nil {
		t.Fatalf("ParseReply: %v", err)
	}
	if r.Code != 250 {
		t.Errorf("Code = %d, want 250", r.Code)
	}
	wantLines := []string{"STARTTLS", "SIZE 10240000", "HELP"}
	if len(r.Lines) != len(wantLines) {
		t.Fatalf("Lines = %v, want %v", r.Lines, wantLines)
	}
	for i, want := range wantLines {
		if r.Lines[i] != want {
			t.Errorf("Lines[%d] = %q, want %q", i, r.Lines[i], want)
		}
	}
}

func TestParseReplyEnhancedStatusCode(t *testing.T) {
	r, err := ParseReply([]byte("550 5.7.1 Sender rejected\r\n"))
	if err != nil {
		t.Fatalf("ParseReply: %v", err)
	}
	if r.Code != 550 {
		t.Errorf("Code = %d, want 550", r.Code)
	}
	if r.Enhanced == nil {
		t.Fatal("Enhanced = nil, want a value")
	}
	if r.Enhanced.Class != 5 || r.Enhanced.Subject != 7 || r.Enhanced.Detail != 1 {
		t.Errorf("Enhanced = %+v, want {5 7 1}", r.Enhanced)
	}
	if r.Text != "Sender rejected" {
		t.Errorf("Text = %q, want %q", r.Text, "Sender rejected")
	}
	if !r.IsPermanent() {
		t.Error("IsPermanent() = false, want true")
	}
}

func TestParseReplyWithoutEnhancedCodeIsDistinguishable(t *testing.T) {
	r, err := ParseReply([]byte("452 Too many recipients\r\n"))
	if err != nil {
		t.Fatalf("ParseReply: %v", err)
	}
	if r.Enhanced != nil {
		t.Errorf("Enhanced = %+v, want nil (absence must be distinguishable from a zero value)", r.Enhanced)
	}
	if !r.IsTransient() {
		t.Error("IsTransient() = false, want true")
	}
	if r.Text != "Too many recipients" {
		t.Errorf("Text = %q, want full text unaffected by absent enhanced code", r.Text)
	}
}

func TestParseReplyMismatchedClassEnhancedCodeIsAbsent(t *testing.T) {
	r, err := ParseReply([]byte("250 4.1.1 looks enhanced but wrong class\r\n"))
	if err != nil {
		t.Fatalf("ParseReply: %v", err)
	}
	if r.Enhanced != nil {
		t.Errorf("Enhanced = %+v, want nil when first digit disagrees with reply code class", r.Enhanced)
	}
}

func TestParseReplyRejectsMismatchedContinuationCodes(t *testing.T) {
	raw := "250-STARTTLS\r\n251 SIZE 10240000\r\n"
	_, err := ParseReply([]byte(raw))
	if err == nil {
		t.Fatal("ParseReply: err = nil, want an error for mismatched continuation codes")
	}
}

func TestParseReplyRejectsEmptyInput(t *testing.T) {
	_, err := ParseReply([]byte(""))
	if err == nil {
		t.Fatal("ParseReply: err = nil, want an error for empty input")
	}
}

func TestParseExtensions(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  []Extension
	}{
		{
			name:  "SIZE",
			lines: []string{"mail.example.com", "SIZE 10240000"},
			want:  []Extension{{Name: "SIZE", Params: []string{"10240000"}, Raw: "SIZE 10240000"}},
		},
		{
			name:  "STARTTLS",
			lines: []string{"mail.example.com", "STARTTLS"},
			want:  []Extension{{Name: "STARTTLS", Params: nil, Raw: "STARTTLS"}},
		},
		{
			name:  "AUTH with mechanisms",
			lines: []string{"mail.example.com", "AUTH PLAIN LOGIN"},
			want:  []Extension{{Name: "AUTH", Params: []string{"PLAIN", "LOGIN"}, Raw: "AUTH PLAIN LOGIN"}},
		},
		{
			name:  "PIPELINING",
			lines: []string{"mail.example.com", "PIPELINING"},
			want:  []Extension{{Name: "PIPELINING", Params: nil, Raw: "PIPELINING"}},
		},
		{
			name:  "8BITMIME",
			lines: []string{"mail.example.com", "8BITMIME"},
			want:  []Extension{{Name: "8BITMIME", Params: nil, Raw: "8BITMIME"}},
		},
		{
			name:  "multiple extensions",
			lines: []string{"mail.example.com", "SIZE 10240000", "STARTTLS", "AUTH PLAIN LOGIN", "8BITMIME"},
			want: []Extension{
				{Name: "SIZE", Params: []string{"10240000"}, Raw: "SIZE 10240000"},
				{Name: "STARTTLS", Params: nil, Raw: "STARTTLS"},
				{Name: "AUTH", Params: []string{"PLAIN", "LOGIN"}, Raw: "AUTH PLAIN LOGIN"},
				{Name: "8BITMIME", Params: nil, Raw: "8BITMIME"},
			},
		},
		{
			name:  "lowercase extension name is normalised",
			lines: []string{"mail.example.com", "auth plain"},
			want:  []Extension{{Name: "AUTH", Params: []string{"plain"}, Raw: "auth plain"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseExtensions(tt.lines)
			if len(got) != len(tt.want) {
				t.Fatalf("ParseExtensions() = %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i].Name != tt.want[i].Name {
					t.Errorf("[%d].Name = %q, want %q", i, got[i].Name, tt.want[i].Name)
				}
				if strings.Join(got[i].Params, ",") != strings.Join(tt.want[i].Params, ",") {
					t.Errorf("[%d].Params = %v, want %v", i, got[i].Params, tt.want[i].Params)
				}
				if got[i].Raw != tt.want[i].Raw {
					t.Errorf("[%d].Raw = %q, want %q", i, got[i].Raw, tt.want[i].Raw)
				}
			}
		})
	}
}
