package resolve

import (
	"errors"
	"testing"
)

func TestErrorIsBySentinel(t *testing.T) {
	err := &Error{Kind: KindNotFound, Name: "example.com", Type: "TXT"}
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("errors.Is(err, ErrNotFound) = false, want true")
	}
	if errors.Is(err, ErrNoRecords) {
		t.Fatal("errors.Is(err, ErrNoRecords) = true, want false")
	}
}

func TestErrorAsAndUnwrap(t *testing.T) {
	cause := errors.New("no such host")
	err := error(&Error{Kind: KindTemporary, Name: "example.com", Type: "A/AAAA", Err: cause})

	var re *Error
	if !errors.As(err, &re) {
		t.Fatal("errors.As failed")
	}
	if re.Kind != KindTemporary {
		t.Fatalf("re.Kind = %v, want KindTemporary", re.Kind)
	}
	if errors.Unwrap(err) != cause {
		t.Fatalf("Unwrap() = %v, want %v", errors.Unwrap(err), cause)
	}
}

func TestErrorStringLowercaseNoPunctuation(t *testing.T) {
	err := &Error{Kind: KindNoRecords, Name: "example.com", Type: "TXT"}
	s := err.Error()
	if s == "" {
		t.Fatal("Error() returned empty string")
	}
	if s[len(s)-1] == '.' {
		t.Fatalf("Error() ends with trailing punctuation: %q", s)
	}
	if s[0] >= 'A' && s[0] <= 'Z' {
		t.Fatalf("Error() starts with an uppercase letter: %q", s)
	}
}
