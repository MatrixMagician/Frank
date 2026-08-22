package gate

import (
	"errors"
	"testing"
)

func TestWithoutConfirmSendDispositionIsDryRun(t *testing.T) {
	got, err := Decide(Input{
		Recipient:       "victim@example.com",
		StdinIsTerminal: true,
	})
	if err != nil {
		t.Fatalf("Decide returned error %v, want nil", err)
	}
	if got.Disposition != DispositionDryRun {
		t.Errorf("Disposition = %v, want DispositionDryRun", got.Disposition)
	}
	if got.Recipient != "victim@example.com" {
		t.Errorf("Recipient = %q, want %q", got.Recipient, "victim@example.com")
	}
	if got.Reason == "" {
		t.Error("Reason is empty, want an explanation for the Transcript")
	}
}

func TestConfirmSendRequiresMatchingRecipient(t *testing.T) {
	tests := []struct {
		name        string
		confirmSend string
		recipient   string
		wantErr     bool
		wantSend    bool
	}{
		{"matching recipient sends", "victim@example.com", "victim@example.com", false, true},
		{"mismatched recipient is a usage error", "wrong@example.com", "victim@example.com", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decide(Input{
				ConfirmSend:     tt.confirmSend,
				Recipient:       tt.recipient,
				StdinIsTerminal: true,
			})
			if tt.wantErr {
				if !errors.Is(err, ErrConfirmSendRecipientMismatch) {
					t.Fatalf("err = %v, want ErrConfirmSendRecipientMismatch", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decide returned error %v, want nil", err)
			}
			if tt.wantSend && got.Disposition != DispositionSend {
				t.Errorf("Disposition = %v, want DispositionSend", got.Disposition)
			}
			if got.Recipient != tt.recipient {
				t.Errorf("Recipient = %q, want %q", got.Recipient, tt.recipient)
			}
		})
	}
}

func TestConfirmSendWithDryRunIsUsageError(t *testing.T) {
	_, err := Decide(Input{
		DryRunRequested: true,
		ConfirmSend:     "victim@example.com",
		Recipient:       "victim@example.com",
		StdinIsTerminal: true,
	})
	if !errors.Is(err, ErrConfirmSendWithDryRun) {
		t.Fatalf("err = %v, want ErrConfirmSendWithDryRun", err)
	}
}

// TestConfirmationWithoutTTYIsAnErrorNotAPrompt proves the acceptance
// criterion: a run needing confirmation with no TTY errors before the first
// dial. Decide is pure and performs no I/O of its own, so a caller who calls
// Decide and checks its error before doing anything else (in particular
// before calling net.Dial) is guaranteed the error arrives first: there is no
// dial for it to race against, because Decide never starts one.
func TestConfirmationWithoutTTYIsAnErrorNotAPrompt(t *testing.T) {
	_, err := Decide(Input{
		Recipient:       "victim@example.com",
		StdinIsTerminal: false,
	})
	if !errors.Is(err, ErrConfirmationNeedsTerminal) {
		t.Fatalf("err = %v, want ErrConfirmationNeedsTerminal", err)
	}
}

func TestDecideDryRunWithConfirmSendMismatchIsStillUsageError(t *testing.T) {
	_, err := Decide(Input{
		DryRunRequested: true,
		ConfirmSend:     "a@example.com",
		Recipient:       "b@example.com",
		StdinIsTerminal: true,
	})
	if !errors.Is(err, ErrConfirmSendWithDryRun) {
		t.Fatalf("err = %v, want ErrConfirmSendWithDryRun even when the recipient also mismatches", err)
	}
}
