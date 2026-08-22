package gate

import (
	"errors"
	"fmt"
	"os"
)

type Disposition int

const (
	DispositionDryRun Disposition = iota
	DispositionSend
)

func (d Disposition) String() string {
	switch d {
	case DispositionDryRun:
		return "dry-run"
	case DispositionSend:
		return "send"
	default:
		return "unknown"
	}
}

// Decision is what Decide returns: the Disposition a Probe must take, the
// effective Recipient SPEC.md requires every Transcript to record, and the
// Reason a reader needs to understand why a run transmitted nothing.
type Decision struct {
	Disposition Disposition
	Recipient   string
	Reason      string
}

// Input carries everything Decide needs to reach a Decision without touching
// the environment itself, so a test drives every case without a real TTY.
type Input struct {
	DryRunRequested bool
	ConfirmSend     string
	Recipient       string
	StdinIsTerminal bool
}

var ErrConfirmSendWithDryRun = errors.New("gate: --confirm-send and --dry-run contradict each other")
var ErrConfirmSendRecipientMismatch = errors.New("gate: --confirm-send does not match the probe's recipient")
var ErrConfirmationNeedsTerminal = errors.New("gate: confirmation required but stdin is not a terminal")

// Decide is pure and does no I/O, which is what lets a caller guarantee it
// runs before any dial: call Decide first, and only proceed to dial if it
// returns a nil error.
func Decide(in Input) (Decision, error) {
	if in.DryRunRequested && in.ConfirmSend != "" {
		return Decision{}, ErrConfirmSendWithDryRun
	}

	if in.DryRunRequested {
		return Decision{
			Disposition: DispositionDryRun,
			Recipient:   in.Recipient,
			Reason:      "--dry-run requested",
		}, nil
	}

	if in.ConfirmSend != "" {
		if in.ConfirmSend != in.Recipient {
			return Decision{}, fmt.Errorf("%w: --confirm-send %q, recipient %q", ErrConfirmSendRecipientMismatch, in.ConfirmSend, in.Recipient)
		}
		return Decision{
			Disposition: DispositionSend,
			Recipient:   in.Recipient,
			Reason:      "--confirm-send " + in.ConfirmSend,
		}, nil
	}

	// Neither --dry-run nor --confirm-send was given. An interactive run
	// could still ask the operator to confirm; a non-interactive one cannot,
	// and must not hang waiting for input that will never come, so it errors
	// here, before the caller ever dials.
	if !in.StdinIsTerminal {
		return Decision{}, ErrConfirmationNeedsTerminal
	}

	return Decision{
		Disposition: DispositionDryRun,
		Recipient:   in.Recipient,
		Reason:      "no --confirm-send given",
	}, nil
}

// StdinIsTerminal is the helper real callers use to fill Input.StdinIsTerminal;
// the package itself never detects this, so tests drive both cases without a
// pty.
//
// A character-device check alone is not enough, and this is not a nicety:
// /dev/null is a character device too, so `frank probe < /dev/null` looked
// interactive and dialed a run that should have refused to send. The ioctl is
// the same question isatty(3) asks.
func StdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return isTerminal(os.Stdin.Fd())
}
