package gate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Disposition is what a run will actually do about the Probe Message.
type Disposition int

const (
	// DispositionDryRun walks the full protocol through RCPT TO and stops
	// before issuing DATA. It dials, negotiates TLS and sends the real
	// identities; it never transmits the Probe Message.
	DispositionDryRun Disposition = iota
	// DispositionSend transmits the Probe Message.
	DispositionSend
)

var dispositionNames = [...]string{"dry-run", "send"}

func (d Disposition) String() string {
	if int(d) < 0 || int(d) >= len(dispositionNames) {
		return "unknown"
	}
	return dispositionNames[d]
}

// ErrConfirmSendWithDryRun is returned when both are given, because they
// contradict.
var ErrConfirmSendWithDryRun = errors.New("gate: --confirm-send and --dry-run contradict each other")

// ErrConfirmSendMismatch is returned when --confirm-send names a different
// address from the Probe's Recipient. Naming the Recipient is the point of the
// flag: it is intent about a specific address, not a general assertion.
var ErrConfirmSendMismatch = errors.New("gate: --confirm-send names a different address from --recipient")

// ErrNoTerminal is returned when a run would have to prompt and stdin is not a
// terminal. Erroring here rather than prompting is what makes Frank safe to run
// in CI, where a prompt would hang forever.
var ErrNoTerminal = errors.New("gate: confirmation is required but stdin is not a terminal")

// Input is everything Decide needs. StdinIsTerminal is injected rather than
// detected here, so a test can drive both cases without a pty.
type Input struct {
	DryRunRequested bool
	ConfirmSend     string
	Recipient       string
	StdinIsTerminal bool
}

// Decision is what a run will do, and why. The Reason reaches the Transcript,
// because a reader needs to know why a run transmitted nothing.
type Decision struct {
	Disposition Disposition
	Recipient   string
	Reason      string
}

// Decide resolves the gating flags into a Disposition.
//
// It runs before anything is dialed, which is what makes the no-terminal case
// an error rather than a hang: a caller that dials first would already have
// touched the target before discovering it must not send.
func Decide(in Input) (Decision, error) {
	if in.ConfirmSend != "" && in.DryRunRequested {
		return Decision{}, ErrConfirmSendWithDryRun
	}

	if in.Recipient == "" {
		return Decision{}, fmt.Errorf("gate: a recipient is required")
	}

	if in.ConfirmSend == "" {
		reason := "no --confirm-send given, so the probe message was not transmitted"
		if in.DryRunRequested {
			reason = "--dry-run requested, so the probe message was not transmitted"
		}
		return Decision{
			Disposition: DispositionDryRun,
			Recipient:   in.Recipient,
			Reason:      reason,
		}, nil
	}

	if in.ConfirmSend != in.Recipient {
		return Decision{}, fmt.Errorf("%w: %q against %q",
			ErrConfirmSendMismatch, in.ConfirmSend, in.Recipient)
	}

	return Decision{
		Disposition: DispositionSend,
		Recipient:   in.Recipient,
		Reason:      "--confirm-send named this recipient explicitly",
	}, nil
}

// DecideInteractive is Decide for a run that has no --confirm-send but would
// accept an interactive confirmation. It exists so the no-terminal rule has one
// place to live: a run needing confirmation with no terminal errors here,
// before any dial.
func DecideInteractive(in Input) (Decision, error) {
	if in.ConfirmSend == "" && !in.DryRunRequested && !in.StdinIsTerminal {
		return Decision{}, ErrNoTerminal
	}
	return Decide(in)
}

// StdinIsTerminal reports whether standard input is an interactive terminal.
//
// A character-device check alone is not enough: /dev/null is also a character
// device, so `frank probe < /dev/null` would look interactive and a run that
// should have refused to send would dial instead. The ioctl below is what
// actually distinguishes a tty, and it is the same question isatty(3) asks.
func StdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	if info.Mode()&fs.ModeCharDevice == 0 {
		return false
	}
	return isTerminal(os.Stdin.Fd())
}
