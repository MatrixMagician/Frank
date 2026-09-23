package matrix

import (
	"context"
	"fmt"

	"github.com/MatrixMagician/Frank/internal/gate"
	"github.com/MatrixMagician/Frank/internal/smtpconv"
)

// Config is one sweep. Probe is a seam so the runner is testable without
// reaching for the network itself; a nil Probe runs the real conversation.
type Config struct {
	TargetHost string
	Recipient  string
	Slots      Slots
	Base       smtpconv.Config

	Limiter *gate.Limiter
	Backoff *gate.Backoff

	// RetriesAfterDeferral is how many additional Probes a Cell gets after a
	// Deferral. The spec caps re-probing at twice, and only after a Deferral.
	RetriesAfterDeferral int

	Probe func(smtpconv.Config) *smtpconv.Result
}

// DefaultRetriesAfterDeferral is the cap the spec sets: a Cell is re-probed at
// most twice, and only after a Deferral.
const DefaultRetriesAfterDeferral = 2

// Run sweeps every Triple, one Probe per Cell per pass, on a fresh connection
// every time.
//
// There is no RSET reuse, per ADR-0003. The measurement is that the mandatory
// rate limiter is the binding constraint at every conservative setting, so
// reuse saves nothing, and it would let one Cell's Outcome depend on the Cell
// before it, which costs the run the independence its evidence rests on.
func Run(ctx context.Context, cfg Config) (*Matrix, error) {
	if err := cfg.Slots.valid(); err != nil {
		return nil, err
	}
	if cfg.Recipient == "" {
		return nil, fmt.Errorf("matrix: recipient is empty")
	}

	probe := cfg.Probe
	if probe == nil {
		probe = smtpconv.Run
	}
	limiter := cfg.Limiter
	if limiter == nil {
		limiter = gate.NewLimiter(gate.DefaultRatePerMinute, gate.RealClock{})
	}
	backoff := cfg.Backoff
	if backoff == nil {
		backoff = gate.NewBackoff(gate.BackoffConfig{}, gate.RealClock{})
	}
	retries := cfg.RetriesAfterDeferral
	if retries == 0 {
		retries = DefaultRetriesAfterDeferral
	}

	triples := cfg.Slots.Triples()
	m := &Matrix{
		TargetHost: cfg.TargetHost,
		Recipient:  cfg.Recipient,
		Slots:      cfg.Slots,
		Cells:      make([]*Cell, len(triples)),
	}
	for i, t := range triples {
		m.Cells[i] = &Cell{Triple: t}
	}

	for _, cell := range m.Cells {
		// Every pass over a Cell opens its own connection, so an aborted sweep
		// leaves the Cells it never reached marked Unrun rather than silently
		// looking like they answered nothing.
		for attempt := 0; attempt <= retries; attempt++ {
			if err := limiter.Wait(ctx); err != nil {
				m.Aborted = err.Error()
				return m, nil
			}
			cell.reached = true

			res := probe(probeConfig(cfg, cell.Triple))
			cell.Probes = append(cell.Probes, record(res))

			if res.Outcome == nil {
				break
			}
			if res.Outcome.IsDeferral() {
				if err := backoff.Defer(ctx); err != nil {
					m.Aborted = err.Error()
					return m, nil
				}
				continue
			}
			backoff.Reset()
			break
		}
	}

	return m, nil
}

func probeConfig(cfg Config, t Triple) smtpconv.Config {
	out := cfg.Base
	out.TargetHost = cfg.TargetHost
	out.Recipient = smtpconv.Recipient(cfg.Recipient)
	out.Triple = smtpconv.IdentityTriple{
		EnvelopeSender: envelopeSenderFor(t.EnvelopeSender),
		HeloIdentity:   t.HeloIdentity,
		HeaderFrom:     t.HeaderFrom,
	}
	return out
}

// envelopeSenderFor treats the empty string and "<>" alike as the null sender,
// which is a first-class Identity Triple value rather than an error.
func envelopeSenderFor(v string) smtpconv.EnvelopeSender {
	if v == "" || v == "<>" {
		return smtpconv.NullEnvelopeSender()
	}
	return smtpconv.NewEnvelopeSender(v)
}

func record(res *smtpconv.Result) ProbeRecord {
	rec := ProbeRecord{Outcome: res.Outcome, Transcript: res.Transcript, Err: res.Err}
	if res.Err != nil {
		rec.Error = res.Err.Error()
	}
	if res.Outcome != nil {
		reply := res.Outcome.Reply()
		rec.Phase = res.Outcome.Phase().String()
		rec.Code = reply.Code
		rec.Text = reply.Text
		if reply.Enhanced != nil {
			rec.Enhanced = reply.Enhanced.String()
		}
	}
	return rec
}
