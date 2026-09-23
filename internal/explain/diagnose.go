package explain

import (
	"fmt"
	"strings"

	"github.com/MatrixMagician/Frank/internal/spf"
	"github.com/MatrixMagician/Frank/internal/transcript"
)

// facts is the evidence one Input yields, gathered once so every rule reads
// the same view rather than re-deriving it.
type facts struct {
	in *Input

	lastReply    *transcript.Reply
	lastPhase    transcript.Phase
	haveReply    bool
	tlsAttempted bool
	tlsVerified  bool
	tlsError     string
	dialError    string
}

func gather(in *Input) facts {
	f := facts{in: in}
	if in.Transcript == nil {
		return f
	}

	for _, e := range in.Transcript.Events {
		// QUIT's reply is the server acknowledging the close and says nothing
		// about the identities, so it must not stand in for the Outcome. A
		// clean QUIT happens on every exit path, including a rejection, and
		// reading it as the result reported every refused probe as accepted.
		if e.Reply != nil && e.Phase != transcript.PhaseQuit {
			f.lastReply = e.Reply
			f.lastPhase = e.Phase
			f.haveReply = true
		}
		if e.Kind == transcript.KindError && e.Phase == transcript.PhaseDial {
			f.dialError = string(e.Raw)
		}
		// Only a STARTTLS command actually sent counts as an attempt. A note
		// saying the extension was never advertised is the opposite fact, and
		// treating it as an attempt turned every plaintext probe into a
		// spurious transport diagnosis.
		if e.Phase == transcript.PhaseSTARTTLS && e.Kind == transcript.KindSend {
			f.tlsAttempted = true
		}
	}
	if in.Transcript.TLS != nil {
		f.tlsVerified = in.Transcript.TLS.Verified
		f.tlsError = in.Transcript.TLS.VerifyError
	}
	return f
}

// rule is one row of the ordered table Diagnose walks. The first rule whose
// when returns true states the Diagnosis, so the table's order is its
// precedence and a new cause is added by inserting a row rather than by
// growing a conditional.
type rule struct {
	name string
	when func(facts) bool
	say  func(facts) Diagnosis
}

// rules are ordered most specific first. A matrix run is checked before any
// single-Probe rule, because its Diagnosis is about the sweep rather than
// about one conversation.
var rules = []rule{
	{
		name: "matrix sweep",
		when: func(f facts) bool { return f.in.MatrixBoundary != "" },
		say:  matrixDiagnosis,
	},
	{
		name: "dial failed",
		when: func(f facts) bool { return f.dialError != "" },
		say: func(f facts) Diagnosis {
			return Diagnosis{
				Summary: "the probe never reached the target, so nothing was established about the identities: " + f.dialError,
				Evidence: []Evidence{
					{Observed: true, Text: "the dial failed: " + f.dialError},
				},
				Confidence: Supported,
				NextProbe:  "confirm the target host and port are reachable, then probe again",
			}
		},
	},
	{
		name: "tls refused",
		when: func(f facts) bool {
			return f.tlsAttempted && f.in.Transcript != nil && f.in.Transcript.TLS == nil
		},
		say: func(f facts) Diagnosis {
			return Diagnosis{
				Summary:    "the probe stopped at STARTTLS, so this is a transport fault rather than a policy decision about the identities",
				Confidence: Supported,
				Evidence: []Evidence{
					{Observed: true, Text: "STARTTLS was attempted and no TLS session was established"},
				},
				NextProbe: "probe again with --tls=none to see whether the target accepts the identities in plaintext",
			}
		},
	},
	{
		name: "tls verification failed",
		when: func(f facts) bool { return f.in.Transcript != nil && f.in.Transcript.TLS != nil && !f.tlsVerified },
		say: func(f facts) Diagnosis {
			d := Diagnosis{
				Summary:    "the certificate did not verify, which is a finding in its own right and is recorded rather than acted on",
				Confidence: Ambiguous,
				Evidence: []Evidence{
					{Observed: true, Text: "certificate verification failed: " + f.tlsError},
				},
				NextProbe: "probe again with --tls-verify to stop on the verification failure, or supply the expected chain",
			}
			if f.haveReply && f.lastReply.IsPermanent() {
				d.Summary = "the target refused the message, and separately the certificate did not verify; the refusal is the policy decision and the certificate is a second finding"
				d.Evidence = append(d.Evidence, Evidence{
					Observed: true,
					Text:     replyText(f),
				})
			}
			return d
		},
	},
	{
		name: "deferral",
		when: func(f facts) bool { return f.haveReply && f.lastReply.IsTransient() },
		say: func(f facts) Diagnosis {
			return Diagnosis{
				Summary:    "the target deferred rather than deciding, so this proves nothing about the identity triple that met it",
				Confidence: Ambiguous,
				Evidence: []Evidence{
					{Observed: true, Text: replyText(f)},
					{Observed: true, Text: "a 4xx is a deferral, meaning greylisting, rate limiting or temporary unavailability, and is not a rejection"},
				},
				NextProbe: "probe the same identity triple again after the greylisting interval; a host that defers indefinitely needs a different recipient or target",
			}
		},
	},
	{
		name: "rejection with an alignment explanation",
		when: func(f facts) bool {
			return f.haveReply && f.lastReply.IsPermanent() && f.in.DMARC != nil && f.in.DMARC.Found && !f.in.DMARC.Pass
		},
		say: alignmentDiagnosis,
	},
	{
		name: "rejection with an spf record defect",
		when: func(f facts) bool {
			return f.haveReply && f.lastReply.IsPermanent() && firstDefect(f.in.SPF) != nil
		},
		say: defectDiagnosis,
	},
	{
		name: "rejection",
		when: func(f facts) bool { return f.haveReply && f.lastReply.IsPermanent() },
		say: func(f facts) Diagnosis {
			d := Diagnosis{
				Summary:    fmt.Sprintf("the target rejected the probe at %s, and the published records do not explain it", f.lastPhase),
				Confidence: Ambiguous,
				Evidence:   []Evidence{{Observed: true, Text: replyText(f)}},
				NextProbe:  "probe again varying one identity slot at a time, or run frank matrix to find the boundary",
			}
			d.Evidence = append(d.Evidence, authEvidence(f)...)
			return d
		},
	},
	{
		name: "acceptance",
		when: func(f facts) bool { return f.haveReply && f.lastReply.IsPositive() },
		say: func(f facts) Diagnosis {
			d := Diagnosis{
				// Acceptance is the strongest fact a Probe can establish and is
				// still not evidence of delivery. Nothing here may say otherwise.
				Summary:    fmt.Sprintf("the target accepted the message at %s, which establishes that it took responsibility for it and not that it was delivered", f.lastPhase),
				Confidence: Supported,
				Evidence:   []Evidence{{Observed: true, Text: replyText(f)}},
			}
			d.Evidence = append(d.Evidence, authEvidence(f)...)
			return d
		},
	},
}

// Diagnose walks the rule table and states the first Diagnosis that fits.
func Diagnose(in Input) Diagnosis {
	f := gather(&in)
	for _, r := range rules {
		if r.when(f) {
			return r.say(f)
		}
	}
	return Diagnosis{
		Summary:    "the probe produced no reply to draw a diagnosis from",
		Confidence: Ambiguous,
		Evidence:   []Evidence{{Observed: true, Text: "no server reply was recorded"}},
		NextProbe:  "probe again and check the target is reachable",
	}
}

func matrixDiagnosis(f facts) Diagnosis {
	d := Diagnosis{
		Summary:      "the sweep found the boundary: " + f.in.MatrixBoundary,
		Confidence:   Supported,
		Evidence:     []Evidence{{Observed: true, Text: f.in.MatrixBoundary}},
		PerCellLines: f.in.MatrixCells,
	}
	if strings.Contains(f.in.MatrixBoundary, "no Triple was rejected") {
		d.Summary = "the sweep rejected no identity triple, so the target's policy did not discriminate among the ones probed"
	}
	d.Evidence = append(d.Evidence, authEvidence(f)...)
	return d
}

func alignmentDiagnosis(f facts) Diagnosis {
	dm := f.in.DMARC
	d := Diagnosis{
		Confidence: Supported,
		Evidence:   []Evidence{{Observed: true, Text: replyText(f)}},
	}

	headerFrom := dm.DKIMAlignment.HeaderFromDomain
	if headerFrom == "" {
		headerFrom = dm.SPFAlignment.HeaderFromDomain
	}

	d.Summary = fmt.Sprintf(
		"the rejection is consistent with a DMARC alignment failure rather than a connection or TLS fault: the header From domain is %s, DMARC for it is p=%s, and neither identifier authenticated and aligned",
		headerFrom, dm.EffectivePolicy)

	d.Evidence = append(d.Evidence,
		Evidence{Observed: false, Text: fmt.Sprintf("DMARC for %s publishes p=%s with aspf=%s and adkim=%s", headerFrom, dm.Policy.P, dm.Policy.ASPF, dm.Policy.ADKIM)},
		Evidence{Observed: false, Text: fmt.Sprintf("SPF alignment: authenticated %q against header from %q, relaxed=%v strict=%v",
			dm.SPFAlignment.AuthenticatedDomain, dm.SPFAlignment.HeaderFromDomain, dm.SPFAlignment.Relaxed, dm.SPFAlignment.Strict)},
		Evidence{Observed: false, Text: fmt.Sprintf("DKIM alignment: authenticated %q against header from %q, relaxed=%v strict=%v",
			dm.DKIMAlignment.AuthenticatedDomain, dm.DKIMAlignment.HeaderFromDomain, dm.DKIMAlignment.Relaxed, dm.DKIMAlignment.Strict)},
	)
	if f.in.SPF != nil {
		d.Evidence = append(d.Evidence, Evidence{
			Observed: false,
			Text:     fmt.Sprintf("SPF for %s evaluated to %s", f.in.SPF.Subject, f.in.SPF.Verdict),
		})
	}
	for _, c := range dm.Caveats {
		d.Evidence = append(d.Evidence, Evidence{Observed: false, Text: c})
	}
	return d
}

func authEvidence(f facts) []Evidence {
	var out []Evidence
	if f.in.SPF != nil {
		out = append(out, Evidence{
			Observed: false,
			Text:     fmt.Sprintf("SPF for %s evaluated to %s", f.in.SPF.Subject, f.in.SPF.Verdict),
		})
	}
	if f.in.DMARC != nil && f.in.DMARC.Found {
		out = append(out, Evidence{
			Observed: false,
			Text:     fmt.Sprintf("DMARC policy is p=%s and the message %s", f.in.DMARC.EffectivePolicy, passWord(f.in.DMARC.Pass)),
		})
	}
	return out
}

func passWord(pass bool) string {
	if pass {
		return "passes DMARC"
	}
	return "does not pass DMARC"
}

func firstDefect(res *spf.Result) *spf.Defect {
	if res == nil || len(res.Defects) == 0 {
		return nil
	}
	return &res.Defects[0]
}

// defectDiagnosis names a Record Defect as the cause. Every kind makes the
// record a permerror for every receiver, which is what lets it explain a
// Rejection on its own.
func defectDiagnosis(f facts) Diagnosis {
	d := firstDefect(f.in.SPF)
	switch d.Kind {
	case spf.DefectSecondaryLimitExceeded:
		return Diagnosis{
			Summary:    "the target refused the message, and an mx mechanism in the sender's SPF record exceeds the RFC 7208 secondary limit, which makes it a permerror for every receiver and is a root cause in its own right",
			Confidence: Supported,
			Evidence: []Evidence{
				{Observed: true, Text: replyText(f)},
				{Observed: false, Text: strings.TrimPrefix(d.Message, "spf: ")},
				{Observed: false, Text: "an mx mechanism over the secondary limit evaluates to permerror regardless of the sending ip"},
			},
			NextProbe: fmt.Sprintf("replace the mx mechanism for %s with ip4/ip6 ranges or cut its MX set to %d hosts, and probe the same identity triple again", d.Domain, spf.SecondaryLookupLimit),
		}
	default:
		return Diagnosis{
			Summary:    "the target refused the message, and the sender's SPF record exceeds the RFC 7208 lookup limit, which makes it a permerror for every receiver and is a root cause in its own right",
			Confidence: Supported,
			Evidence: []Evidence{
				{Observed: true, Text: replyText(f)},
				{Observed: false, Text: fmt.Sprintf("the SPF record for %s uses %d dns-querying mechanisms against a limit of %d", f.in.SPF.Subject, f.in.SPF.Lookups, spf.LookupLimit)},
				{Observed: false, Text: "an over-limit record evaluates to permerror regardless of the sending ip"},
			},
			NextProbe: "flatten the SPF record below the limit and probe the same identity triple again",
		}
	}
}

func replyText(f facts) string {
	if !f.haveReply {
		return "no reply was recorded"
	}
	enhanced := ""
	if f.lastReply.Enhanced != nil {
		enhanced = " " + f.lastReply.Enhanced.String()
	}
	return fmt.Sprintf("the target replied %d%s at %s: %s",
		f.lastReply.Code, enhanced, f.lastPhase, f.lastReply.Text)
}
