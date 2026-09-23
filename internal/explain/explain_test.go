package explain

import (
	"context"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MatrixMagician/Frank/internal/dmarc"
	"github.com/MatrixMagician/Frank/internal/resolve"
	"github.com/MatrixMagician/Frank/internal/spf"
	"github.com/MatrixMagician/Frank/internal/transcript"
)

var update = flag.Bool("update", false, "rewrite the golden files from the current output")

func TestMain(m *testing.M) {
	os.Exit(resolve.ForbidNetwork(m))
}

// golden compares got against testdata/<name>.golden, rewriting it under
// -update. A golden file is the readable artefact a reviewer diffs, which is
// what makes a wording change visible rather than silent.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")

	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run go test ./internal/explain -update to create it)", path, err)
	}
	if got != string(want) {
		t.Errorf("output does not match %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func transcriptEndingWith(t *testing.T, phase transcript.Phase, raw string) *transcript.Transcript {
	t.Helper()
	tr := transcript.NewTranscript("mx.target.example:25", transcript.IdentityTriple{
		EnvelopeSender: "bounce@sender.example",
		HeloIdentity:   "frank.invalid",
		HeaderFrom:     "ceo@victim.example",
	}, "rcpt@target.example")

	ev := tr.Append(transcript.KindRecv, phase, []byte(raw))
	reply, err := transcript.ParseReply([]byte(raw))
	if err != nil {
		t.Fatalf("ParseReply(%q): %v", raw, err)
	}
	ev.Reply = reply
	return tr
}

func TestGoldenAlignmentFailure(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("sender.example", "v=spf1 ip4:192.0.2.0/24 -all")
	z.TXT("_dmarc.victim.example", "v=DMARC1; p=reject; aspf=s; adkim=s")

	ip, err := spf.NewCandidateSendingIP(mustAddr(t, "192.0.2.7"), true)
	if err != nil {
		t.Fatalf("NewCandidateSendingIP: %v", err)
	}
	spfRes, err := spf.Evaluate(context.Background(), z, spf.Request{
		EnvelopeSender: "bounce@sender.example",
		HeloIdentity:   "frank.invalid",
		CandidateIP:    &ip,
	})
	if err != nil {
		t.Fatalf("spf.Evaluate: %v", err)
	}

	dmarcRes, err := dmarc.Evaluate(context.Background(), z, dmarc.Input{
		HeaderFromDomain: "victim.example",
		SPF:              *spfRes,
	})
	if err != nil {
		t.Fatalf("dmarc.Evaluate: %v", err)
	}

	d := Diagnose(Input{
		Transcript: transcriptEndingWith(t, transcript.PhaseEndOfData,
			"550 5.7.1 Unauthenticated email from victim.example is not accepted\r\n"),
		SPF:   spfRes,
		DMARC: dmarcRes,
	})

	golden(t, "alignment-failure", d.Render())

	if d.Confidence != Supported {
		t.Errorf("confidence = %v, want supported", d.Confidence)
	}
	if !strings.Contains(d.Summary, "alignment failure") {
		t.Errorf("summary does not name the alignment failure: %q", d.Summary)
	}
	if !strings.Contains(d.Summary, "rather than a connection or TLS fault") {
		t.Errorf("summary does not rule out the transport: %q", d.Summary)
	}
}

func TestGoldenOverLimitSPF(t *testing.T) {
	z := resolve.NewZone()
	var terms []string
	for i := range 11 {
		name := "inc" + string(rune('a'+i)) + ".example"
		terms = append(terms, "include:"+name)
		z.TXT(name, "v=spf1 -all")
	}
	z.TXT("sender.example", "v=spf1 "+strings.Join(terms, " ")+" -all")

	ip, err := spf.NewCandidateSendingIP(mustAddr(t, "192.0.2.7"), true)
	if err != nil {
		t.Fatalf("NewCandidateSendingIP: %v", err)
	}
	spfRes, err := spf.Evaluate(context.Background(), z, spf.Request{
		EnvelopeSender: "bounce@sender.example",
		CandidateIP:    &ip,
	})
	if err != nil {
		t.Fatalf("spf.Evaluate: %v", err)
	}

	d := Diagnose(Input{
		Transcript: transcriptEndingWith(t, transcript.PhaseEndOfData,
			"550 5.7.23 SPF validation failed\r\n"),
		SPF: spfRes,
	})

	golden(t, "over-limit-spf", d.Render())

	if !strings.Contains(d.Summary, "lookup limit") {
		t.Errorf("summary does not name the lookup limit: %q", d.Summary)
	}
}

func TestGoldenSecondaryLimitSPF(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("sender.example", "v=spf1 mx -all")
	for i := range 12 {
		host := "mx" + string(rune('a'+i)) + ".sender.example"
		z.MX("sender.example", uint16(i), host)
		z.A(host, "203.0.113.1")
	}

	ip, err := spf.NewCandidateSendingIP(mustAddr(t, "192.0.2.7"), true)
	if err != nil {
		t.Fatalf("NewCandidateSendingIP: %v", err)
	}
	spfRes, err := spf.Evaluate(context.Background(), z, spf.Request{
		EnvelopeSender: "bounce@sender.example",
		CandidateIP:    &ip,
	})
	if err != nil {
		t.Fatalf("spf.Evaluate: %v", err)
	}

	d := Diagnose(Input{
		Transcript: transcriptEndingWith(t, transcript.PhaseEndOfData,
			"550 5.7.23 SPF validation failed\r\n"),
		SPF: spfRes,
	})

	golden(t, "secondary-limit-spf", d.Render())

	if !strings.Contains(d.Summary, "secondary limit") {
		t.Errorf("summary does not name the secondary limit: %q", d.Summary)
	}
}

func TestGoldenTLSRefusal(t *testing.T) {
	tr := transcript.NewTranscript("mx.target.example:25", transcript.IdentityTriple{
		EnvelopeSender: "bounce@sender.example",
		HeloIdentity:   "frank.invalid",
		HeaderFrom:     "author@sender.example",
	}, "rcpt@target.example")
	tr.Append(transcript.KindSend, transcript.PhaseSTARTTLS, []byte("STARTTLS\r\n"))
	ev := tr.Append(transcript.KindRecv, transcript.PhaseSTARTTLS, []byte("454 4.7.0 TLS not available\r\n"))
	reply, err := transcript.ParseReply([]byte("454 4.7.0 TLS not available\r\n"))
	if err != nil {
		t.Fatalf("ParseReply: %v", err)
	}
	ev.Reply = reply

	d := Diagnose(Input{Transcript: tr})

	golden(t, "tls-refusal", d.Render())

	if !strings.Contains(d.Summary, "STARTTLS") {
		t.Errorf("summary does not name STARTTLS: %q", d.Summary)
	}
	if d.NextProbe == "" {
		t.Error("no next probe is named for a transport fault")
	}
}

func TestGoldenGreylisting(t *testing.T) {
	d := Diagnose(Input{
		Transcript: transcriptEndingWith(t, transcript.PhaseEndOfData,
			"450 4.7.1 Greylisted, please try again in 300 seconds\r\n"),
	})

	golden(t, "greylisting", d.Render())

	if d.Confidence != Ambiguous {
		t.Errorf("confidence = %v, want ambiguous: a deferral proves nothing", d.Confidence)
	}
	if !strings.Contains(d.Summary, "proves nothing") {
		t.Errorf("summary does not say the deferral proves nothing: %q", d.Summary)
	}
	if d.NextProbe == "" {
		t.Error("no disambiguating probe is named for an ambiguous case")
	}
}

// TestObservedAndComputedAreDistinguishable is the distinction the whole
// safety posture rests on: an Outcome is something a Target Host did, a
// Verdict is something the published records say.
func TestObservedAndComputedAreDistinguishable(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("sender.example", "v=spf1 -all")
	z.TXT("_dmarc.victim.example", "v=DMARC1; p=reject")

	ip, err := spf.NewCandidateSendingIP(mustAddr(t, "192.0.2.7"), true)
	if err != nil {
		t.Fatalf("NewCandidateSendingIP: %v", err)
	}
	spfRes, _ := spf.Evaluate(context.Background(), z, spf.Request{EnvelopeSender: "bounce@sender.example", CandidateIP: &ip})
	dmarcRes, _ := dmarc.Evaluate(context.Background(), z, dmarc.Input{HeaderFromDomain: "victim.example", SPF: *spfRes})

	d := Diagnose(Input{
		Transcript: transcriptEndingWith(t, transcript.PhaseEndOfData, "550 5.7.1 rejected\r\n"),
		SPF:        spfRes,
		DMARC:      dmarcRes,
	})

	var observed, computed int
	for _, e := range d.Evidence {
		if e.Observed {
			observed++
		} else {
			computed++
		}
	}
	if observed == 0 {
		t.Error("no evidence is marked observed")
	}
	if computed == 0 {
		t.Error("no evidence is marked computed")
	}

	rendered := d.Render()
	if !strings.Contains(rendered, "observed:") || !strings.Contains(rendered, "computed:") {
		t.Errorf("the rendering does not distinguish observed from computed:\n%s", rendered)
	}
}

func TestAmbiguousCaseNamesDisambiguatingProbe(t *testing.T) {
	d := Diagnose(Input{
		Transcript: transcriptEndingWith(t, transcript.PhaseEndOfData,
			"550 5.0.0 message refused\r\n"),
	})

	if d.Confidence != Ambiguous {
		t.Errorf("confidence = %v, want ambiguous with no auth records to explain the refusal", d.Confidence)
	}
	if d.NextProbe == "" {
		t.Fatal("an ambiguous diagnosis names no disambiguating probe")
	}
	if !strings.Contains(d.Render(), "next probe:") {
		t.Error("the rendering does not surface the disambiguating probe")
	}
}

func TestMatrixTranscriptYieldsRunAndPerCellDiagnosis(t *testing.T) {
	d := Diagnose(Input{
		MatrixBoundary: "2 of 4 Triples were rejected; every rejection carried header from ceo@victim.example",
		MatrixCells: []string{
			"[rejected] bounce@sender.example | frank.invalid | ceo@victim.example -> 550 5.7.1 at end-of-data",
			"[accepted] bounce@sender.example | frank.invalid | author@sender.example -> 250 2.0.0 at end-of-data",
		},
	})

	if !strings.Contains(d.Summary, "boundary") {
		t.Errorf("summary does not name the boundary: %q", d.Summary)
	}
	if len(d.PerCellLines) != 2 {
		t.Errorf("got %d per-cell lines, want one per cell", len(d.PerCellLines))
	}

	rendered := d.Render()
	if !strings.Contains(rendered, "cells:") {
		t.Error("the rendering carries no per-cell section")
	}
	for _, line := range d.PerCellLines {
		if !strings.Contains(rendered, line) {
			t.Errorf("the rendering omits the cell line %q", line)
		}
	}
}

// TestNoDiagnosisClaimsDelivery guards the glossary's rule that an Acceptance
// is the strongest fact a Probe can establish and is still not evidence of
// delivery.
func TestNoDiagnosisClaimsDelivery(t *testing.T) {
	cases := map[string]Input{
		"acceptance": {Transcript: transcriptEndingWith(t, transcript.PhaseEndOfData, "250 2.0.0 OK\r\n")},
		"rejection":  {Transcript: transcriptEndingWith(t, transcript.PhaseEndOfData, "550 5.7.1 no\r\n")},
		"deferral":   {Transcript: transcriptEndingWith(t, transcript.PhaseEndOfData, "450 4.7.1 later\r\n")},
		"matrix":     {MatrixBoundary: "no Triple was rejected"},
	}

	// A claim of delivery is an assertion, not the word itself: the acceptance
	// summary says "not that it was delivered", which is the disclaimer this
	// rule exists to require rather than a violation of it.
	claims := []string{
		"was delivered", "has been delivered", "message was delivered",
		"successfully delivered", "inboxed", "reached the inbox", "arrived in the inbox",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			rendered := strings.ToLower(Diagnose(in).Render())
			for _, claim := range claims {
				idx := strings.Index(rendered, claim)
				if idx < 0 {
					continue
				}
				// "not that it was delivered" and "never delivered" are
				// disclaimers, so only an unnegated claim is a failure.
				prefix := rendered[max(0, idx-24):idx]
				if strings.Contains(prefix, "not ") || strings.Contains(prefix, "never ") {
					continue
				}
				t.Errorf("the diagnosis claims delivery with %q:\n%s", claim, rendered)
			}
		})
	}
}

func TestAcceptanceSaysWhatItDoesAndDoesNotEstablish(t *testing.T) {
	d := Diagnose(Input{
		Transcript: transcriptEndingWith(t, transcript.PhaseEndOfData, "250 2.0.0 OK\r\n"),
	})

	if !strings.Contains(d.Summary, "not that it was delivered") {
		t.Errorf("an acceptance summary does not disclaim delivery: %q", d.Summary)
	}
}

func TestDialFailureIsNotAPolicyDiagnosis(t *testing.T) {
	tr := transcript.NewTranscript("192.0.2.1:25", transcript.IdentityTriple{}, "rcpt@target.example")
	tr.Append(transcript.KindDial, transcript.PhaseDial, []byte("dial 192.0.2.1:25"))
	tr.Append(transcript.KindError, transcript.PhaseDial, []byte("dial tcp 192.0.2.1:25: i/o timeout"))

	d := Diagnose(Input{Transcript: tr})

	if !strings.Contains(d.Summary, "never reached the target") {
		t.Errorf("summary = %q, want it to say nothing was established about the identities", d.Summary)
	}
}

func TestDiagnosisRendersAsJSON(t *testing.T) {
	d := Diagnose(Input{
		Transcript: transcriptEndingWith(t, transcript.PhaseEndOfData, "550 5.7.1 no\r\n"),
	})

	out, err := d.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	for _, want := range []string{`"summary"`, `"confidence"`, `"evidence"`, `"observed"`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("json does not contain %s:\n%s", want, out)
		}
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return addr
}

// TestPlaintextProbeIsNotDiagnosedAsATLSFault guards the difference between a
// STARTTLS command that was sent and failed, and a note recording that the
// target never advertised the extension. Treating the note as an attempt
// turned every plaintext probe into a spurious transport diagnosis.
func TestPlaintextProbeIsNotDiagnosedAsATLSFault(t *testing.T) {
	tr := transcript.NewTranscript("mx.target.example:25", transcript.IdentityTriple{
		EnvelopeSender: "bounce@sender.example",
		HeloIdentity:   "frank.invalid",
		HeaderFrom:     "author@sender.example",
	}, "rcpt@target.example")
	tr.Append(transcript.KindNote, transcript.PhaseSTARTTLS, nil).Note =
		"starttls not advertised, continuing in plaintext"
	ev := tr.Append(transcript.KindRecv, transcript.PhaseEndOfData, []byte("550 5.7.1 message refused\r\n"))
	reply, err := transcript.ParseReply([]byte("550 5.7.1 message refused\r\n"))
	if err != nil {
		t.Fatalf("ParseReply: %v", err)
	}
	ev.Reply = reply

	d := Diagnose(Input{Transcript: tr})

	if strings.Contains(d.Summary, "STARTTLS") {
		t.Errorf("a plaintext probe was diagnosed as a TLS fault: %q", d.Summary)
	}
	if !strings.Contains(d.Summary, "rejected") {
		t.Errorf("summary = %q, want the rejection diagnosed", d.Summary)
	}
}

// TestQuitReplyIsNotTheOutcome guards a mistake that reported every refused
// probe as accepted: QUIT answers 221 on every exit path, including after a
// rejection, and it says nothing about the identities.
func TestQuitReplyIsNotTheOutcome(t *testing.T) {
	tr := transcript.NewTranscript("mx.target.example:25", transcript.IdentityTriple{
		EnvelopeSender: "bounce@sender.example",
		HeloIdentity:   "frank.invalid",
		HeaderFrom:     "ceo@victim.example",
	}, "rcpt@target.example")

	for _, step := range []struct {
		phase transcript.Phase
		raw   string
	}{
		{transcript.PhaseEndOfData, "550 5.7.1 message refused by policy\r\n"},
		{transcript.PhaseQuit, "221 2.0.0 closing connection\r\n"},
	} {
		ev := tr.Append(transcript.KindRecv, step.phase, []byte(step.raw))
		reply, err := transcript.ParseReply([]byte(step.raw))
		if err != nil {
			t.Fatalf("ParseReply(%q): %v", step.raw, err)
		}
		ev.Reply = reply
	}

	d := Diagnose(Input{Transcript: tr})

	if strings.Contains(d.Summary, "accepted") {
		t.Errorf("a rejected probe was diagnosed as accepted because QUIT answered 221: %q", d.Summary)
	}
	if !strings.Contains(d.Render(), "550") {
		t.Errorf("the diagnosis does not cite the 550 that decided it:\n%s", d.Render())
	}
}
