package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/MatrixMagician/Frank/internal/dmarc"
	"github.com/MatrixMagician/Frank/internal/explain"
	"github.com/MatrixMagician/Frank/internal/resolve"
	"github.com/MatrixMagician/Frank/internal/spf"
	"github.com/MatrixMagician/Frank/internal/transcript"
)

type explainFlags struct {
	authPath    string
	candidateIP string
}

func explainCmd(opts *Options, args []string, stdout, stderr io.Writer) Code {
	var ef explainFlags
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&ef.authPath, "auth", "", "a captured auth document; without it Frank performs the lookups itself")
	fs.StringVar(&ef.candidateIP, "candidate-ip", "", "the Candidate Sending IP to evaluate SPF against")

	if err := fs.Parse(args); err != nil {
		return CodeUsage
	}

	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(stderr, "frank explain: give exactly one transcript json file")
		return CodeUsage
	}

	raw, err := os.ReadFile(rest[0])
	if err != nil {
		fmt.Fprintf(stderr, "frank explain: %v\n", err)
		return CodeUsage
	}

	tr, err := decodeTranscript(raw)
	if err != nil {
		fmt.Fprintf(stderr, "frank explain: %s is not a readable transcript: %v\n", rest[0], err)
		return CodeUsage
	}

	in := explain.Input{Transcript: tr}
	if ef.authPath != "" {
		// SPEC.md: without --auth Frank performs the lookups itself. With it,
		// the supplied Verdicts are used as given, so a Diagnosis can be
		// reproduced from a captured pair without touching DNS again.
		if err := loadAuth(ef.authPath, &in); err != nil {
			fmt.Fprintf(stderr, "frank explain: %s is not a readable auth document: %v\n", ef.authPath, err)
			return CodeUsage
		}
	} else if err := populateVerdicts(context.Background(), &in, tr, ef, resolve.NewSystem()); err != nil {
		fmt.Fprintf(stderr, "frank explain: %v\n", err)
	}

	d := explain.Diagnose(in)

	if opts.JSON {
		out, err := d.RenderJSON()
		if err != nil {
			fmt.Fprintf(stderr, "frank explain: %v\n", err)
			return CodeIncomplete
		}
		fmt.Fprintln(stdout, string(out))
	} else {
		fmt.Fprint(stdout, d.Render())
	}

	return CodeAcceptance
}

// loadAuth reads a captured auth document, which is a report.json or the auth
// half of one. Only the sections a Diagnosis draws on are required.
func loadAuth(path string, in *explain.Input) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc struct {
		SPF   *spf.Result   `json:"spf"`
		DMARC *dmarc.Result `json:"dmarc"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	if doc.SPF == nil && doc.DMARC == nil {
		return fmt.Errorf("the document carries neither an spf nor a dmarc section")
	}
	in.SPF, in.DMARC = doc.SPF, doc.DMARC
	return nil
}

// transcriptDoc mirrors what transcript.RenderJSON writes, which is the shape
// explain reads back.
type transcriptDoc struct {
	TargetHost string `json:"target_host"`
	Identity   struct {
		EnvelopeSender string `json:"envelope_sender"`
		HeloIdentity   string `json:"helo_identity"`
		HeaderFrom     string `json:"header_from"`
	} `json:"identity"`
	Recipient     string `json:"recipient"`
	SourceAddress string `json:"source_address"`
	TLS           *struct {
		Version     string `json:"version"`
		Cipher      string `json:"cipher"`
		ServerName  string `json:"server_name"`
		Verified    bool   `json:"verified"`
		VerifyError string `json:"verify_error"`
	} `json:"tls"`
	Events []struct {
		Kind  string `json:"kind"`
		Phase string `json:"phase"`
		Raw   string `json:"raw"`
		Note  string `json:"note"`
		Reply *struct {
			Code int    `json:"code"`
			Text string `json:"text"`
		} `json:"reply"`
	} `json:"events"`
}

// decodeTranscript rebuilds enough of a Transcript for a Diagnosis. The raw
// bytes are reparsed rather than trusted from the document's parsed view, so a
// hand-edited file cannot smuggle in a reply that never crossed the wire.
func decodeTranscript(raw []byte) (*transcript.Transcript, error) {
	var doc transcriptDoc
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if len(doc.Events) == 0 {
		return nil, fmt.Errorf("the document carries no events")
	}

	tr := transcript.NewTranscript(doc.TargetHost, transcript.IdentityTriple{
		EnvelopeSender: doc.Identity.EnvelopeSender,
		HeloIdentity:   doc.Identity.HeloIdentity,
		HeaderFrom:     doc.Identity.HeaderFrom,
	}, doc.Recipient)

	if doc.TLS != nil {
		tr.TLS = &transcript.TLSDetails{
			Version:     doc.TLS.Version,
			Cipher:      doc.TLS.Cipher,
			ServerName:  doc.TLS.ServerName,
			Verified:    doc.TLS.Verified,
			VerifyError: doc.TLS.VerifyError,
		}
	}

	for _, e := range doc.Events {
		kind, err := parseKind(e.Kind)
		if err != nil {
			return nil, err
		}
		phase, err := parsePhase(e.Phase)
		if err != nil {
			return nil, err
		}
		ev := tr.Append(kind, phase, []byte(e.Raw))
		ev.Note = e.Note
		if kind == transcript.KindRecv {
			if reply, err := transcript.ParseReply([]byte(e.Raw)); err == nil {
				ev.Reply = reply
			}
		}
	}
	return tr, nil
}

func parseKind(s string) (transcript.Kind, error) {
	var k transcript.Kind
	if err := k.UnmarshalJSON([]byte(`"` + s + `"`)); err != nil {
		return 0, err
	}
	return k, nil
}

func parsePhase(s string) (transcript.Phase, error) {
	var p transcript.Phase
	if err := p.UnmarshalJSON([]byte(`"` + s + `"`)); err != nil {
		return 0, err
	}
	return p, nil
}

// populateVerdicts performs the lookups explain needs when it was not handed
// them, per SPEC.md: without --auth, Frank performs the lookups itself.
func populateVerdicts(ctx context.Context, in *explain.Input, tr *transcript.Transcript, ef explainFlags, r resolve.Resolver) error {
	req := spf.Request{
		EnvelopeSender: tr.Identity.EnvelopeSender,
		HeloIdentity:   tr.Identity.HeloIdentity,
	}

	candidateIP := ef.candidateIP
	if candidateIP == "" {
		candidateIP = tr.SourceAddr.String()
	}
	if candidateIP != "" {
		if addr, err := netip.ParseAddr(candidateIP); err == nil {
			if ip, err := spf.NewCandidateSendingIP(addr, ef.candidateIP == ""); err == nil {
				req.CandidateIP = &ip
			}
		}
	}

	if req.EnvelopeSender == "" && req.HeloIdentity == "" {
		return nil
	}

	spfRes, err := spf.Evaluate(ctx, r, req)
	if err != nil {
		return fmt.Errorf("spf lookup: %w", err)
	}
	in.SPF = spfRes

	headerFrom := domainOf(tr.Identity.HeaderFrom)
	if headerFrom == "" {
		return nil
	}
	dmarcRes, err := dmarc.Evaluate(ctx, r, dmarc.Input{
		HeaderFromDomain: headerFrom,
		SPF:              *spfRes,
	})
	if err != nil {
		return fmt.Errorf("dmarc lookup: %w", err)
	}
	in.DMARC = dmarcRes
	return nil
}
