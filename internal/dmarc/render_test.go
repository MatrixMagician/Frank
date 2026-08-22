package dmarc

import (
	"context"
	"strings"
	"testing"

	"github.com/MatrixMagician/Frank/internal/resolve"
)

func TestRenderIncludesAlignmentAndCaveat(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("_dmarc.example.com", "v=DMARC1; p=reject; pct=25")

	res, err := Evaluate(context.Background(), z, Input{
		HeaderFromDomain: "example.com",
		DKIMDomain:       "mail.example.com",
		DKIMPass:         false,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	out := Render(res)
	for _, want := range []string{"subject:", "spf alignment:", "dkim alignment:", "effective policy: reject", "dmarc: fail", "caveat:", "pct=25"} {
		if !strings.Contains(out, want) {
			t.Errorf("Render output missing %q, got:\n%s", want, out)
		}
	}
}

func TestRenderNoPolicyFound(t *testing.T) {
	z := resolve.NewZone()

	res, err := Evaluate(context.Background(), z, Input{HeaderFromDomain: "example.com"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	out := Render(res)
	if !strings.Contains(out, "policy: none found") {
		t.Errorf("Render output missing %q, got:\n%s", "policy: none found", out)
	}
}
