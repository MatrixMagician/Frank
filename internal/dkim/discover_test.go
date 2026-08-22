package dkim

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/MatrixMagician/Frank/internal/resolve"
)

const seededRSARecord = "v=DKIM1; k=rsa; p=" + realWorldRSAPublicKey

func TestDiscoveryFindsSeededSelectorAmongDecoys(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("selector2._domainkey.example.com", seededRSARecord)

	res, err := Discover(context.Background(), z, "example.com", Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if len(res.Found) != 1 {
		t.Fatalf("Found = %v, want exactly 1 key", res.Found)
	}
	if res.Found[0].Selector != "selector2" {
		t.Fatalf("Found[0].Selector = %q, want selector2", res.Found[0].Selector)
	}
	if !res.Found[0].Present {
		t.Fatalf("Found[0].Present = false, want true")
	}
}

func TestSelectorFlagExtendsBuiltInList(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("custom-corp-selector._domainkey.example.com", seededRSARecord)

	res, err := Discover(context.Background(), z, "example.com", Options{
		Selectors: []string{"custom-corp-selector"},
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	found := false
	for _, s := range res.Probed {
		if s == "custom-corp-selector" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Probed = %v, want to contain custom-corp-selector", res.Probed)
	}

	if len(res.Found) != 1 || res.Found[0].Selector != "custom-corp-selector" {
		t.Fatalf("Found = %v, want exactly the custom selector", res.Found)
	}
}

func TestExplicitSelectorAlreadyBuiltInIsNotProbedTwice(t *testing.T) {
	z := resolve.NewZone()

	res, err := Discover(context.Background(), z, "example.com", Options{
		Selectors: []string{"google", "google"},
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	count := 0
	for _, s := range res.Probed {
		if s == "google" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("Probed contains %q %d times, want 1", "google", count)
	}

	queried := 0
	for _, q := range z.Queries() {
		if strings.HasPrefix(q.Name, "google._domainkey.") {
			queried++
		}
	}
	if queried != 1 {
		t.Fatalf("google._domainkey queried %d times, want 1", queried)
	}
}

func TestEffectiveSelectorListAppearsInBothRenderings(t *testing.T) {
	z := resolve.NewZone()

	res, err := Discover(context.Background(), z, "example.com", Options{
		Selectors: []string{"a-custom-one"},
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	text := Render(res)
	if !strings.Contains(text, "a-custom-one") {
		t.Fatalf("text rendering missing probed selector a-custom-one:\n%s", text)
	}
	for _, s := range builtinSelectors {
		if !strings.Contains(text, s) {
			t.Fatalf("text rendering missing built-in selector %q:\n%s", s, text)
		}
	}

	var buf strings.Builder
	if err := RenderJSON(&buf, res); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var decoded struct {
		Probed []string `json:"probed"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(decoded.Probed) != len(res.Probed) {
		t.Fatalf("JSON probed list = %v, want %v", decoded.Probed, res.Probed)
	}
	foundCustom := false
	for _, s := range decoded.Probed {
		if s == "a-custom-one" {
			foundCustom = true
		}
	}
	if !foundCustom {
		t.Fatalf("JSON probed list missing a-custom-one: %v", decoded.Probed)
	}
}

func TestDiscoveryQueryVolumeBoundedAndStated(t *testing.T) {
	z := resolve.NewZone()

	bound := 5
	res, err := Discover(context.Background(), z, "example.com", Options{Bound: bound})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if z.QueryCount() > bound {
		t.Fatalf("QueryCount = %d, want <= bound %d", z.QueryCount(), bound)
	}
	if res.QueriesMade > bound {
		t.Fatalf("QueriesMade = %d, want <= bound %d", res.QueriesMade, bound)
	}
	if res.Bound != bound {
		t.Fatalf("res.Bound = %d, want %d", res.Bound, bound)
	}

	text := Render(res)
	if !strings.Contains(text, "5") {
		t.Fatalf("rendering does not state the bound (5):\n%s", text)
	}
}

func TestDiscoveryDefaultBoundIsEffectiveListLength(t *testing.T) {
	z := resolve.NewZone()

	res, err := Discover(context.Background(), z, "example.com", Options{
		Selectors: []string{"one-extra"},
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if res.Bound != len(res.Probed) {
		t.Fatalf("default Bound = %d, want len(Probed) = %d", res.Bound, len(res.Probed))
	}
	if z.QueryCount() != len(res.Probed) {
		t.Fatalf("QueryCount = %d, want %d (every probed selector queried once)", z.QueryCount(), len(res.Probed))
	}
}

func TestNullResultReadsAsCheckedNotSilent(t *testing.T) {
	z := resolve.NewZone()

	res, err := Discover(context.Background(), z, "example.com", Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if len(res.Found) != 0 {
		t.Fatalf("Found = %v, want empty", res.Found)
	}
	if len(res.Probed) == 0 {
		t.Fatalf("Probed is empty, want the effective selector list")
	}

	text := Render(res)
	if !strings.Contains(text, "none of the probed selectors answered") {
		t.Fatalf("rendering does not read as checked-not-silent:\n%s", text)
	}
	if !strings.Contains(text, "default") || !strings.Contains(text, "google") {
		t.Fatalf("rendering does not list what was checked:\n%s", text)
	}
}

func TestDiscoveryPropagatesTemporaryFailure(t *testing.T) {
	z := resolve.NewZone()
	z.Temporary("default._domainkey.example.com")

	_, err := Discover(context.Background(), z, "example.com", Options{})
	if err == nil {
		t.Fatalf("expected an error for a temporary DNS failure")
	}
	if !resolve.IsTemporary(err) {
		t.Fatalf("err = %v, want KindTemporary", err)
	}
}

func TestDiscoveryIgnoresNonAnsweringDecoys(t *testing.T) {
	z := resolve.NewZone()
	z.TXT("mail._domainkey.example.com", "not a dkim record at all")
	z.TXT("dkim._domainkey.example.com", seededRSARecord)

	res, err := Discover(context.Background(), z, "example.com", Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if len(res.Found) != 2 {
		t.Fatalf("Found = %v, want 2 selectors present (both answered, one unparseable)", res.Found)
	}
	var mailKey, dkimKey *Key
	for i := range res.Found {
		switch res.Found[i].Selector {
		case "mail":
			mailKey = &res.Found[i]
		case "dkim":
			dkimKey = &res.Found[i]
		}
	}
	if mailKey == nil || len(mailKey.Faults) == 0 || mailKey.Faults[0] != FaultUnparseableRecord {
		t.Fatalf("mail selector faults = %+v, want [%s]", mailKey, FaultUnparseableRecord)
	}
	if dkimKey == nil || len(dkimKey.Faults) != 0 {
		t.Fatalf("dkim selector faults = %+v, want none", dkimKey)
	}
}
