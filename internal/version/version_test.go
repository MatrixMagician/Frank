package version

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for range 8 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("no go.mod found above the test's working directory")
	return ""
}

// TestGoModHasNoThirdPartyRequirements pins issue #1's rule that Frank adds no
// dependency. scripts/check.sh asserts it too, but a contributor running the
// suite alone should still find out.
func TestGoModHasNoThirdPartyRequirements(t *testing.T) {
	root := repoRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	body := string(raw)

	if strings.Contains(body, "require") {
		t.Errorf("go.mod declares a requirement, but Frank takes no dependency:\n%s", body)
	}
	if strings.Contains(body, "replace") {
		t.Errorf("go.mod declares a replace directive:\n%s", body)
	}

	sum := filepath.Join(root, "go.sum")
	if info, err := os.Stat(sum); err == nil && info.Size() > 0 {
		t.Errorf("go.sum exists and is %d bytes, so something was vendored in", info.Size())
	}
}

// TestCIRunsVetAndRace pins the workflow's shape, so a later edit cannot
// quietly drop the race detector the concurrent matrix runner depends on.
func TestCIRunsVetAndRace(t *testing.T) {
	root := repoRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read the ci workflow: %v", err)
	}
	body := string(raw)

	for _, want := range []string{
		"go vet ./...",
		"go test -race ./...",
		"go build ./...",
		"CGO_ENABLED: 0",
		// -race needs cgo while the shipped binary must stay static, so the
		// workflow has to set the two differently. A single global setting
		// makes one of the steps impossible.
		"CGO_ENABLED: 1",
		"statically linked",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the ci workflow does not contain %q", want)
		}
	}

	for _, trigger := range []string{"push:", "pull_request:"} {
		if !strings.Contains(body, trigger) {
			t.Errorf("the ci workflow does not run on %s", trigger)
		}
	}
}

func TestVersionIsSet(t *testing.T) {
	if strings.TrimSpace(Version) == "" {
		t.Error("Version is empty, so frank --version would print nothing")
	}
}
