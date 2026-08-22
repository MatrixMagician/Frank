package resolve

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Exit(ForbidNetwork(m))
}
