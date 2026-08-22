package spf

import (
	"os"
	"testing"

	"github.com/MatrixMagician/Frank/internal/resolve"
)

func TestMain(m *testing.M) {
	os.Exit(resolve.ForbidNetwork(m))
}
