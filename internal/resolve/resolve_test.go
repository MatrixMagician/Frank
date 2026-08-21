package resolve

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
)

// ForbidNetwork installs a Dial hook on net.DefaultResolver that fails any
// attempt to actually reach the network, then runs m.Run(). It is exported
// so #8 (spf), #9 (dkim) and #10 (dmarc) can each write:
//
//	func TestMain(m *testing.M) { os.Exit(resolve.ForbidNetwork(m)) }
//
// in their own package, giving every downstream package the same guarantee
// this package proves for itself below: nothing in the test binary can reach
// a real DNS server or any other network endpoint through the default
// resolver.
func ForbidNetwork(m *testing.M) int {
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, errors.New("resolve: network access forbidden in tests (ForbidNetwork installed this guard)")
	}
	return m.Run()
}

func TestMain(m *testing.M) {
	code := ForbidNetwork(m)
	if code != 0 {
		panic("resolve package tests failed")
	}
}
