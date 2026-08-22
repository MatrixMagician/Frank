package resolve

import (
	"context"
	"errors"
	"net"
	"testing"
)

// ForbidNetwork installs a Dial hook on net.DefaultResolver that fails any
// attempt to actually reach the network, then runs m.Run(). It is exported
// so #8 (spf), #9 (dkim) and #10 (dmarc) can each write:
//
//	func TestMain(m *testing.M) { os.Exit(resolve.ForbidNetwork(m)) }
//
// in their own package, giving every downstream package the same guarantee
// this package proves for itself in resolve_test.go: nothing in the test
// binary can reach a real DNS server or any other network endpoint through
// the default resolver. It lives in a non-test file, rather than beside its
// own TestMain, because a _test.go symbol is invisible to an importer
// outside this package's own test binary.
func ForbidNetwork(m *testing.M) int {
	deny := func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, errors.New("resolve: network access forbidden in tests (ForbidNetwork installed this guard)")
	}
	net.DefaultResolver.Dial = deny
	dialDNS = deny
	return m.Run()
}
