//go:build !unix

package gate

// isTerminal cannot be answered without a platform call here, so Frank assumes
// no terminal. That is the safe direction: a run needing confirmation errors
// rather than transmitting.
func isTerminal(fd uintptr) bool { return false }
