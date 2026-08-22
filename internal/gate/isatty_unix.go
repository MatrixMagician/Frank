//go:build unix

package gate

import (
	"syscall"
	"unsafe"
)

// isTerminal asks the kernel whether fd is a tty, which is what isatty(3) does.
// A character-device check alone would accept /dev/null.
func isTerminal(fd uintptr) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL, fd, tcgets,
		uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return errno == 0
}
