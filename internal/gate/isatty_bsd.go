//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package gate

import "syscall"

const tcgets = syscall.TIOCGETA
