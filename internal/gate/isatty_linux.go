//go:build linux

package gate

import "syscall"

const tcgets = syscall.TCGETS
