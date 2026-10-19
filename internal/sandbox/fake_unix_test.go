//go:build unix

package sandbox

import "syscall"

func killPID(pid int, s syscall.Signal) { _ = syscall.Kill(pid, s) }

func pidAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }
