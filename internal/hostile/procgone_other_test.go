//go:build hostile && !windows

package hostile

import "syscall"

// processGone reports whether the process pid has ended.
func processGone(pid int) bool { return syscall.Kill(pid, 0) != nil }
