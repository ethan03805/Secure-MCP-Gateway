//go:build windows

package sandbox

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// killPID ends pid; Windows has no signals, so TERM and KILL both
// terminate the process.
func killPID(pid int, _ syscall.Signal) {
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}

func pidAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)) //nolint:gosec // a PID fits in uint32
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h) //nolint:errcheck
	var code uint32
	return windows.GetExitCodeProcess(h, &code) == nil && code == 259 // STILL_ACTIVE
}
