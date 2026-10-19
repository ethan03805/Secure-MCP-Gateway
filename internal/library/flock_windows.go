//go:build windows

package library

import (
	"os"

	"golang.org/x/sys/windows"
)

// flockExclusive takes a non-blocking exclusive lock on the first byte of f
// with LockFileEx, the Windows counterpart of flock(LOCK_EX|LOCK_NB).
func flockExclusive(f *os.File) error {
	var ol windows.Overlapped
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
}

// flockRelease releases the lock flockExclusive took.
func flockRelease(f *os.File) error {
	var ol windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol)
}
