//go:build unix

package library

import (
	"os"
	"syscall"
)

// flockExclusive takes a non-blocking exclusive advisory lock on f.
func flockExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // a file descriptor fits in int
}

// flockRelease releases the lock flockExclusive took.
func flockRelease(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:gosec // a file descriptor fits in int
}
