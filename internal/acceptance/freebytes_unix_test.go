//go:build unix

package acceptance

import (
	"syscall"
	"testing"
)

func freeBytes(t *testing.T, dir string) uint64 {
	t.Helper()
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	return uint64(st.Bavail) * uint64(st.Bsize) //nolint:gosec,unconvert // Bsize is int64 on Linux, uint32 on macOS
}
