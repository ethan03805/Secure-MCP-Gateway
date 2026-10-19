//go:build unix

package sandbox

import (
	"os"
	"syscall"
)

func ownedBySelf(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// fileUID is the owner of a stat result, or -1.
func fileUID(st os.FileInfo) int {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(sys.Uid)
	}
	return -1
}
