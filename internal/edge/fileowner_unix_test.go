//go:build unix

package edge

import (
	"os"
	"syscall"
)

// fileGID is the group of a stat result.
func fileGID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Gid), true
}
