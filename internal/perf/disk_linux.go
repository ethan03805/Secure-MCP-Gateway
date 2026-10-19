//go:build linux

package perf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// diskOf returns the size and free space of the file system that holds
// dir, its block device and the device's model (or the parent device's,
// for a partition) where /sys reports one.
func diskOf(dir string) (size, free int64, device, model string) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err == nil {
		size, free = int64(st.Blocks)*int64(st.Bsize), int64(st.Bavail)*int64(st.Bsize) // #nosec G115 -- file system sizes fit in int64
	}
	var fi unix.Stat_t
	if err := unix.Stat(dir, &fi); err != nil {
		return
	}
	sys := fmt.Sprintf("/sys/dev/block/%d:%d", unix.Major(fi.Dev), unix.Minor(fi.Dev))
	real, err := filepath.EvalSymlinks(sys)
	if err != nil {
		return
	}
	device = filepath.Base(real)
	for _, p := range []string{filepath.Join(real, "device", "model"), filepath.Join(filepath.Dir(real), "device", "model")} {
		if b, err := os.ReadFile(p); err == nil {
			model = strings.TrimSpace(string(b))
			break
		}
	}
	return
}
