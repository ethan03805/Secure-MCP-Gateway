//go:build darwin

package perf

import "syscall"

// diskOf returns the size and free space of the file system that holds
// dir; the device and its model are reported on Linux only.
func diskOf(dir string) (size, free int64, device, model string) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err == nil {
		size, free = int64(st.Blocks)*int64(st.Bsize), int64(st.Bavail)*int64(st.Bsize) // #nosec G115 -- file system sizes fit in int64
	}
	return
}
