//go:build windows

package sandbox

import "os"

// ownedBySelf reports false on Windows: files have no POSIX owner UID, so
// no cgroup delegation is ever treated as the gateway's own.
func ownedBySelf(os.FileInfo) bool { return false }

// fileUID is -1 on Windows, which has no POSIX owner UID.
func fileUID(os.FileInfo) int { return -1 }
