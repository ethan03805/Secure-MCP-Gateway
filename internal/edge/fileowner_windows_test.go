//go:build windows

package edge

import "os"

// fileGID: Windows files have no POSIX group.
func fileGID(os.FileInfo) (int, bool) { return 0, false }
