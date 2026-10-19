//go:build windows

package filters

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// evalPath resolves an existing path to its final path with
// GetFinalPathNameByHandle (FR-21.25): symbolic links, junctions and other
// mount points are followed, and short (8.3) names are expanded, which
// filepath.EvalSymlinks does not do for junctions.
func evalPath(p string) (string, error) {
	n, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(n, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", &os.PathError{Op: "open", Path: p, Err: err}
	}
	defer func() { _ = windows.CloseHandle(h) }()
	buf := make([]uint16, 512)
	for {
		m, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0) //nolint:gosec // the buffer length
		if err != nil {
			return "", &os.PathError{Op: "GetFinalPathNameByHandle", Path: p, Err: err}
		}
		if int(m) < len(buf) {
			s := windows.UTF16ToString(buf[:m])
			switch {
			case strings.HasPrefix(s, `\\?\UNC\`):
				s = `\\` + s[len(`\\?\UNC\`):]
			case strings.HasPrefix(s, `\\?\`):
				s = s[len(`\\?\`):]
			}
			return s, nil
		}
		buf = make([]uint16, m+1)
	}
}
