//go:build windows

package winsvc

import "golang.org/x/sys/windows"

// ProgramData and ProgramFiles ask Windows for the folders instead of
// reading the ProgramData and ProgramFiles environment variables, which a
// process of the user can set for the user's later sessions (HKCU
// Environment), elevated ones included: the machine mode must not put the
// service binary or its state in a folder the user chose (security review
// v1.3, SR-20).
func ProgramData() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0); err == nil && p != "" {
		return p
	}
	return `C:\ProgramData`
}

// ProgramFiles is the 64-bit Program Files folder (see ProgramData).
func ProgramFiles() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0); err == nil && p != "" {
		return p
	}
	return `C:\Program Files`
}
