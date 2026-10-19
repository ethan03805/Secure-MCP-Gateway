//go:build windows

package main

import "os"

// canWritePath reports whether this user may write p: a file opened for
// writing, or a file created in a directory. Windows has no access(2); the
// .msi and its ACL check (SR-4.11-2) come with the Windows port.
func canWritePath(p string) bool {
	st, err := os.Stat(p)
	if err != nil {
		return false
	}
	if st.IsDir() {
		f, err := os.CreateTemp(p, ".smcp-doctor-*")
		if err != nil {
			return false
		}
		name := f.Name()
		f.Close()
		_ = os.Remove(name)
		return true
	}
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}
