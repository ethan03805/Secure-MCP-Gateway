//go:build !windows

package winsec

// ProcessUserSID returns ErrNotWindows.
func ProcessUserSID() (string, error) { return "", ErrNotWindows }

// LookupSID returns ErrNotWindows.
func LookupSID(string) (string, error) { return "", ErrNotWindows }

// SetProtectedDACL returns ErrNotWindows.
func SetProtectedDACL(string, []Entry) error { return ErrNotWindows }

// DACL returns ErrNotWindows.
func DACL(string) (protected, null bool, entries []Entry, err error) {
	return false, false, nil, ErrNotWindows
}

// CheckDACL returns ErrNotWindows.
func CheckDACL(string, bool, ...string) error { return ErrNotWindows }

// Grant returns ErrNotWindows.
func Grant(string, string, Access) error { return ErrNotWindows }

// Revoke returns ErrNotWindows.
func Revoke(string, string) error { return ErrNotWindows }

// Protect returns ErrNotWindows.
func Protect([]byte) ([]byte, error) { return nil, ErrNotWindows }

// Unprotect returns ErrNotWindows.
func Unprotect([]byte) ([]byte, error) { return nil, ErrNotWindows }

// FreeBytes returns ErrNotWindows.
func FreeBytes(string) (uint64, error) { return 0, ErrNotWindows }

// ReplaceFile returns ErrNotWindows.
func ReplaceFile(string, string) error { return ErrNotWindows }

// CheckOwnerOnly returns ErrNotWindows.
func CheckOwnerOnly(string) error { return ErrNotWindows }

// SecureOwnerOnly returns ErrNotWindows.
func SecureOwnerOnly(string) error { return ErrNotWindows }
