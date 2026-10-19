// Package testperm checks in tests that a file the Gateway wrote is
// private to the account that wrote it, on every platform: by its POSIX
// mode on Linux and macOS, and on Windows, which has no POSIX modes
// (SRS FR-21.2), by its DACL (only this account, SYSTEM and
// Administrators) and, for a read-only mode, the read-only attribute.
package testperm

import (
	"os"
	"runtime"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

// Equal fails t unless path has exactly the mode want on Linux and macOS,
// or, on Windows, is private to this account and read-only when want has
// no write bit.
func Equal(t testing.TB, path string, want os.FileMode) {
	t.Helper()
	check(t, path, want, true)
}

// AtMost fails t unless path's mode grants nothing beyond want on Linux
// and macOS, or, on Windows, path is private to this account.
func AtMost(t testing.TB, path string, want os.FileMode) {
	t.Helper()
	check(t, path, want, false)
}

func check(t testing.TB, path string, want os.FileMode, exact bool) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	perm := st.Mode().Perm()
	if runtime.GOOS == "windows" {
		if err := winsec.CheckOwnerOnly(path); err != nil {
			t.Errorf("%s is not private to this account: %v", path, err)
		}
		if !st.IsDir() && want&0o222 == 0 && perm&0o222 != 0 {
			t.Errorf("%s is not read-only", path)
		}
		return
	}
	if (exact && perm != want) || (!exact && perm&^want != 0) {
		t.Errorf("%s mode %v, want %v", path, perm, want)
	}
}
