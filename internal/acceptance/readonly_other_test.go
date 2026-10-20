//go:build !windows

package acceptance

import (
	"os"
	"testing"
)

// setReadOnlyDir makes dir unwritable (mode 0500), or writable again (0700).
func setReadOnlyDir(t *testing.T, dir string, readOnly bool) {
	t.Helper()
	mode := os.FileMode(0o700)
	if readOnly {
		mode = 0o500
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
}
