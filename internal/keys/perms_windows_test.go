//go:build windows

package keys

import (
	"errors"
	"testing"
)

// TestWindowsCheckPrivateFailsClosed: without the FR-21.5 DACL check the
// Gateway refuses to start on Windows instead of trusting file modes.
func TestWindowsCheckPrivateFailsClosed(t *testing.T) {
	if err := CheckPrivate(t.TempDir()); !errors.Is(err, ErrUnprotectedPlatform) {
		t.Fatalf("CheckPrivate = %v, want ErrUnprotectedPlatform", err)
	}
}
