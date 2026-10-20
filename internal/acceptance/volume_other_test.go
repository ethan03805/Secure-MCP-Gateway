//go:build !windows

package acceptance

import "testing"

// smallVolumeWindows is used on Windows only.
func smallVolumeWindows(t *testing.T) string { t.Helper(); t.Skip("Windows only"); return "" }
