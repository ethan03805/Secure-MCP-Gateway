//go:build windows

package edge

import "testing"

// TestWindowsUDSRefused: the UDS Harness Profile never opens an AF_UNIX
// socket on Windows (FR-21.8).
func TestWindowsUDSRefused(t *testing.T) {
	if err := udsSupported(); err == nil {
		t.Fatal("udsSupported() = nil on Windows")
	}
}
