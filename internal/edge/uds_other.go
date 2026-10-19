//go:build !windows

package edge

// udsSupported reports whether the UDS Harness Profile can listen here.
func udsSupported() error { return nil }
