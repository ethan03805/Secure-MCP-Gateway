//go:build !windows

package backup

// secureRestored does nothing off Windows: the extracted state directory
// already has mode 0700.
func secureRestored(string, string) error { return nil }
