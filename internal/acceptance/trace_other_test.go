//go:build !windows

package acceptance

// startProcessTrace does nothing off Windows; the SR-4.8-2 trace is a
// Windows requirement.
func startProcessTrace() {}
