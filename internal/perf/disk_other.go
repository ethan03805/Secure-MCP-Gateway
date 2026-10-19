//go:build !linux && !darwin

package perf

// diskOf reports nothing here; the measurements run on Linux and macOS.
func diskOf(string) (size, free int64, device, model string) { return }
