//go:build !windows

package pipeline

// subprocessSupported reports whether SubprocessLauncher may start server
// instances on this platform.
func subprocessSupported() error { return nil }
