//go:build !windows

package winsvc

// QueryService returns ErrNotWindows.
func QueryService() (running, installed bool, err error) { return false, false, ErrNotWindows }

// PerUserRunning returns ErrNotWindows.
func PerUserRunning(string) (bool, error) { return false, ErrNotWindows }
