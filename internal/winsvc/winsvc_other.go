//go:build !windows

package winsvc

import (
	"context"
	"io"
	"os"
	"time"
)

// HostVersion returns the zero Version off Windows.
func HostVersion() Version { return Version{} }

// StopContext returns ErrNotWindows.
func StopContext(context.Context, string) (context.Context, func(), error) {
	return nil, nil, ErrNotWindows
}

// SignalStop returns ErrNotWindows.
func SignalStop(string) (bool, error) { return false, ErrNotWindows }

// SuperviseOptions bound the supervisor's restarts (Windows only).
type SuperviseOptions struct {
	StopWait, MinBackoff, MaxBackoff, ResetAfter time.Duration
	Log                                          io.Writer
}

// Supervise returns ErrNotWindows.
func Supervise(context.Context, string, []string, SuperviseOptions) error { return ErrNotWindows }

// SetRunValue returns ErrNotWindows.
func SetRunValue(string) error { return ErrNotWindows }

// RunValueData returns "".
func RunValueData() string { return "" }

// DeleteRunValue returns ErrNotWindows.
func DeleteRunValue() error { return ErrNotWindows }

// ServiceImage returns ErrNotWindows.
func ServiceImage() (string, bool, error) { return "", false, ErrNotWindows }

// StopService returns ErrNotWindows.
func StopService(time.Duration) error { return ErrNotWindows }

// DeleteService returns ErrNotWindows.
func DeleteService() error { return ErrNotWindows }

// StartDetached returns ErrNotWindows.
func StartDetached(string, []string, string, *os.File) (int, error) { return 0, ErrNotWindows }
