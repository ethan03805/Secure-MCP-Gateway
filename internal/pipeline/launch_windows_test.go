//go:build windows

package pipeline

import (
	"context"
	"errors"
	"os"
	"testing"
)

// TestWindowsSubprocessLaunchFailsClosed: without the FR-21.11 launch rules
// and the FR-21.12 Job Object no server instance is started on Windows.
func TestWindowsSubprocessLaunchFailsClosed(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p, err := SubprocessLauncher{}.Launch(context.Background(), ServerSpec{Command: exe})
	if !errors.Is(err, ErrLaunchUnsupported) {
		if p != nil {
			p.Close()
		}
		t.Fatalf("Launch = %v, want ErrLaunchUnsupported", err)
	}
}
