//go:build windows

package winsvc

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestWindowsPerUserRunningFollowsTheStopEvent: the running check sees a
// per-user Gateway while it holds its stop event and does not set the
// event (FR-20.3, the Desktop Application's status query).
func TestWindowsPerUserRunningFollowsTheStopEvent(t *testing.T) {
	reqtest.Partial(t, "FR-20.3")
	cfg := filepath.Join(t.TempDir(), "smcp.toml")
	if running, err := PerUserRunning(cfg); err != nil || running {
		t.Fatalf("before start: running=%v err=%v", running, err)
	}
	ctx, release, err := StopContext(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if running, err := PerUserRunning(cfg); err != nil || !running {
			t.Fatalf("while running: running=%v err=%v", running, err)
		}
	}
	if ctx.Err() != nil {
		t.Fatal("the running check set the stop event")
	}
	release()
	if running, err := PerUserRunning(cfg); err != nil || running {
		t.Fatalf("after release: running=%v err=%v", running, err)
	}
	other := filepath.Join(t.TempDir(), "smcp.toml")
	if running, _ := PerUserRunning(other); running {
		t.Fatal("another installation's event was seen")
	}
}

// TestWindowsQueryServiceUnelevated: the query needs no more than
// SC_MANAGER_CONNECT; an unregistered service reports not installed.
// (The runner may or may not have smcpd registered from another test;
// only the absence of an error is required then.)
func TestWindowsQueryServiceUnelevated(t *testing.T) {
	reqtest.Partial(t, "FR-20.3")
	running, installed, err := QueryService()
	if err != nil {
		t.Fatal(err)
	}
	if !installed && running {
		t.Fatal("an unregistered service reported running")
	}
}
