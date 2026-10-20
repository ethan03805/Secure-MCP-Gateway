//go:build windows

package winsvc

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// The test binary doubles as the supervised child: with SMCP_WINSVC_CHILD
// set it counts its starts in a file, fails the first N, and then waits
// for the stop event and exits 0.
func TestMain(m *testing.M) {
	if dir := os.Getenv("SMCP_WINSVC_CHILD"); dir != "" {
		os.Exit(child(dir))
	}
	os.Exit(m.Run())
}

func child(dir string) int {
	countFile := filepath.Join(dir, "starts")
	b, _ := os.ReadFile(countFile)
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	n++
	_ = os.WriteFile(countFile, []byte(strconv.Itoa(n)), 0o600)
	fails, _ := strconv.Atoi(os.Getenv("SMCP_WINSVC_FAILS"))
	if n <= fails {
		return 3
	}
	ctx, release, err := StopContext(context.Background(), filepath.Join(dir, "smcp.toml"))
	if err != nil {
		return 4
	}
	defer release()
	select {
	case <-ctx.Done():
		_ = os.WriteFile(filepath.Join(dir, "stopped"), []byte("orderly"), 0o600)
		return 0
	case <-time.After(2 * time.Minute):
		return 5
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// TestWindowsSuperviseRestartsAndStops: the supervisor restarts a child
// that fails (FR-21.6, restart after a failure) and, when the stop event
// is set, the child stops in order and the supervisor returns (FR-21.7,
// the per-user stop). Partial: the real smcpd and the Task Scheduler
// start are covered by the windows CI job's install smoke test.
func TestWindowsSuperviseRestartsAndStops(t *testing.T) {
	reqtest.Partial(t, "FR-21.6", "FR-21.7")
	dir := t.TempDir()
	cfg := filepath.Join(dir, "smcp.toml")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SMCP_WINSVC_CHILD", dir)
	t.Setenv("SMCP_WINSVC_FAILS", "2")
	ctx, release, err := StopContext(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var log syncBuf
	done := make(chan error, 1)
	go func() {
		done <- Supervise(ctx, exe, []string{"-test.run=^$"}, SuperviseOptions{MinBackoff: 50 * time.Millisecond, StopWait: 30 * time.Second, Log: &log})
	}()
	// Two failed starts, then one that runs.
	deadline := time.Now().Add(30 * time.Second)
	for {
		b, _ := os.ReadFile(filepath.Join(dir, "starts"))
		if strings.TrimSpace(string(b)) == "3" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child not restarted; starts %q\n%s", b, log.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond) // the third child opens the event
	running, err := SignalStop(cfg)
	if err != nil || !running {
		t.Fatalf("SignalStop = %v, %v", running, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(40 * time.Second):
		t.Fatalf("supervisor did not return\n%s", log.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "stopped")); string(b) != "orderly" {
		t.Fatalf("child did not stop in order\n%s", log.String())
	}
	if n := strings.Count(log.String(), "restarting in"); n != 2 {
		t.Fatalf("%d restarts logged\n%s", n, log.String())
	}
	release()
	if running, _ := SignalStop(cfg); running {
		t.Fatal("stop event still open after every process released it")
	}
}

func TestWindowsHostVersionSupported(t *testing.T) {
	// GitHub's windows-latest and windows-11-arm runners meet FR-21.1.
	reqtest.Partial(t, "FR-21.1")
	v := HostVersion()
	if v.Major < 10 || v.Build == 0 {
		t.Fatalf("HostVersion = %+v", v)
	}
	if err := CheckVersion(v); err != nil {
		t.Fatalf("%v (runner image below the FR-21.1 minimum?)", err)
	}
	t.Logf("host: %s", v)
}
