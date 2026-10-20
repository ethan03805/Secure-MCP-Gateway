package connector_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cfharness"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *testClock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// TestStartOnDemand is FR-22.23 with the Connector's demand loop running
// (checks every 20 ms) on a test clock: the instance is stopped until a
// probe needs it; it runs during the probe and, with nothing enabled,
// stops when the clock passes 30 seconds after the probe and not
// before; enabling the imported hosted revision starts it again; a
// second probe while the revision is enabled leaves it running; after
// the revision is disabled it stops within 30 seconds of the clock.
func TestStartOnDemand(t *testing.T) {
	reqtest.Verifies(t, "FR-22.23")
	clock := &testClock{t: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{{ID: "od-a", URL: "https://od-a.example.com/mcp"}, {ID: "od-b", URL: "https://od-b.example.com/mcp"}},
		Now: clock.now, DemandInterval: 20 * time.Millisecond})
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	e.Conn.Start(ctx)
	state := func() string { return e.Conn.Instance().State }
	waitFor := func(want string, why string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for state() != want {
			if time.Now().After(deadline) {
				t.Fatalf("%s: instance %s, want %s", why, state(), want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	stays := func(want, why string) {
		t.Helper()
		time.Sleep(150 * time.Millisecond) // several demand checks
		if got := state(); got != want {
			t.Fatalf("%s: instance %s, want %s", why, got, want)
		}
	}
	stays(bundle.StateStopped, "nothing enabled, no probe")

	// A probe starts it; 30 seconds after it ended, it stops.
	p, err := e.Probe("od-a", connector.LocalImport{})
	if err != nil || p.State != "ready" {
		t.Fatalf("probe: %v %+v", err, p)
	}
	if state() == bundle.StateStopped {
		t.Fatal("the probe ran without the instance")
	}
	stays(bundle.StateHealthy, "just after the probe")
	clock.add(29 * time.Second)
	stays(bundle.StateHealthy, "29 s after the probe")
	clock.add(time.Second)
	waitFor(bundle.StateStopped, "30 s after the probe")

	// Enabling the imported revision starts it.
	got, err := e.Conn.Decide(p.ID, true, p.Decision.SHA256, "op")
	if err != nil {
		t.Fatal(err)
	}
	stays(bundle.StateStopped, "imported, not enabled")
	if _, err := e.Lib.Enable(got.ServerID, got.Revision, library.EnableOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(bundle.StateHealthy, "enabled")
	// A probe while it is enabled; then the revision disabled.
	if q, err := e.Probe("od-b", connector.LocalImport{}); err != nil || q.State != "ready" {
		t.Fatalf("second probe: %v %+v", err, q)
	}
	clock.add(time.Hour)
	stays(bundle.StateHealthy, "enabled, an hour after the second probe")
	if _, _, err := e.Lib.SetState(got.ServerID, got.Revision, library.StateVerifiedDisabled, "test", "op"); err != nil {
		t.Fatal(err)
	}
	stays(bundle.StateHealthy, "just after disabling")
	clock.add(29 * time.Second)
	stays(bundle.StateHealthy, "29 s after disabling")
	clock.add(time.Second)
	waitFor(bundle.StateStopped, "30 s after disabling")
}
