package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestMonitorCollectsObservables is FR-5.33: for one instance the Runtime
// Monitor collects each observable from the instance's cgroup: a process
// creation (a process_created event and observation), the memory peak and
// CPU time (the instance's usage sample) and an OOM limit event (a
// limit_breach event that carries the memory peak).
func TestMonitorCollectsObservables(t *testing.T) {
	reqtest.Verifies(t, "FR-5.33")
	rt := testRuntime()
	rt.Servers = []config.RuntimeServer{{Alias: "obs", AllowSpawn: true}}
	h := newHarness(t, rt)
	p, err := h.l.Launch(context.Background(), h.spec("obs"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	connect(t, p)
	name := h.l.Instances()[0].Container
	eventually(t, 3*time.Second, "running", func() bool { return h.l.Instances()[0].State == StateRunning })
	eventually(t, 3*time.Second, "main process", func() bool { return findEvent(h.mem.Events(), "process_created", "") != nil })

	// Memory peak and CPU time.
	h.cg(name, "memory.peak", "73400320\n")
	h.cg(name, "cpu.stat", "usage_usec 4242\nuser_usec 4000\nsystem_usec 242\n")
	eventually(t, 3*time.Second, "usage sample", func() bool {
		u := h.l.Instances()[0].Usage
		return u.MemoryPeak == 73400320 && u.CPUUsageUsec == 4242
	})
	// A process creation.
	pid, _ := os.ReadFile(filepath.Join(h.dir, name+".pid"))
	h.cg(name, "cgroup.procs", strings.TrimSpace(string(pid))+"\n424242\n")
	eventually(t, 3*time.Second, "process creation", func() bool {
		for _, e := range h.mem.Events() {
			if d, ok := e.Detail.(map[string]any); ok && e.Outcome == "process_created" && d["pid"] == 424242 {
				return true
			}
		}
		return false
	})
	created := false
	for _, o := range h.l.Instances()[0].Observations {
		created = created || (o.Kind == "process_created" && o.Detail["pid"] == 424242)
	}
	if !created {
		t.Fatal("process creation not in the instance's observations")
	}
	// An OOM limit event.
	h.cg(name, "memory.events", "low 0\nhigh 0\nmax 1\noom 1\noom_kill 1\n")
	eventually(t, 3*time.Second, "limit event", func() bool { return findEvent(h.mem.Events(), "limit_breach", ReasonMemoryLimit) != nil })
	e := findEvent(h.mem.Events(), "limit_breach", ReasonMemoryLimit)
	if d := e.Detail.(map[string]any); d["memory_peak_bytes"] != int64(73400320) && d["memory_peak_bytes"] != 73400320 {
		t.Fatalf("limit event detail %+v", d)
	}
}

// TestContainmentActionsWithinOneSecond is FR-5.35: for each containment
// action of a deviation rule, the action is performed within 1 second of
// the deviation: `alert` records the deviation and leaves the instance
// serving; `kill-instance` records it and has the instance killed.
func TestContainmentActionsWithinOneSecond(t *testing.T) {
	reqtest.Verifies(t, "FR-5.35")
	for _, rule := range []string{ActionAlert, ActionKill} {
		t.Run(rule, func(t *testing.T) {
			rt := testRuntime()
			rt.Servers = []config.RuntimeServer{{Alias: "dv", OnDeviation: rule}}
			h := newHarness(t, rt)
			p, err := h.l.Launch(context.Background(), h.spec("dv"))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			sess := connect(t, p)
			name := h.l.Instances()[0].Container
			eventually(t, 3*time.Second, "first sample", func() bool { return findEvent(h.mem.Events(), "process_created", "") != nil })
			pid, _ := os.ReadFile(filepath.Join(h.dir, name+".pid"))
			h.cg(name, "cgroup.procs", strings.TrimSpace(string(pid))+"\n999998\n")
			eventually(t, 3*time.Second, "deviation", func() bool {
				return findEvent(h.mem.Events(), "deviation", ReasonUndeclaredProcess) != nil
			})
			e := findEvent(h.mem.Events(), "deviation", ReasonUndeclaredProcess)
			d := e.Detail.(map[string]any)
			if d["action"] != rule {
				t.Fatalf("action %v", d)
			}
			switch rule {
			case ActionAlert:
				// The alert is the deviation record itself; the instance keeps serving.
				if got := callText(t, sess, "echo", map[string]any{"text": "alive"}); got != "alive" || strings.Contains(h.kills(name), "KILL") {
					t.Fatal("alert stopped the instance")
				}
			case ActionKill:
				// The monitor measures from the matched deviation to the kill.
				ms, ok := d["latency_ms"].(int64)
				if !ok || ms > 1000 {
					t.Fatalf("kill latency %v", d["latency_ms"])
				}
				if !strings.Contains(h.kills(name), "KILL") {
					t.Fatal("instance not killed")
				}
			}
		})
	}
}
