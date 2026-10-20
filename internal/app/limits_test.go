package app

import (
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestRuntimeLimits: the Job Object limits come from [[runtime.server]],
// then the manifest, then [runtime] (CP-24 by default). Partial for
// FR-21.12: the Job Object itself is tested on Windows.
func TestRuntimeLimits(t *testing.T) {
	reqtest.Partial(t, "FR-21.12")
	rt := config.Runtime{MemoryBytes: 512 << 20, CPUs: 1, Pids: 128,
		Servers: []config.RuntimeServer{{Alias: "big", MemoryBytes: 2 << 30, Pids: 16}}}
	f := RuntimeLimits(rt)
	if got := f(pipeline.ServerSpec{Alias: "x"}); got != (pipeline.ResourceLimits{MemoryBytes: 512 << 20, CPUs: 1, Processes: 128}) {
		t.Fatalf("defaults: %+v", got)
	}
	m := pipeline.ResourceLimits{MemoryBytes: 64 << 20, CPUs: 0.5, Processes: 4}
	if got := f(pipeline.ServerSpec{Alias: "x", Limits: m}); got != m {
		t.Fatalf("manifest: %+v", got)
	}
	if got := f(pipeline.ServerSpec{Alias: "big", Limits: m}); got != (pipeline.ResourceLimits{MemoryBytes: 2 << 30, CPUs: 0.5, Processes: 16}) {
		t.Fatalf("per-server: %+v", got)
	}
}
