package obspolicy

import (
	"errors"
	"slices"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// The G-08 memory budget also carries the graph engine's heap and page
// cache budget: out-of-range values are refused, the published values are
// the effective budget, they wait for the next start while smcpd runs, and
// Apply at the next start puts them in the graph mirror's configuration
// copy (FR-8.16).
func TestGraphBudgetAppliesAtNextStart(t *testing.T) {
	reqtest.Partial(t, "FR-8.16")
	cfg := testConfig(t, "127.0.0.1:0")
	cfg.Graph.HeapBytes, cfg.Graph.PageCacheBytes = 1<<30, 512<<20
	s, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []MemoryBudget{
		{ObservationMemoryLimitBytes: 256 << 20, GraphHeapBytes: 1 << 20},
		{ObservationMemoryLimitBytes: 256 << 20, GraphPageCacheBytes: 128 << 30},
	} {
		if _, err := s.Publish(KindMemoryBudget, body(t, b), "operator:olga", ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: %v", b, err)
		}
	}
	// Started: Apply records the budget the mirror runs with; a live
	// applier is attached as smcpd does.
	start := *cfg
	if err := s.Apply(&start); err != nil {
		t.Fatal(err)
	}
	s.SetApplier(func(*config.Config) ([]string, error) { return nil, nil })
	if h, p := s.GraphBudget(); h != 1<<30 || p != 512<<20 {
		t.Fatalf("file budget: %d %d", h, p)
	}
	if _, err := s.Publish(KindMemoryBudget, body(t, MemoryBudget{ObservationMemoryLimitBytes: 256 << 20, GraphHeapBytes: 768 << 20, GraphPageCacheBytes: 256 << 20}), "operator:olga", ""); err != nil {
		t.Fatal(err)
	}
	if h, p := s.GraphBudget(); h != 768<<20 || p != 256<<20 {
		t.Fatalf("published budget: %d %d", h, p)
	}
	objs, _, _ := s.Status()
	for _, o := range objs {
		if o.Kind == KindMemoryBudget && (!o.Pending || !slices.Contains(o.RestartRequired, "graph_heap_bytes") || !slices.Contains(o.RestartRequired, "graph_page_cache_bytes")) {
			t.Fatalf("running: %+v", o)
		}
	}
	// Next start.
	s2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := *cfg
	if err := s2.Apply(&c); err != nil {
		t.Fatal(err)
	}
	if c.Graph.HeapBytes != 768<<20 || c.Graph.PageCacheBytes != 256<<20 || cfg.Graph.HeapBytes != 1<<30 {
		t.Fatalf("applied graph %+v (file %+v)", c.Graph, cfg.Graph)
	}
	s2.SetApplier(func(*config.Config) ([]string, error) { return nil, nil })
	objs, _, _ = s2.Status()
	for _, o := range objs {
		if o.Kind == KindMemoryBudget && (o.Pending || len(o.RestartRequired) != 0) {
			t.Fatalf("after the start: %+v", o)
		}
	}
	// A budget without graph fields keeps the [graph] values.
	if _, err := s2.Publish(KindMemoryBudget, body(t, MemoryBudget{ObservationMemoryLimitBytes: 256 << 20}), "operator:olga", ""); err != nil {
		t.Fatal(err)
	}
	if h, p := s2.GraphBudget(); h != 1<<30 || p != 512<<20 {
		t.Fatalf("without graph fields: %d %d", h, p)
	}
	// The default budget published explicitly is the budget in force.
	cfg.Graph = config.Graph{}
	s3, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c3 := *cfg
	if err := s3.Apply(&c3); err != nil {
		t.Fatal(err)
	}
	s3.SetApplier(func(*config.Config) ([]string, error) { return nil, nil })
	if _, err := s3.Publish(KindMemoryBudget, body(t, MemoryBudget{ObservationMemoryLimitBytes: 256 << 20, GraphHeapBytes: 1 << 30, GraphPageCacheBytes: 1 << 30}), "operator:olga", ""); err != nil {
		t.Fatal(err)
	}
	objs, _, _ = s3.Status()
	for _, o := range objs {
		if o.Kind == KindMemoryBudget && slices.ContainsFunc(o.RestartRequired, func(f string) bool { return f == "graph_heap_bytes" || f == "graph_page_cache_bytes" }) {
			t.Fatalf("default budget published: %+v", o)
		}
	}
}
