package analytics

import (
	"context"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// feedCall feeds the evidence events of one delivered call.
func feedCall(c *observe.Collector, corr string, at time.Time) {
	base := audit.Event{CorrelationID: corr, SessionID: "s1", PrincipalID: "p1", ServerRevision: "live-abc", ToolRevision: "live-abc/read",
		PolicyRevision: "rev-1"}
	for i, st := range []struct {
		class string
		phase audit.Phase
	}{{"call", audit.PhaseRequested}, {"decision", audit.PhaseAuthorized}, {"call", audit.PhaseDispatched}, {"call", audit.PhaseCompleted}, {"call", audit.PhaseDelivered}} {
		e := base
		e.Class, e.Phase, e.Time = st.class, st.phase, at.Add(time.Duration(i)*time.Millisecond).Format(time.RFC3339Nano)
		if st.class != "call" || st.phase != audit.PhaseRequested {
			e.DecisionID = "dec-" + corr
		}
		c.Observe(e)
	}
}

// TestDropAccountingUnderInjectedBackpressure: backpressure is injected at
// each bounded queue of the observation path (the collector's input queue
// with its consumer stalled, the Observation Store writer's queue with the
// store stalled, and the evidence fan-out's queue for the collector), and
// calls are sampled down; the counts per reason equal the injected drop
// volume, and P-246 in the meta-metrics sample reports the same counts
// (FR-10.8).
func TestDropAccountingUnderInjectedBackpressure(t *testing.T) {
	reqtest.Verifies(t, "FR-10.8")
	cfg := parse(t, "store = \"jsonl\"\nqueue = 32\nsampling_rate = 1.0")
	cfg.State.Dir = t.TempDir()
	s, err := New(Options{Config: cfg, Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	if s.writer == nil {
		t.Fatalf("store: %v", s.storeErr)
	}
	// Not started: the collector's consumer and the store writer are
	// stalled. 1,000 observables into a queue of 32.
	const observables, rows = 1000, 300
	for i := 0; i < observables/2; i++ {
		s.Collector.Observe(audit.Event{CorrelationID: fmt.Sprintf("bp-%d", i), Class: "call", Phase: audit.PhaseRequested, Time: time.Now().Format(time.RFC3339Nano)})
		s.Collector.Offer(&observe.Probe{CorrelationID: fmt.Sprintf("bp-%d", i)})
	}
	// 300 captured records into the writer's queue of 32.
	for i := 0; i < rows; i++ {
		s.writeRecord(&observe.Record{CorrelationID: fmt.Sprintf("rec-%d", i), Time: time.Now(), Values: map[string]any{"request_bytes": int64(i)}})
	}
	const fanoutDropped = 77
	want := map[string]uint64{observe.DropQueueFull: observables - 32, observe.DropStoreQueue: rows - 32}
	if got := s.Drops(); !maps.Equal(got, want) {
		t.Fatalf("drops %v, want %v", got, want)
	}
	// The evidence fan-out's drops for the collector are part of P-246.
	s.Start(context.Background(), &audit.Memory{}, nil, func() uint64 { return fanoutDropped })
	t.Cleanup(s.Close)
	s.Sync()
	want[observe.DropObserver] = fanoutDropped
	if got := s.Drops(); !maps.Equal(got, want) {
		t.Fatalf("drops after start %v, want %v", got, want)
	}
	reported, ok := s.MetricsRow()["capture_drops"].(map[string]uint64)
	if !ok || !maps.Equal(reported, want) {
		t.Fatalf("P-246 in the meta-metrics %v, want %v", s.MetricsRow()["capture_drops"], want)
	}

	// Sampling down: at a rate of 0.25, every assembled call that is not
	// captured is counted as sampled down (or, under pressure, degraded).
	cfg2 := parse(t, "store = \"jsonl\"\nqueue = 20000\nsampling_rate = 0.25")
	cfg2.State.Dir = t.TempDir()
	s2, err := New(Options{Config: cfg2, Log: diag.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	s2.Start(context.Background(), &audit.Memory{}, nil, nil)
	t.Cleanup(s2.Close)
	const calls = 2000
	t0 := time.Now().Add(-time.Hour)
	for i := 0; i < calls; i++ {
		feedCall(s2.Collector, fmt.Sprintf("call-%05d", i), t0.Add(time.Duration(i)*time.Second))
	}
	s2.Sync()
	st := s2.Collector.Stats()
	d := s2.Drops()
	if st.Assembled != calls {
		t.Fatalf("assembled %d of %d", st.Assembled, calls)
	}
	if d[observe.DropSampledDown] == 0 || d[observe.DropSampledDown]+d[observe.DropDegraded]+st.Captured != calls {
		t.Fatalf("sampled down %d + degraded %d + captured %d != %d calls (drops %v)", d[observe.DropSampledDown], d[observe.DropDegraded], st.Captured, calls, d)
	}
	recs := scanAll(t, s2, "records")
	if uint64(len(recs)) != st.Captured {
		t.Fatalf("%d records stored, %d captured", len(recs), st.Captured)
	}
	reported, _ = s2.MetricsRow()["capture_drops"].(map[string]uint64)
	if !maps.Equal(reported, s2.Drops()) {
		t.Fatalf("P-246 %v, drops %v", reported, s2.Drops())
	}
}
