package observe

import (
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// TestCostAggregation: the collector aggregates span time per stage and
// policy object with the Observation Policy in force, ranks the largest
// total first, and passes every batch to the sink.
func TestCostAggregation(t *testing.T) {
	var mu sync.Mutex
	var sunk []string
	c := New(Options{PolicyID: "obs-1", SpanSink: func(policy string, sp []pipeline.StageSpan) {
		mu.Lock()
		sunk = append(sunk, policy+"/"+sp[0].CorrelationID)
		mu.Unlock()
	}})
	go c.Run()
	t0 := time.Now()
	span := func(corr, stage, filter string, d time.Duration) pipeline.StageSpan {
		return pipeline.StageSpan{Stage: stage, CorrelationID: corr, Start: t0, End: t0.Add(d), CPU: d / 2, PolicyRevision: "r1", Rule: "r1/ro/a", Filter: filter}
	}
	for i, corr := range []string{"c1", "c2"} {
		c.OfferSpans([]pipeline.StageSpan{
			span(corr, pipeline.SpanDecision, "", time.Millisecond),
			span(corr, pipeline.SpanFilter, "fast", time.Duration(i+1)*time.Millisecond),
			span(corr, pipeline.SpanFilter, "slow", 30*time.Millisecond),
		})
	}
	c.OfferSpans(nil)
	c.Close()
	rows := c.Cost(true)
	if len(rows) != 2 || rows[0].Filter != "slow" || rows[0].Spans != 2 || rows[0].TotalMs != 60 || rows[0].CPUMs != 30 || rows[0].MeanMs != 30 ||
		rows[0].ObservationPolicy != "obs-1" || rows[0].Rule != "r1/ro/a" || rows[1].Filter != "fast" || rows[1].TotalMs != 3 || rows[1].MaxMs != 2 {
		t.Fatalf("filter cost %+v", rows)
	}
	if all := c.Cost(false); len(all) != 3 || all[0].Filter != "slow" || all[2].Stage != pipeline.SpanDecision {
		t.Fatalf("cost %+v", all)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sunk) != 2 || sunk[0] != "obs-1/c1" {
		t.Fatalf("sink %v", sunk)
	}
}
