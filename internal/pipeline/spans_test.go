package pipeline

import (
	"runtime"
	"testing"
	"time"
)

func burn(d time.Duration) {
	for t0 := time.Now(); time.Since(t0) < d; {
	}
}

// TestSpanTimerMeasuresStagesAndCPU: stage spans carry monotonic times,
// thread CPU time and the policy objects set after the decision; filter
// runs become filter spans whose CPU is added to their stage.
func TestSpanTimerMeasuresStagesAndCPU(t *testing.T) {
	cpuClock := runtime.GOOS == "linux" || runtime.GOOS == "darwin"
	st := NewSpanTimer("corr-1")
	end := st.Start(SpanDecision)
	burn(3 * time.Millisecond)
	end()
	st.PolicyRevision, st.Rule = "r1", "r1/ro/a"
	end = st.Start(SpanRequestInspection)
	time.Sleep(2 * time.Millisecond)
	end()
	st.AddFilterRuns([]FilterRun{{Stage: StageRequest, Filter: "f", Start: time.Now(), Duration: time.Millisecond, CPU: 4 * time.Millisecond}})
	spans := st.Finish()
	if len(spans) != 3 {
		t.Fatalf("%d spans", len(spans))
	}
	d, insp, f := spans[0], spans[1], spans[2]
	if d.Stage != SpanDecision || d.PolicyRevision != "" || d.CorrelationID != "corr-1" || d.Duration() < 3*time.Millisecond {
		t.Fatalf("decision span %+v", d)
	}
	if cpuClock && (d.CPU < time.Millisecond || !d.CPUMeasured) {
		t.Fatalf("decision span CPU %v measured %v", d.CPU, d.CPUMeasured)
	}
	if insp.PolicyRevision != "r1" || insp.Rule != "r1/ro/a" || f.Filter != "f" || f.Stage != SpanFilter || f.PolicyRevision != "r1" {
		t.Fatalf("spans %+v %+v", insp, f)
	}
	if insp.CPU < 4*time.Millisecond {
		t.Fatalf("inspection CPU %v lacks the filter's 4ms", insp.CPU)
	}
	if cpu, ok := MeasureCPU(func() { burn(2 * time.Millisecond) }); ok != cpuClock || (ok && cpu < time.Millisecond) {
		t.Fatalf("MeasureCPU %v %v", cpu, ok)
	}
}
