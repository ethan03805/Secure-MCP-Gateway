package pipeline

import (
	"runtime"
	"time"
)

// Stages of the call pipeline that emit timing spans (FR-10.2), in FR-4.3
// order. Request and response scoring run inside the inspection stages as
// the observation probes, so their time is part of those stages and of the
// probes' filter spans.
const (
	SpanAuthenticate         = "authenticate"
	SpanSessionCheck         = "session_check"
	SpanDecision             = "decision"
	SpanRequestInspection    = "request_inspection"
	SpanApproval             = "approval"
	SpanLaunchAuthorization  = "launch_authorization"
	SpanDispatch             = "dispatch"
	SpanResponseInspection   = "response_inspection"
	SpanReleaseAuthorization = "release_authorization"
	// SpanFilter is the span of one filter run inside an inspection stage;
	// its Filter field names the filter.
	SpanFilter = "filter"
)

// StageSpan is one timing span of a tool call (FR-10.2): the stage, the
// monotonic start and end (time.Now readings), the CPU time spent by the
// Gateway in the stage, the call's correlation ID and the policy objects
// that caused the work: the policy revision and decisive rule revision of
// the call's decision (empty before the decision) and, for a filter span,
// the filter ID.
type StageSpan struct {
	Stage          string
	CorrelationID  string
	Start, End     time.Time
	CPU            time.Duration
	CPUMeasured    bool // false where the platform has no per-thread CPU clock
	PolicyRevision string
	Rule           string
	Filter         string
}

// Duration is End minus Start on the monotonic clock.
func (s StageSpan) Duration() time.Duration { return s.End.Sub(s.Start) }

// SpanSink receives the spans of one call when the call ends. It runs on
// the call's goroutine and must not block (E-29 queues them).
type SpanSink func([]StageSpan)

// cpuMeter measures the CPU time of the calling goroutine by locking it to
// its OS thread and reading the thread's CPU clock. Lock before the work,
// Read at stage boundaries, Unlock when done.
type cpuMeter struct {
	ok bool
}

func lockCPU() cpuMeter {
	runtime.LockOSThread()
	_, ok := threadCPU()
	return cpuMeter{ok: ok}
}

func (m cpuMeter) read() time.Duration {
	if !m.ok {
		return 0
	}
	d, _ := threadCPU()
	return d
}

func (m cpuMeter) unlock() { runtime.UnlockOSThread() }

// SpanTimer records the spans of one call on its goroutine. NewSpanTimer
// locks the goroutine to its OS thread so that thread CPU time is the
// call's own; Finish unlocks it and returns the spans.
type SpanTimer struct {
	m     cpuMeter
	corr  string
	spans []StageSpan
	// PolicyRevision and Rule are set once the call is decided and are
	// copied into every later span.
	PolicyRevision, Rule string
}

// NewSpanTimer starts recording the spans of the call corr.
func NewSpanTimer(corr string) *SpanTimer { return &SpanTimer{m: lockCPU(), corr: corr} }

// Start begins a stage; the returned function ends it.
func (t *SpanTimer) Start(stage string) func() {
	start, cpu0 := time.Now(), t.m.read()
	return func() {
		t.spans = append(t.spans, StageSpan{Stage: stage, CorrelationID: t.corr, Start: start, End: time.Now(), CPU: t.m.read() - cpu0,
			CPUMeasured: t.m.ok, PolicyRevision: t.PolicyRevision, Rule: t.Rule})
	}
}

// Add records a span measured elsewhere (authentication before the call
// handler, filter runs on their own goroutines).
func (t *SpanTimer) Add(s StageSpan) {
	s.CorrelationID = t.corr
	if s.PolicyRevision == "" {
		s.PolicyRevision, s.Rule = t.PolicyRevision, t.Rule
	}
	t.spans = append(t.spans, s)
}

// AddFilterRuns records one span per filter run, and adds the filters' CPU
// time (spent on their own goroutines) to the stage span that contains
// them, which must be the last span recorded.
func (t *SpanTimer) AddFilterRuns(runs []FilterRun) {
	var cpu time.Duration
	for _, r := range runs {
		cpu += r.CPU
		t.Add(StageSpan{Stage: SpanFilter, Start: r.Start, End: r.Start.Add(r.Duration), CPU: r.CPU, CPUMeasured: t.m.ok, Filter: r.Filter})
	}
	for i := len(t.spans) - 1; i >= 0; i-- {
		if t.spans[i].Stage != SpanFilter {
			t.spans[i].CPU += cpu
			break
		}
	}
}

// Finish unlocks the goroutine and returns the spans in order of their
// start.
func (t *SpanTimer) Finish() []StageSpan {
	t.m.unlock()
	return t.spans
}

// MeasureCPU runs fn locked to its OS thread and returns the thread CPU
// time it used (0, false where the platform has no per-thread clock).
func MeasureCPU(fn func()) (time.Duration, bool) {
	m := lockCPU()
	defer m.unlock()
	c0 := m.read()
	fn()
	return m.read() - c0, m.ok
}
