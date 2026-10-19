package perf

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/analytics"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
)

// Observation data of the reference dataset (FR-11.6, FR-11.8): synthetic
// observation records with the columns of the default Observation Policy,
// spread over RefDays days.
const (
	// IngestRate is the FR-11.6 replay rate in records per second.
	IngestRate = 2000
	// IngestDuration is the FR-11.6 replay duration.
	IngestDuration = 10 * time.Minute
)

// obsServers are the servers of the synthetic records with their tools and
// a relative call weight; the reference server's tools come first.
var obsServers = []struct {
	server, revision string
	tools            []string
	weight           int
}{
	{"ref", "smcp-ref-filesystem@ref", RefTools, 6},
	{"filesystem", "server-filesystem@2026.9.1", []string{"read_text_file", "list_directory", "search_files", "write_file", "edit_file"}, 5},
	{"fetch", "server-fetch@2026.8.0", []string{"fetch"}, 2},
	{"git", "server-git@2026.9.0", []string{"git_status", "git_diff", "git_log", "git_show"}, 3},
	{"thinking", "server-sequential-thinking@2026.7.2", []string{"sequentialthinking"}, 1},
}

// ObservationGen produces synthetic observation records: eight principals
// with sessions of 500 calls, five servers with weighted tools, latencies
// and sizes from log-normal distributions, one call in ten denied, and
// occasional filter hits, redactions and elevated anomaly bands. Each value
// has the type and unit of its catalog parameter. The sequence is fixed
// by the seed.
type ObservationGen struct {
	rng      *rand.Rand
	start    time.Time
	step     time.Duration
	n        int
	prevTool [RefCallers]string
	weights  int
	score    obsstore.Row
}

// NewObservationGen returns a generator of total records whose times are
// spread evenly over days days ending at end.
func NewObservationGen(seed uint64, total, days int, end time.Time) *ObservationGen {
	span := time.Duration(days) * 24 * time.Hour
	g := &ObservationGen{rng: rand.New(rand.NewPCG(seed, 11)), start: end.Add(-span), step: span / time.Duration(max(total, 1))} // #nosec G404 -- synthetic workload
	for _, s := range obsServers {
		g.weights += s.weight
	}
	return g
}

func (g *ObservationGen) logNormal(median, sigma float64) float64 {
	return median * math.Exp(g.rng.NormFloat64()*sigma)
}

// Next returns the next record as a row of the store's records table.
func (g *ObservationGen) Next() obsstore.Row {
	i := g.n
	g.n++
	p := i % RefCallers
	pick := g.rng.IntN(g.weights)
	si := 0
	for pick >= obsServers[si].weight {
		pick -= obsServers[si].weight
		si++
	}
	srv := obsServers[si]
	tool := srv.tools[g.rng.IntN(len(srv.tools))]
	prev := g.prevTool[p]
	g.prevTool[p] = tool
	denied := i%10 == 9
	reqBytes := int64(g.logNormal(420, 0.6)) + 80
	respBytes := int64(0)
	execMs, respFilters := 0.0, 0.0
	outcome, release, delivery, conformance := "deny", "not_dispatched", "none", "not_applicable"
	if !denied {
		respBytes = int64(g.logNormal(6000, 1.4)) + 40
		execMs = g.logNormal(18, 0.9)
		respFilters = 0.002*float64(respBytes)/64 + g.logNormal(0.4, 0.3)
		outcome, release, delivery, conformance = "permit", "released", "confirmed", "conformant"
	}
	reqFilters := g.logNormal(0.35, 0.3)
	scoring := g.logNormal(0.04, 0.3)
	capture := g.logNormal(0.05, 0.3)
	overhead := reqFilters + respFilters + scoring + capture + g.logNormal(2.5, 0.4)
	band := "normal"
	switch r := g.rng.Float64(); {
	case r < 0.002:
		band = "abnormal"
	case r < 0.02:
		band = "elevated"
	}
	z := math.Abs(g.rng.NormFloat64())
	filterHits, redactions := map[string]any{}, int64(0)
	if g.rng.IntN(50) == 0 {
		filterHits["secret-patterns"] = 1
		redactions = 1
	}
	row := obsstore.Row{
		"ts":                         g.start.Add(time.Duration(i) * g.step),
		"correlation_id":             fmt.Sprintf("obs-%08d", i),
		"server_id":                  srv.server,
		"policy_revision":            "workload-r1",
		"observation_policy":         "default",
		"catalog_version":            "1",
		"capture":                    "metadata",
		"principal_id":               fmt.Sprintf("workload-%d", p),
		"session_id":                 fmt.Sprintf("session-%d-%d", p, i/(500*RefCallers)),
		"session_template":           "read-only",
		"harness_adapter_version":    "claude-code/2.1",
		"trace_parent":               fmt.Sprintf("00-%032x-%016x-01", i, i),
		"mcp_method":                 "tools/call",
		"server_revision":            srv.revision,
		"tool_name":                  tool,
		"previous_tool":              prev,
		"request_bytes":              reqBytes,
		"argument_count":             int64(1 + g.rng.IntN(4)),
		"argument_max_depth":         int64(1 + g.rng.IntN(3)),
		"argument_string_lengths":    []any{int64(g.logNormal(24, 0.8)) + 1},
		"argument_entropy":           3.6 + g.rng.NormFloat64()*0.4,
		"path_argument_count":        int64(g.rng.IntN(2)),
		"url_argument_count":         int64(boolInt(srv.server == "fetch")),
		"unicode_control_count":      int64(0),
		"injection_detect_score":     map[string]any{"heuristic": math.Round(g.rng.Float64()*0.2*1000) / 1000},
		"calls_in_session":           int64(i/RefCallers%500 + 1),
		"calls_per_minute_session":   int64(1 + g.rng.IntN(12)),
		"calls_per_minute_principal": int64(1 + g.rng.IntN(20)),
		"distinct_tools_in_session":  int64(1 + g.rng.IntN(8)),
		"repeated_identical_calls":   int64(g.rng.IntN(3)),
		"inter_call_interval":        int64(g.logNormal(4000, 1.2)),
		"transition_surprise":        g.logNormal(1.1, 0.5),
		"decision_outcome":           outcome,
		"decisive_rule_ids":          []any{"workload-r1/read-only/ro-0000"},
		"obligations_applied":        []any{},
		"approval_state":             map[string]any{"required": false},
		"anomaly_band":               band,
		"max_abs_z":                  map[string]any{"value": math.Round(z*1000) / 1000},
		"baseline_snapshot_id":       "snap-workload-1",
		"server_execution_time":      execMs,
		"response_bytes":             respBytes,
		"response_entropy":           4.2 + g.rng.NormFloat64()*0.5,
		"response_token_estimate":    respBytes / 4,
		"content_parts_by_type":      map[string]any{"text": 1},
		"output_schema_conformance":  conformance,
		"is_error":                   map[string]any{"value": false},
		"structured_field_count":     int64(g.rng.IntN(6)),
		"embedded_url_count":         int64(g.rng.IntN(3)),
		"filter_hits":                filterHits,
		"redaction_count":            redactions,
		"secret_fingerprint_matches": int64(0),
		"injection_marker_score":     map[string]any{"heuristic": math.Round(g.rng.Float64()*0.1*1000) / 1000},
		"pii_hits":                   map[string]any{},
		"release_outcome":            release,
		"delivery_confirmation":      delivery,
		"t_request_filters":          map[string]any{"total": reqFilters},
		"t_response_filters":         map[string]any{"total": respFilters},
		"t_approval_wait":            0.0,
		"t_scoring":                  scoring,
		"t_capture":                  capture,
		"gateway_overhead":           overhead,
		"end_to_end_latency":         overhead + execMs,
	}
	if denied {
		row["reason_code"] = "NO_PERMIT"
	}
	g.score = nil
	if band != "normal" {
		g.score = obsstore.Row{"ts": row["ts"], "correlation_id": row["correlation_id"], "snapshot_id": "snap-workload-1",
			"context": "principal=" + row["principal_id"].(string) + ",tool=" + tool, "combined": 2 + z, "contributing_feature": "response_bytes",
			"band": band, "features": `{"response_bytes":` + fmt.Sprintf("%.3f", 2+z) + `}`, "actions": "[]", "mode": "sync",
			"principal_id": row["principal_id"], "session_id": row["session_id"], "tool_name": tool}
	}
	return row
}

// Score returns the scoring row (scores table) of the record Next last
// returned when its anomaly band is above normal, otherwise nil: the
// scorer stores a row per scored call, and the replay keeps the rows that
// the anomaly view lists.
func (g *ObservationGen) Score() obsstore.Row { return g.score }

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// IngestResult is the outcome of an ingest replay.
type IngestResult struct {
	Offered  int64                 `json:"offered"`  // observation records offered
	Scores   int64                 `json:"scores"`   // scoring rows offered besides
	Elapsed  time.Duration         `json:"elapsed"`  // from the first offer to the last
	Rate     float64               `json:"rate"`     // observation records per second
	Stats    analytics.IngestStats `json:"stats"`    // after the writer drained
	Backend  string                `json:"backend"`  // store backend
	Interval time.Duration         `json:"interval"` // pacing step
	Days     int                   `json:"days"`     // span of the records' times
}

// Backpressure reports whether the replay saw the backpressure signal: an
// offer at 80% or more of the writer's queue, a dropped record or a failed
// store write.
func (r IngestResult) Backpressure() bool {
	var drops uint64
	for _, n := range r.Stats.Drops {
		drops += n
	}
	return r.Stats.PressureOffers > 0 || drops > 0 || r.Stats.LastError != "" || r.Stats.Written != r.Offered+r.Scores
}

// ReplayIngest opens the Observation Store of the configuration cfgPath
// through the analytics service, with its production writer (batches,
// queue and store backend as configured), and offers rate synthetic
// records per second for d, paced every 10 ms. The records' times are
// spread over days days ending at end, so that the replay also writes the
// 30 days of observation data that the FR-11.8 analytics queries read.
// smcpd must not be running on the same state directory.
func ReplayIngest(ctx context.Context, cfgPath string, rate int, d time.Duration, days int, end time.Time) (IngestResult, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return IngestResult{}, err
	}
	return replayIngest(ctx, cfg, rate, d, days, end)
}

func replayIngest(ctx context.Context, cfg *config.Config, rate int, d time.Duration, days int, end time.Time) (IngestResult, error) {
	svc, err := analytics.New(analytics.Options{Config: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		return IngestResult{}, err
	}
	if svc.Disabled() || svc.Store == nil {
		svc.Close()
		return IngestResult{}, fmt.Errorf("perf: observation store unavailable")
	}
	res := IngestResult{Backend: svc.Store.Backend(), Days: days}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	svc.Start(sctx, nil, nil, nil)
	const tick = 10 * time.Millisecond
	total := int64(float64(rate) * d.Seconds())
	gen := NewObservationGen(3, int(total), days, end)
	t := time.NewTicker(tick)
	defer t.Stop()
	start := time.Now()
	for res.Offered < total {
		// Offer what is due by now: a late tick catches up, so the
		// average rate is kept even when the ticker slips.
		due := min(total, int64(time.Since(start).Seconds()*float64(rate))+1)
		for ; res.Offered < due; res.Offered++ {
			svc.Offer("records", gen.Next())
			if sc := gen.Score(); sc != nil {
				svc.Offer("scores", sc)
				res.Scores++
			}
		}
		select {
		case <-ctx.Done():
			svc.Close()
			return res, ctx.Err()
		case <-t.C:
		}
	}
	res.Elapsed = time.Since(start)
	res.Rate = float64(res.Offered) / res.Elapsed.Seconds()
	res.Interval = tick
	svc.Close() // drains the writer
	res.Stats = svc.IngestStats()
	return res, nil
}

// ingestMeasurement is FR-11.6 for a replay of want records per second for
// wantFor: the rate achieved, passing when the whole duration was replayed
// at the rate without the backpressure signal. It is complete only for the
// full 10 minutes at 2,000 records per second into the DuckDB store, the
// Observation Store of the SRS stack (§3.1); the JSON Lines fallback of
// builds without cgo is not what FR-11.6 names.
func ingestMeasurement(r IngestResult, want int, wantFor time.Duration) Measurement {
	m := Measurement{Requirement: "FR-11.6", Name: "Observation ingest", Metric: "sustained rate", Unit: "records/s", Value: r.Rate, Budget: float64(want),
		Samples: int(r.Offered), Complete: wantFor >= IngestDuration && want >= IngestRate && r.Backend == "duckdb"}
	m.Pass = !r.Backpressure() && r.Rate >= float64(want)*0.995 && r.Elapsed >= wantFor-time.Second
	var drops uint64
	for _, n := range r.Stats.Drops {
		drops += n
	}
	m.Method = fmt.Sprintf("%d synthetic observation records (default Observation Policy columns, times over %d days) offered through the analytics store writer at %d/s for %s (paced every %s), with %d scoring rows of the records above the normal band, %s backend; %d rows written, %d offers at 80%% queue occupancy or more, %d dropped",
		r.Offered, r.Days, want, r.Elapsed.Round(time.Second), r.Interval, r.Scores, r.Backend, r.Stats.Written, r.Stats.PressureOffers, drops)
	if r.Stats.LastError != "" {
		m.Note = "store write failed: " + r.Stats.LastError
	}
	if !m.Complete {
		m.Note = fmt.Sprintf("replay shorter than %s, slower than %d/s or not into the DuckDB store", IngestDuration, IngestRate)
	}
	return m
}
