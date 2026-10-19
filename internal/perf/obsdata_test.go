package perf

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/analytics"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestObservationGen: the synthetic records carry every parameter of the
// default Observation Policy with its catalog type, spread evenly over 30
// days; one call in ten is denied; scoring rows exist only for records
// above the normal band; the sequence is fixed by the seed.
func TestObservationGen(t *testing.T) {
	end := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	const n = 20000
	g := NewObservationGen(3, n, RefDays, end)
	cat := observe.DefaultCatalog()
	var rows, scores []obsstore.Row
	denied, tools := 0, map[string]bool{}
	for range n {
		r := g.Next()
		rows = append(rows, r)
		if r["decision_outcome"] == "deny" {
			denied++
		}
		tools[r["server_id"].(string)+"/"+r["tool_name"].(string)] = true
		if sc := g.Score(); sc != nil {
			if r["anomaly_band"] == "normal" || sc["correlation_id"] != r["correlation_id"] {
				t.Fatalf("score %v for record %v", sc, r)
			}
			scores = append(scores, sc)
		} else if r["anomaly_band"] != "normal" {
			t.Fatalf("no score for band %v", r["anomaly_band"])
		}
	}
	for _, p := range cat.DefaultParameters() {
		v, ok := rows[0][p]
		if !ok {
			t.Errorf("default parameter %s missing", p)
			continue
		}
		param, _ := cat.Lookup(p)
		switch param.DataType {
		case "integer":
			_, ok = v.(int64)
		case "number":
			_, ok = v.(float64)
		case "string":
			_, ok = v.(string)
		case "array":
			_, ok = v.([]any)
		case "object":
			_, ok = v.(map[string]any)
		}
		if !ok {
			t.Errorf("%s is %T, catalog type %s", p, v, param.DataType)
		}
	}
	first, last := rows[0]["ts"].(time.Time), rows[n-1]["ts"].(time.Time)
	if span := last.Sub(first); span < 29*24*time.Hour || last.After(end) {
		t.Fatalf("records span %s, last at %s", span, last)
	}
	if denied != n/10 || len(tools) < 10 || len(scores) == 0 || len(scores) > n/20 {
		t.Fatalf("%d denied, %d tools, %d scores", denied, len(tools), len(scores))
	}
	again := NewObservationGen(3, n, RefDays, end).Next()
	if !reflect.DeepEqual(again, rows[0]) {
		t.Fatal("generator is not deterministic")
	}
	// Every row is accepted by the store's schema.
	s, err := obsstore.Open(obsstore.Options{Dir: t.TempDir(), Backend: "jsonl", Tables: analytics.Tables(cat)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Append("records", rows[:2000]); err != nil {
		t.Fatal(err)
	}
	if err := s.Append("scores", scores); err != nil {
		t.Fatal(err)
	}
}

func replayConfig(t *testing.T, store string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte("[state]\ndir = \"" + filepath.ToSlash(filepath.Join(t.TempDir(), "state")) + "\"\n[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g\"\n[policy]\nfile = \"p.json\"\n[approvals]\nnotify = \"off\"\n[observation]\nstore = \"" + store + "\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestReplayIngest: the replay offers records through the analytics store
// writer at the requested rate; at a modest rate for three seconds nothing
// raises the backpressure signal, every offered row is in the store, and
// the analytics aggregates over the 30 days find them. The rate is low so
// that the race detector and a busy CI host do not make this test about
// throughput: the CI job perf runs the same replay at 2,000 records per
// second for the full 10 minutes (FR-11.6) and queries the result
// (FR-11.8).
func TestReplayIngest(t *testing.T) {
	reqtest.Partial(t, "FR-11.6", "FR-11.8")
	if testing.Short() {
		t.Skip("ingest replay")
	}
	const rate = 300
	backends := []string{"jsonl"}
	if obsstore.DuckDBAvailable() {
		backends = append(backends, "duckdb")
	}
	for _, b := range backends {
		t.Run(b, func(t *testing.T) {
			cfg := replayConfig(t, b)
			// The store keeps times to the microsecond; a whole-second end
			// keeps the first record (at end minus the 30 days) inside From.
			end := time.Now().UTC().Truncate(time.Second)
			res, err := replayIngest(context.Background(), cfg, rate, 3*time.Second, RefDays, end)
			if err != nil {
				t.Fatal(err)
			}
			if res.Backend != b || res.Offered != 3*rate || res.Backpressure() || res.Stats.Written < res.Offered+res.Scores {
				t.Fatalf("replay %+v", res)
			}
			if res.Rate < rate*0.99 || res.Elapsed < 2900*time.Millisecond {
				t.Fatalf("rate %.0f/s over %s", res.Rate, res.Elapsed)
			}
			m := ingestMeasurement(res, rate, 3*time.Second)
			if !m.Pass || m.Complete || m.Requirement != "FR-11.6" || !strings.Contains(m.Method, "0 offers at 80% queue occupancy") {
				t.Fatalf("measurement %+v", m)
			}
			s, err := obsstore.Open(obsstore.Options{Dir: filepath.Join(cfg.State.Dir, "observation", "store"), Backend: b, Tables: analytics.Tables(observe.DefaultCatalog())})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			agg, err := s.Aggregate(obsstore.AggQuery{Feature: "end_to_end_latency", GroupBy: []string{"tool_name"}, Bucket: 24 * time.Hour,
				Quantiles: []float64{0.95}, Filter: obsstore.Filter{From: end.Add(-RefDays * 24 * time.Hour), To: end.Add(time.Minute)}})
			if err != nil {
				t.Fatal(err)
			}
			var total int64
			days := map[time.Time]bool{}
			for _, r := range agg {
				total += r.Count
				days[*r.Bucket] = true
			}
			if total != res.Offered || len(days) < RefDays {
				t.Fatalf("aggregate counts %d records over %d days", total, len(days))
			}
		})
	}
}

// TestIngestMeasurement: FR-11.6 passes only without the backpressure
// signal and at the full rate for the whole duration, and is complete
// only for 2,000 records per second over 10 minutes.
func TestIngestMeasurement(t *testing.T) {
	ok := IngestResult{Offered: 1200000, Scores: 100, Elapsed: IngestDuration, Rate: 2000, Days: 30, Backend: "duckdb", Interval: 10 * time.Millisecond,
		Stats: analytics.IngestStats{Written: 1200100, Drops: map[string]uint64{}}}
	if m := ingestMeasurement(ok, IngestRate, IngestDuration); !m.Pass || !m.Complete || m.Value != 2000 || m.Budget != 2000 || m.Samples != 1200000 {
		t.Fatalf("clean replay: %+v", m)
	}
	for name, mod := range map[string]func(*IngestResult){
		"pressure":     func(r *IngestResult) { r.Stats.PressureOffers = 1 },
		"drop":         func(r *IngestResult) { r.Stats.Drops = map[string]uint64{observe.DropStoreQueue: 1} },
		"write error":  func(r *IngestResult) { r.Stats.LastError = "disk full" },
		"missing rows": func(r *IngestResult) { r.Stats.Written-- },
		"slow":         func(r *IngestResult) { r.Rate = 1900 },
		"short":        func(r *IngestResult) { r.Elapsed = 5 * time.Minute },
	} {
		r := ok
		r.Stats.Drops = map[string]uint64{}
		mod(&r)
		if m := ingestMeasurement(r, IngestRate, IngestDuration); m.Pass {
			t.Errorf("%s: passes", name)
		}
	}
	// The service writes its own meta-metrics rows (one per interval)
	// beside the replayed ones; they do not count as a fault.
	withMetrics := ok
	withMetrics.Stats.Written += 60
	if m := ingestMeasurement(withMetrics, IngestRate, IngestDuration); !m.Pass {
		t.Fatalf("meta-metrics rows fail the replay: %+v", m)
	}
	if m := ingestMeasurement(ok, IngestRate, time.Minute); m.Complete {
		t.Fatal("a one-minute replay is complete")
	}
}

// TestQuerySets: the FR-11.8 standard query set holds the console's audit
// queries and analytics queries over the 30 days, each bounded by a
// limit, a time range or groups.
func TestQuerySets(t *testing.T) {
	now := time.Now()
	if len(auditQuerySet(now)) != 6 {
		t.Fatalf("audit set %v", auditQuerySet(now))
	}
	set := analyticsQuerySet(now)
	if len(set) < 8 {
		t.Fatalf("analytics set %v", set)
	}
	for _, q := range set {
		if !strings.HasPrefix(q, "/api/v1/observations") && !strings.HasPrefix(q, "/api/v1/anomalies") {
			t.Errorf("not an analytics route: %s", q)
		}
		if !strings.Contains(q, "from=") || !strings.Contains(q, "to=") {
			t.Errorf("unbounded time range: %s", q)
		}
	}
	if !hasRows([]byte(`{"rows":[{}]}`)) || !hasRows([]byte(`{"events":[{}]}`)) || hasRows([]byte(`{"rows":[]}`)) || hasRows([]byte(`x`)) {
		t.Fatal("hasRows")
	}
}
