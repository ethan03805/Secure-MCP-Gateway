package perf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RunOptions configure a measurement run.
type RunOptions struct {
	BinDir    string        // smcpd, smcpctl and smcp-refserver
	Work      string        // empty directory for the instances
	Calls     int           // tool calls per load measurement (default 2000)
	Callers   int           // concurrent callers (default RefCallers)
	Decisions int           // decisions for FR-11.2 (default 100,000)
	Queries   int           // repetitions of the console query set (default 100)
	Idle      time.Duration // wait before the idle memory sample (default 10 minutes)
	Commit    string
	Log       io.Writer
}

func (o *RunOptions) defaults() {
	if o.Calls <= 0 {
		o.Calls = 2000
	}
	if o.Callers <= 0 {
		o.Callers = RefCallers
	}
	if o.Decisions <= 0 {
		o.Decisions = 100000
	}
	if o.Queries <= 0 {
		o.Queries = 100
	}
	if o.Idle <= 0 {
		o.Idle = 10 * time.Minute
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
}

// Run measures FR-11.2, FR-11.4, FR-11.5, FR-11.8 and FR-11.9 with the
// reference workload against real smcpd instances.
func Run(ctx context.Context, o RunOptions) (*Results, error) {
	o.defaults()
	say := func(f string, a ...any) { fmt.Fprintf(o.Log, "smcp-workload: "+f+"\n", a...) }
	doc, err := ReferencePolicy("workload-r1", RefRules, RefCandidates)
	if err != nil {
		return nil, err
	}
	res := &Results{Schema: 1, Commit: o.Commit, GeneratedAt: time.Now().UTC().Format(time.RFC3339), Host: CurrentHost(),
		Dataset: Dataset{Rules: RefRules, RegistryNodes: RefRegistryNodes, Candidates: RefCandidates, Events: RefEvents, Days: RefDays, Callers: o.Callers}}

	// FR-11.9: an idle instance, started first and sampled last.
	idle, err := newInstance(o.BinDir, filepath.Join(o.Work, "idle"), "", doc)
	if err != nil {
		return nil, err
	}
	if err := idle.start(); err != nil {
		return nil, err
	}
	defer idle.stop()
	idleSince := time.Now()
	say("idle instance started; memory is sampled after %s", o.Idle)

	// FR-11.2: decisions against the reference policy.
	say("FR-11.2: %d decisions, %d callers, %d candidate rules", o.Decisions, o.Callers, RefCandidates)
	lat, err := MeasureDecisions(doc, o.Decisions, o.Callers)
	if err != nil {
		return nil, err
	}
	p95 := Quantile(lat, 0.95)
	res.Measurements = append(res.Measurements, Measurement{Requirement: "FR-11.2", Name: "Decision latency", Metric: "p95", Unit: "ms",
		Value: p95, Budget: BudgetDecisionMs, Ceiling: CeilingDecisionMs, Samples: len(lat), Pass: p95 <= BudgetDecisionMs,
		Method: fmt.Sprintf("policy.Decider.Decide on the compiled reference policy (%d rules, %d candidates per decision), %d concurrent callers, latency as the caller sees it", RefRules, RefCandidates, o.Callers)})

	// FR-11.4 and FR-11.5: load against three instances.
	load := func(name, extra string) ([]float64, error) {
		in, err := newInstance(o.BinDir, filepath.Join(o.Work, name), extra, doc)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(in.sandbox, "64k.txt"), []byte(strings.Repeat("0123456789abcdef", 64<<10/16)), 0o644); err != nil {
			return nil, err
		}
		if err := in.start(); err != nil {
			return nil, err
		}
		defer in.stop()
		say("%s: %d calls of read_file (64 KiB result), %d callers", name, o.Calls, o.Callers)
		if err := drive(ctx, in, o.Calls, o.Callers); err != nil {
			return nil, err
		}
		in.stop()
		return in.overheads()
	}
	syncScoring, err := load("sync-scoring", "\n[observation]\nscoring = \"sync\"\n")
	if err != nil {
		return nil, err
	}
	p95 = Quantile(syncScoring, 0.95)
	res.Measurements = append(res.Measurements, Measurement{Requirement: "FR-11.5", Name: "Gateway-added overhead (P-213)", Metric: "p95", Unit: "ms",
		Value: p95, Budget: BudgetOverheadMs, Ceiling: CeilingOverheadMs, Samples: len(syncScoring), Pass: p95 <= BudgetOverheadMs,
		Method: fmt.Sprintf("real smcpd with synchronous scoring, %d concurrent callers reading a 64 KiB file through the reference server; P-213 from journal timestamps (requested to dispatched plus completed to delivered)", o.Callers)})
	captureOn, err := load("capture-on", "")
	if err != nil {
		return nil, err
	}
	captureOff, err := load("capture-off", "\n[observation]\nenabled = false\n")
	if err != nil {
		return nil, err
	}
	diff := Quantile(captureOn, 0.95) - Quantile(captureOff, 0.95)
	res.Measurements = append(res.Measurements, Measurement{Requirement: "FR-11.4", Name: "Observation capture overhead", Metric: "p95 difference", Unit: "ms",
		Value: diff, Budget: BudgetCaptureMs, Samples: min(len(captureOn), len(captureOff)), Pass: diff <= BudgetCaptureMs,
		Method: fmt.Sprintf("p95 P-213 with observation enabled (%.3f ms) minus disabled (%.3f ms), same workload on two fresh instances", Quantile(captureOn, 0.95), Quantile(captureOff, 0.95))})

	// FR-11.8: the console's audit queries over 30 days of reference data.
	qi, err := newInstance(o.BinDir, filepath.Join(o.Work, "queries"), "", doc)
	if err != nil {
		return nil, err
	}
	say("FR-11.8: writing %d journal events over %d days", RefEvents, RefDays)
	n, err := WriteJournal(qi.state, RefEvents, RefDays, time.Now())
	if err != nil {
		return nil, err
	}
	if err := qi.start(); err != nil {
		return nil, err
	}
	qlat, err := queries(qi, o.Queries)
	qi.stop()
	if err != nil {
		return nil, err
	}
	p95 = Quantile(qlat, 0.95)
	res.Measurements = append(res.Measurements, Measurement{Requirement: "FR-11.8", Name: "Console query latency", Metric: "p95", Unit: "ms",
		Value: p95, Budget: BudgetQueryMs, Samples: len(qlat), Pass: p95 <= BudgetQueryMs,
		Method: fmt.Sprintf("the console's audit queries (latest page, by class, by reason, by correlation, by time window, text search) over a journal of %d events spanning %d days, %d repetitions", n, RefDays, o.Queries),
		Note:   "audit queries only; analytics queries over 30 days of observation data are not in the reference dataset yet"})

	// FR-11.9: wait out the idle period, then sample.
	if wait := o.Idle - time.Since(idleSince); wait > 0 {
		say("FR-11.9: waiting %s for the idle sample", wait.Round(time.Second))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	rss, err := idle.rssBytes()
	if err != nil {
		return nil, err
	}
	res.Measurements = append(res.Measurements, Measurement{Requirement: "FR-11.9", Name: "Idle resident memory", Metric: "RSS", Unit: "MiB",
		Value: float64(rss) / (1 << 20), Budget: float64(BudgetIdleRSSBytes) / (1 << 20), Samples: 1, Pass: rss <= BudgetIdleRSSBytes,
		Method: fmt.Sprintf("resident set size of smcpd %s after start with no traffic, Data Server off (no Neo4j); server instances excluded", time.Since(idleSince).Round(time.Second))})
	return res, nil
}

// drive makes calls tool calls with callers concurrent sessions.
func drive(ctx context.Context, in *instance, calls, callers int) error {
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	sessions := make([]*mcp.ClientSession, callers)
	for i := range sessions {
		cs, err := in.session(ctx)
		if err != nil {
			return err
		}
		defer cs.Close()
		sessions[i] = cs
	}
	for i, cs := range sessions {
		n := calls / callers
		if i < calls%callers {
			n++
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range n {
				cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
				r, err := cs.CallTool(cctx, &mcp.CallToolParams{Name: "ref_read_file", Arguments: map[string]any{"path": "64k.txt"}})
				cancel()
				if err != nil {
					errs <- fmt.Errorf("read_file: %w", err)
					return
				}
				if r.IsError {
					errs <- errors.New("read_file returned a tool error")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	return <-errs
}

// queries runs the console's audit query set reps times and returns each
// request's latency in milliseconds.
func queries(in *instance, reps int) ([]float64, error) {
	hc, err := in.httpClient()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	window := url.Values{"since": {now.Add(-15 * 24 * time.Hour).Format(time.RFC3339)}, "until": {now.Add(-14 * 24 * time.Hour).Format(time.RFC3339)}, "limit": {"100"}}
	set := []string{
		"/api/v1/audit/events?limit=100",
		"/api/v1/audit/events?class=decision&limit=100",
		"/api/v1/audit/events?reason_code=NO_PERMIT&limit=100",
		"/api/v1/audit/events?correlation_id=corr-0012345",
		"/api/v1/audit/events?" + window.Encode(),
		"/api/v1/audit/events?q=read_file&limit=50",
	}
	var out []float64
	for range reps {
		for _, p := range set {
			code, d, err := in.api(hc, p)
			if err != nil {
				return nil, err
			}
			if code != 200 {
				return nil, fmt.Errorf("GET %s: %d", p, code)
			}
			out = append(out, float64(d.Nanoseconds())/1e6)
		}
	}
	return out, nil
}
