package pipeline

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type funcReq struct {
	id string
	fn func(ctx context.Context) (RequestVerdict, error)
}

func (f funcReq) ID() string      { return f.id }
func (f funcReq) Version() string { return "9.9" }
func (f funcReq) FilterRequest(ctx context.Context, _ *Call, _ json.RawMessage) (RequestVerdict, error) {
	return f.fn(ctx)
}

type funcResp struct {
	id string
	fn func(ctx context.Context) (ResponseVerdict, error)
}

func (f funcResp) ID() string { return f.id }
func (f funcResp) FilterResponse(ctx context.Context, _ *Call, _ *mcp.CallToolResult) (ResponseVerdict, error) {
	return f.fn(ctx)
}

// TestFilterFailureFailsClosed is SR-5.10-1: a required filter that panics
// or exceeds the chain deadline (CP-14, shortened here) blocks the request
// or withholds the result.
func TestFilterFailureFailsClosed(t *testing.T) {
	reqtest.Verifies(t, "SR-5.10-1")
	slow := func(ctx context.Context) (RequestVerdict, error) {
		time.Sleep(2 * time.Second) // ignores ctx on purpose
		return RequestVerdict{Action: Pass}, nil
	}
	f := NewFilters()
	f.SetDeadline(50 * time.Millisecond)
	if err := f.RegisterRequest(funcReq{"slow", slow}, Registration{Order: 1, Mandatory: true}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, _, v := f.RunRequest(context.Background(), schemaCall(), json.RawMessage(`{"text":"x"}`))
	if v == nil || v.ReasonCode != ReasonFilterTimeout || time.Since(start) > time.Second {
		t.Fatalf("%+v after %v", v, time.Since(start))
	}
	g := NewFilters()
	if err := g.RegisterRequest(funcReq{"crash", func(context.Context) (RequestVerdict, error) { panic("boom") }}, Registration{Order: 1, Mandatory: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, v := g.RunRequest(context.Background(), schemaCall(), json.RawMessage(`{"text":"x"}`)); v == nil || v.ReasonCode != ReasonFilterError {
		t.Fatalf("%+v", v)
	}
	h := NewFilters()
	h.SetDeadline(50 * time.Millisecond)
	if err := h.RegisterResponse(funcResp{"slow", func(ctx context.Context) (ResponseVerdict, error) {
		<-ctx.Done()
		time.Sleep(10 * time.Millisecond)
		return ResponseVerdict{Action: Pass}, nil
	}}, Registration{Mandatory: true}); err != nil {
		t.Fatal(err)
	}
	if res, _, v := h.RunResponse(context.Background(), schemaCall(), &mcp.CallToolResult{}); res != nil || v == nil || v.ReasonCode != ReasonFilterTimeout {
		t.Fatalf("%+v %+v", res, v)
	}
	k := NewFilters()
	if err := k.RegisterResponse(funcResp{"crash", func(context.Context) (ResponseVerdict, error) { panic("boom") }}, Registration{Mandatory: true}); err != nil {
		t.Fatal(err)
	}
	if res, _, v := k.RunResponse(context.Background(), schemaCall(), &mcp.CallToolResult{}); res != nil || v == nil || v.ReasonCode != ReasonFilterError {
		t.Fatalf("%+v %+v", res, v)
	}
}

// TestFilterRunRecords covers FR-4.4: every filter run reports its action,
// findings, duration and version through the one filter interface, and
// observers receive the runs of each chain execution.
func TestFilterRunRecords(t *testing.T) {
	reqtest.Verifies(t, "FR-4.4")
	f := NewFilters()
	finding := Finding{Filter: "tagger", RuleSet: "rs", RuleSetVersion: "1", Rule: "r", Tag: true}
	if err := f.RegisterRequest(funcReq{"tagger", func(context.Context) (RequestVerdict, error) {
		time.Sleep(time.Millisecond)
		return RequestVerdict{Action: Pass, Findings: []Finding{finding}}, nil
	}}, Registration{Order: 1, Mandatory: true}); err != nil {
		t.Fatal(err)
	}
	// The same ID may name a request and a response filter; a duplicate in
	// one chain is refused.
	if err := f.RegisterResponse(funcResp{"tagger", func(context.Context) (ResponseVerdict, error) {
		return ResponseVerdict{Action: Transform, Result: &mcp.CallToolResult{}, ReasonCode: "REDACTED"}, nil
	}}, Registration{Mandatory: true}); err != nil {
		t.Fatal(err)
	}
	if err := f.RegisterResponse(funcResp{"tagger", nil}, Registration{}); err == nil {
		t.Fatal("duplicate response ID accepted")
	}
	var observed [][]FilterRun
	f.Observe(func(_ *Call, stage string, runs []FilterRun) { observed = append(observed, runs) })
	call := schemaCall()
	if _, _, v := f.RunRequest(context.Background(), call, json.RawMessage(`{"text":"x"}`)); v != nil {
		t.Fatal(v)
	}
	if _, _, v := f.RunResponse(context.Background(), call, &mcp.CallToolResult{}); v != nil {
		t.Fatal(v)
	}
	runs := call.Inspection.Runs()
	if len(runs) != 3 || runs[0].Filter != "tagger" || runs[0].Version != "9.9" || runs[0].Duration <= 0 || runs[0].Action != Pass ||
		runs[1].Filter != "schema-validate" || runs[1].Version != "1" || runs[2].Stage != StageResponse || runs[2].Action != Transform {
		t.Fatalf("%+v", runs)
	}
	if tags := call.Inspection.Tags(); len(tags) != 1 || tags[0] != finding {
		t.Fatalf("%+v", tags)
	}
	if call.Inspection.Disposition() != "redact" {
		t.Fatal(call.Inspection.Disposition())
	}
	if len(observed) != 2 || len(observed[0]) != 2 || len(observed[1]) != 1 {
		t.Fatalf("%+v", observed)
	}
	if reg := f.Registered(StageRequest); len(reg) != 2 || reg[0].ID != "tagger" || !reg[1].Mandatory {
		t.Fatalf("%+v", reg)
	}
	var nilInsp *Inspection
	if nilInsp.Disposition() != "release" || nilInsp.Tags() != nil {
		t.Fatal("nil inspection")
	}
	for a, s := range map[Action]string{Pass: "pass", Transform: "transform", Block: "block"} {
		if a.String() != s {
			t.Fatal(a)
		}
	}
}
