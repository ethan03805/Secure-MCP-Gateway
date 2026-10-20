package connector_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cfharness"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cftest"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestHostedUnqualifiedCapabilities: a bundled-instance stand-in whose
// virtual server advertises resources, prompts, completions and logging,
// answers resources/list and prompts/list, and sends elicitation/create,
// sampling/createMessage and roots/list on a tool call's response stream
// (SR-5.6-3):
//
//   - the Gateway never asks the instance for resources, prompts,
//     completions or logging, and presents only the package's tools;
//   - each of the three requests is answered with -32601 and counted as
//     refused, none is answered with a result, and the call's own result
//     still arrives.
//
// The northbound side is the same as for any backend: the Protocol
// Mediator rejects resources, prompts and the other unqualified features
// and advertises none of them whatever a backend offers (SR-5.6-1,
// internal/conformance), and the Tool Dispatcher declares no sampling,
// elicitation or roots capability southbound (SR-5.6-2), which the
// initialize request checked here confirms for the bundled instance.
func TestHostedUnqualifiedCapabilities(t *testing.T) {
	reqtest.Verifies(t, "SR-5.6-3")
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{{ID: "fx-a", URL: "https://a.example.com/mcp"}}, StandIn: &cftest.StandIn{}})
	ra := e.Import("fx-a", connector.LocalImport{})
	e.StandIn.Unqualified = true
	g, err := e.Launch(ra)
	if err != nil {
		t.Fatal(err)
	}
	res, err := g.Call(ra.Alias+"_echo", map[string]any{"x": 1})
	if err != nil || res.IsError || !strings.HasPrefix(text(res), "a.example.com echo") {
		t.Fatalf("call: %v %+v", err, res)
	}

	refused := map[string]bool{}
	initialized := false
	for _, r := range e.StandIn.Requests() {
		if !strings.HasPrefix(r.Path, "/servers/") || r.Method != "POST" {
			continue
		}
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Capabilities map[string]any `json:"capabilities"`
			} `json:"params"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code int64 `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
			t.Fatalf("request body %q: %v", r.Body, err)
		}
		for _, p := range []string{"resources/", "prompts/", "completion/", "logging/"} {
			if strings.HasPrefix(m.Method, p) {
				t.Fatalf("the Gateway sent %s to the bundled instance", m.Method)
			}
		}
		if m.Method == "initialize" {
			initialized = true
			for _, c := range []string{"sampling", "elicitation", "roots"} {
				if _, ok := m.Params.Capabilities[c]; ok {
					t.Fatalf("the Gateway declared the %s capability to the bundled instance: %s", c, r.Body)
				}
			}
		}
		var id string
		if json.Unmarshal(m.ID, &id) != nil {
			continue
		}
		method, ours := cftest.UnqualifiedRequests[id]
		if !ours || m.Method != "" {
			continue
		}
		if len(m.Result) > 0 || m.Error == nil || m.Error.Code != -32601 {
			t.Fatalf("%s was answered with %s", method, r.Body)
		}
		refused[method] = true
	}
	if !initialized {
		t.Fatal("no initialize request reached the bundled instance")
	}
	if len(refused) != len(cftest.UnqualifiedRequests) {
		t.Fatalf("refused %v, want every one of %v", refused, cftest.UnqualifiedRequests)
	}
	if n := g.Reg.Servers()[ra.Alias].RefusedRequests(); n != 3 {
		t.Fatalf("the dispatcher counted %d refused requests", n)
	}
	names := g.Reg.PublicNames()
	if len(names) != 2 {
		t.Fatalf("presented %v", names)
	}
	for _, n := range names {
		if n != ra.Alias+"_echo" && n != ra.Alias+"_get_time" {
			t.Fatalf("presented %q", n)
		}
	}
}

// TestHostedResultsServerAsserted: the bundled instance answers one call
// with a result and another with a JSON-RPC error, both claiming to come
// from another server (SR-6.18-2). The error's message is journaled as a
// server_asserted event; that event and the call events that record the
// result and the failure are attributed to the called hosted package
// revision and the bundled instance (the route fields of FR-22.39) and
// labeled server-asserted; nothing names the claimed server as the
// source.
//
// The call events are the ones the edge pipeline records: it copies the
// resolved tool's server revision into the base event of the call
// (callRun.base in internal/edge/pipeline.go), so they are committed here
// with the revision the registry resolved, through the Fanout and the
// Connector's decorator as smcpd wires them (attachContextForge).
func TestHostedResultsServerAsserted(t *testing.T) {
	reqtest.Verifies(t, "SR-6.18-2")
	const other = "trusted-internal-server"
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{{ID: "fx-a", URL: "https://a.example.com/mcp"}}, Tools: []string{"echo", "fail"},
		StandIn: &cftest.StandIn{Impersonate: other}})
	ra := e.Import("fx-a", connector.LocalImport{})
	g, err := e.Launch(ra)
	if err != nil {
		t.Fatal(err)
	}
	res, err := g.Call(ra.Alias+"_echo", map[string]any{})
	if err != nil || !strings.Contains(text(res), "from server "+other) {
		t.Fatalf("result: %v %+v", err, res)
	}
	var be *backend.BackendError
	if _, err := g.Call(ra.Alias+"_fail", map[string]any{}); !errors.As(err, &be) {
		t.Fatalf("error call: %v", err)
	}
	ref := g.Reg.Resolve(ra.Alias + "_echo")
	if ref.Server.Revision != ra.Key() {
		t.Fatalf("the registry resolved revision %q, the package is %q", ref.Server.Revision, ra.Key())
	}
	for _, ev := range []audit.Event{
		{Class: "call", Phase: audit.PhaseCompleted, Origin: "E-10", Outcome: "ok", ServerRevision: ref.Server.Revision, PolicyStatus: "evaluated"},
		{Class: "call", Phase: audit.PhaseFailed, Origin: "E-10", Outcome: "backend_error", ReasonCode: "BACKEND_ERROR", ServerRevision: ref.Server.Revision, PolicyStatus: "evaluated"},
	} {
		if err := e.Fanout.Commit(ev); err != nil {
			t.Fatal(err)
		}
	}

	attributed := func(ev audit.Event) bool {
		r := ev.Route
		return ev.ServerRevision == ra.Key() && r["via"] == connector.RouteVia && r["server_id"] == ra.ServerID && r["revision"] == ra.Revision &&
			r["virtual_server"] != "" && r["instance_version"] != "" && strings.HasPrefix(r["instance_digest"], "sha256:") &&
			r[connector.RouteEvidence] == connector.EvidenceServerAsserted
	}
	var asserted *audit.Event
	deadline := time.Now().Add(10 * time.Second)
	for asserted == nil && time.Now().Before(deadline) {
		for _, ev := range e.Rec.Events() {
			if ev.Class == "server_asserted" && ev.Outcome == backend.AssertError {
				asserted = &ev
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if asserted == nil {
		t.Fatal("no server_asserted event for the error")
	}
	d, _ := asserted.Detail.(map[string]any)
	if !attributed(*asserted) || audit.OriginLabel(*asserted) != audit.OriginBackend || d["server"] != ra.Alias ||
		!strings.Contains(d["text"].(string), other) || !strings.HasPrefix(d["instance"].(string), ra.Alias+"#") {
		t.Fatalf("error event %+v", *asserted)
	}
	evs := e.Rec.Events()
	completed, failed := evs[len(evs)-2], evs[len(evs)-1]
	if !attributed(completed) || !attributed(failed) {
		t.Fatalf("call events not attributed and labeled: %+v %+v", completed.Route, failed.Route)
	}
	for _, ev := range evs {
		raw, _ := json.Marshal(ev.Route)
		if strings.Contains(string(raw), other) || strings.Contains(ev.ServerRevision, other) {
			t.Fatalf("an event attributes a claim to %s: %+v", other, ev)
		}
	}
	// The Gateway's own events of the call are not labeled.
	if err := e.Fanout.Commit(audit.Event{Class: "call", Phase: audit.PhaseDispatched, Origin: "E-10", ServerRevision: ref.Server.Revision, PolicyStatus: "evaluated"}); err != nil {
		t.Fatal(err)
	}
	evs = e.Rec.Events()
	if last := evs[len(evs)-1]; last.Route["via"] != connector.RouteVia || last.Route[connector.RouteEvidence] != "" {
		t.Fatalf("dispatched event route %v", last.Route)
	}
}
