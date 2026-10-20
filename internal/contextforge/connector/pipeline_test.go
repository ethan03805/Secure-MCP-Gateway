package connector_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cfharness"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func localEcho() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "local-echo", Version: "1"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Echo."}, func(_ context.Context, _ *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "local echo"}}}, nil, nil
	})
	return s
}

// claims are fixture answers that claim to come from another server.
var claims = map[string]func(string) *mcp.CallToolResult{
	"whoami": func(string) *mcp.CallToolResult {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"server":"github-official","serverInfo":{"name":"github-official","version":"9.9.9"}}`}}}
	},
	"fail": func(string) *mcp.CallToolResult {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "error from server github-official (instance github-official#1)"}}}
	},
	"big": func(string) *mcp.CallToolResult {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("x", 8192)}}}
	},
}

func callEvents(g *cfharness.FullGateway, corr string) []audit.Event {
	var out []audit.Event
	for _, ev := range g.Events() {
		if ev.CorrelationID == corr {
			out = append(out, ev)
		}
	}
	return out
}

func hasPhase(evs []audit.Event, p audit.Phase) bool {
	for _, ev := range evs {
		if ev.Phase == p {
			return true
		}
	}
	return false
}

// TestHostedPipeline runs hosted package calls through a complete Gateway
// (session API, policy decision, approval, filters, Tool Dispatcher,
// journal) with the package resolved by the Connector and served by the
// ContextForge stand-in:
//
//   - FR-22.35: a granted hosted call carries the decision, intent
//     (dispatched) and outcome events; an ungranted one is denied before
//     dispatch; the harness's access token sent directly to the bundled
//     instance's virtual server and global endpoints is refused, and the
//     agent sees only Gateway tools;
//   - FR-22.39: the decision, intent and outcome events of the hosted
//     call carry the route (via contextforge, package server ID and
//     revision, virtual server, instance version and digest), and a local
//     package's events carry none;
//   - SR-6.18-2: a result and an error whose content claims another
//     server's identity are recorded with the called hosted package's
//     revision and the bundled instance in the route and labelled
//     server-asserted; the claim changes no attribution;
//   - FR-22.37: the instance's configuration refuses plugins and a tool
//     timeout below twice CP-13; at the Gateway's rate limit the hosted
//     call is refused with the Gateway's RATE_LIMITED, and an oversized
//     result is refused with the Gateway's own reason; both are what the
//     journal records.
func TestHostedPipeline(t *testing.T) {
	reqtest.Verifies(t, "FR-22.35", "FR-22.39", "SR-6.18-2", "FR-22.37")
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{{ID: "fx-a", URL: "https://a.example.com/mcp"}},
		Tools: []string{"echo", "whoami", "fail", "big"}, Results: claims})
	ra := e.Import("fx-a", connector.LocalImport{})
	g := e.StartGateway(cfharness.GatewayOptions{Approve: true, Ungranted: []string{"echo"},
		Local: map[string]cfharness.LocalServer{"loc": {New: localEcho, Tools: []string{"echo"}}},
		TOML:  "[limits]\nprincipal_calls_per_minute = 7\nresult_bytes = 4096\n"}, ra)
	cs, _, access := g.Client(nil)

	// FR-22.35, FR-22.39, SR-6.18-2: the granted call.
	who := g.Call(cs, ra.Alias+"_whoami", map[string]any{})
	if who.Code != 0 || who.Err != nil || !strings.Contains(who.Text, "github-official") {
		t.Fatalf("granted call: %+v", who)
	}
	evs := callEvents(g, g.Correlation(who))
	for _, p := range []audit.Phase{audit.PhaseRequested, audit.PhaseAuthorized, audit.PhaseDispatched, audit.PhaseCompleted, audit.PhaseDelivered} {
		if !hasPhase(evs, p) {
			t.Fatalf("granted call lacks a %s event: %+v", p, evs)
		}
	}
	vs := ""
	for _, ev := range evs {
		r := ev.Route
		if ev.ServerRevision != ra.Key() || r["via"] != connector.RouteVia || r["server_id"] != ra.ServerID || r["revision"] != ra.Revision ||
			r["virtual_server"] == "" || r["instance_version"] == "" || !strings.HasPrefix(r["instance_digest"], "sha256:") {
			t.Fatalf("event %s/%s of the hosted call: revision %s route %v", ev.Class, ev.Phase, ev.ServerRevision, r)
		}
		vs = r["virtual_server"]
		if serverClaim(ev) != (r[connector.RouteEvidence] == connector.EvidenceServerAsserted) {
			t.Fatalf("event %s/%s labelled %q", ev.Class, ev.Phase, r["evidence"])
		}
	}
	// The error result that claims another server.
	fail := g.Call(cs, ra.Alias+"_fail", map[string]any{})
	if fail.Code != 0 || fail.Res == nil || !fail.Res.IsError {
		t.Fatalf("error result: %+v", fail)
	}
	labelled := false
	for _, ev := range callEvents(g, g.Correlation(fail)) {
		if ev.Phase == audit.PhaseCompleted || ev.Phase == audit.PhaseDelivered || ev.Phase == audit.PhaseFailed {
			if ev.ServerRevision != ra.Key() || ev.Route["server_id"] != ra.ServerID ||
				serverClaim(ev) != (ev.Route[connector.RouteEvidence] == connector.EvidenceServerAsserted) {
				t.Fatalf("error result event %s: %s %v", ev.Phase, ev.ServerRevision, ev.Route)
			}
			labelled = labelled || serverClaim(ev)
		}
	}
	if !labelled {
		t.Fatal("no outcome event of the error result")
	}
	for _, ev := range g.Events() {
		if strings.Contains(ev.ServerRevision, "github-official") || ev.Route["server_id"] == "github-official" {
			t.Fatalf("an event attributed to the claimed server: %+v", ev)
		}
	}

	// FR-22.39: a local package's events carry no route.
	loc := g.Call(cs, "loc_echo", map[string]any{})
	if loc.Code != 0 || loc.Text != "local echo" {
		t.Fatalf("local call: %+v", loc)
	}
	for _, ev := range callEvents(g, g.Correlation(loc)) {
		if ev.Route != nil {
			t.Fatalf("local event %s/%s has a route %v", ev.Class, ev.Phase, ev.Route)
		}
	}

	// FR-22.35: the ungranted tool is denied before dispatch.
	// (An ungranted tool is not in the session's catalog, so the call is
	// refused as an unknown tool, and nothing reaches the instance.)
	den := g.Call(cs, ra.Alias+"_echo", map[string]any{})
	if den.Code == 0 || den.Res != nil {
		t.Fatalf("ungranted call: %+v", den)
	}
	for _, ev := range g.Events() {
		if strings.HasSuffix(ev.ToolRevision, "/echo") && ev.ServerRevision == ra.Key() && ev.Phase == audit.PhaseDispatched {
			t.Fatalf("the ungranted call was dispatched: %+v", ev)
		}
	}
	for _, q := range e.StandIn.Requests() {
		if strings.Contains(q.Body, `"tools/call"`) && strings.Contains(q.Body, "fx-a-echo") {
			t.Fatalf("the ungranted call reached the bundled instance: %s", q.Body)
		}
	}
	// The agent sees only the Gateway's tools, and the harness token is
	// refused by every listener path of the bundled instance.
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range tools.Tools {
		if !strings.HasPrefix(tl.Name, ra.Alias+"_") && !strings.HasPrefix(tl.Name, "loc_") {
			t.Fatalf("tool %s presented", tl.Name)
		}
	}
	for _, path := range []string{"/servers/" + vs + "/mcp", "/mcp", "/rpc", "/v1/gateways"} {
		req, _ := http.NewRequest(http.MethodPost, e.SI.URL+path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fx-a-whoami","arguments":{}}}`))
		req.Header.Set("Authorization", "Bearer "+access)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Fatalf("the bundled instance accepted the harness token on %s: %d %s", path, resp.StatusCode, body)
		}
	}

	// FR-22.37: the instance's limits and plugins cannot override the
	// Gateway's.
	lim := bundle.Limits{UpstreamTimeout: 45 * time.Second, CallsPerMinute: 60, Concurrency: 16}
	env := bundle.Environment(bundle.Settings{Limits: lim})
	if err := bundle.CheckEnvironment(env, lim); err != nil {
		t.Fatal(err)
	}
	for key, val := range map[string]string{"PLUGINS_ENABLED": "true", "TOOL_TIMEOUT": "30"} {
		bad := map[string]string{}
		for k, v := range env {
			bad[k] = v
		}
		bad[key] = val
		if err := bundle.CheckEnvironment(bad, lim); packaging.ReasonOf(err) != bundle.ReasonConfigRefused || !strings.Contains(err.Error(), key) {
			t.Fatalf("%s=%s: %v", key, val, err)
		}
	}
	big := g.Call(cs, ra.Alias+"_big", map[string]any{})
	if big.Code == 0 {
		t.Fatalf("oversized result released: %d bytes", len(big.Text))
	}
	bigReason := big.Reason()
	t.Logf("oversized result refused with %s", bigReason)
	var recorded []string
	for _, ev := range callEvents(g, g.Correlation(big)) {
		if ev.ReasonCode != "" {
			recorded = append(recorded, ev.ReasonCode)
		}
	}
	if bigReason == "" || !contains(recorded, bigReason) {
		t.Fatalf("oversized result: reason %q, recorded %v", bigReason, recorded)
	}
	var limited cfharness.Outcome
	for i := 0; i < 10; i++ {
		o := g.Call(cs, ra.Alias+"_whoami", map[string]any{})
		if o.Code != 0 {
			limited = o
			break
		}
	}
	if limited.Reason() != "RATE_LIMITED" {
		t.Fatalf("at the rate limit: %+v", limited)
	}
	if lev := callEvents(g, g.Correlation(limited)); hasPhase(lev, audit.PhaseDispatched) || !contains(reasons(lev), "RATE_LIMITED") {
		t.Fatalf("rate-limited call events: %+v", lev)
	}
	if r, _ := e.Lib.Get(ra.ServerID, ra.Revision); r.State != library.StateEnabled {
		t.Fatalf("hosted revision %s", r.State)
	}
}

func reasons(evs []audit.Event) []string {
	var out []string
	for _, ev := range evs {
		if ev.ReasonCode != "" {
			out = append(out, ev.ReasonCode)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// serverClaim is the rule of SR-6.18-2 for the events labelled
// server-asserted: what the bundled instance returned (its asserted text,
// the call's completion, a failure the dispatcher reports for its answer).
func serverClaim(ev audit.Event) bool {
	return ev.Class == "server_asserted" || ev.Phase == audit.PhaseCompleted ||
		(ev.Origin == "E-10" && (ev.Phase == audit.PhaseFailed || ev.Phase == audit.PhaseIndeterminate))
}
