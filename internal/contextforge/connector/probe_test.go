package connector_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cfharness"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestNarrowedProbe is SR-3.5-2: while package B runs with its production
// API key bound in S1 at its endpoint, the hosted-entry probe of entry A
// reaches only A's host (every connection the broker makes for the
// bundled instance during the probe goes to A's address, and B's fixture
// receives nothing), the probe holds no secret, B's key reaches neither A,
// the bundled instance nor any event, and the probe's provenance names
// its one network destination.
func TestNarrowedProbe(t *testing.T) {
	reqtest.Verifies(t, "SR-3.5-2")
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{
		{ID: "prod-b", URL: "https://prod-b.example.com/mcp", AuthType: "API Key", RequiresAPIKey: true},
		{ID: "probe-a", URL: "https://probe-a.example.com/mcp"},
	}})
	key := e.Fixtures["prod-b.example.com"].APIKey
	e.AddSecret("prod-b-key", key)
	rb := e.Import("prod-b", connector.LocalImport{ProbeSecret: &connector.ProbeSecret{Secret: "prod-b-key", Header: "X-Api-Key", Template: "{secret}"}})
	e.UseS1(rb.Alias, "api_key", "prod-b-key", "X-Api-Key", "{secret}", "prod-b.example.com:443")
	g, err := e.Launch(rb)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := g.Call(rb.Alias+"_echo", map[string]any{}); err != nil || res.IsError {
		t.Fatalf("B with its production key: %v %+v", err, res)
	}
	bBefore := len(e.Fixtures["prod-b.example.com"].Headers())
	dialedBefore := len(e.Dialed())
	p, err := e.Probe("probe-a", connector.LocalImport{})
	if err != nil || p.State != "ready" {
		t.Fatalf("probe of A: %v %+v", err, p)
	}
	during := e.Dialed()[dialedBefore:]
	if len(during) == 0 {
		t.Fatal("the probe made no connection")
	}
	for _, d := range during {
		if d != during[0] {
			t.Fatalf("the probe reached %s and %s", during[0], d)
		}
	}
	if n := len(e.Fixtures["prod-b.example.com"].Headers()); n != bBefore {
		t.Fatalf("B's fixture received %d requests during A's probe", n-bBefore)
	}
	if len(e.Fixtures["probe-a.example.com"].Headers()) == 0 {
		t.Fatal("A's fixture was not reached")
	}
	for _, h := range e.Fixtures["probe-a.example.com"].Headers() {
		for _, vs := range h {
			for _, v := range vs {
				if strings.Contains(v, key) {
					t.Fatal("B's production key reached A's host")
				}
			}
		}
	}
	for _, q := range e.StandIn.Requests() {
		if strings.Contains(q.Body, key) || strings.Contains(q.Authorization, key) {
			t.Fatalf("the bundled instance received B's key: %s %s", q.Method, q.Path)
		}
	}
	for _, ev := range e.Rec.Events() {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), key) {
			t.Fatalf("an event holds B's key: %s", raw)
		}
	}
	if p.Decision == nil || !strings.Contains(strings.Join(p.Decision.Fields.Egress, " "), "probe-a.example.com") {
		t.Fatalf("decision egress %+v", p.Decision)
	}
}
