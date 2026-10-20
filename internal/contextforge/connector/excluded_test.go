package connector_test

import (
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cfharness"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestReconcileRemovesExcluded is the reconciliation fixture of the
// FR-22.38 Inspection (docs/verification/inspections.md): objects of every
// excluded type that the Connector did not create (a peer gateway, a REST
// tool of no gateway, a prompt, a resource, an A2A agent) are removed by
// one reconciliation pass and recorded as contextforge_drift, and the
// package's own gateway and tools stay.
func TestReconcileRemovesExcluded(t *testing.T) {
	reqtest.Partial(t, "FR-22.38")
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{{ID: "ex-a", URL: "https://ex-a.example.com/mcp"}}})
	r := e.Import("ex-a", connector.LocalImport{})
	g, err := e.Launch(r)
	if err != nil {
		t.Fatal(err)
	}
	e.StandIn.Inject()
	e.Conn.ReconcileNow()
	want := []string{"unknown_gateway", "unknown_tool", "unknown_prompt", "unknown_resource", "unknown_a2a_agent"}
	removed := map[string]bool{}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(removed) < len(want) {
		for _, ev := range e.Rec.Events() {
			if ev.Class != connector.ClassDrift {
				continue
			}
			d, _ := ev.Detail.(map[string]any)
			if k, _ := d["kind"].(string); d["removed"] == true {
				removed[k] = true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, k := range want {
		if !removed[k] {
			t.Errorf("%s not removed (removed: %v)", k, removed)
		}
	}
	if gws := e.StandIn.Gateways(); len(gws) != 1 {
		t.Fatalf("gateways after reconciliation: %v", gws)
	}
	if res, err := g.Call(r.Alias+"_echo", map[string]any{}); err != nil || res.IsError {
		t.Fatalf("the package's own tool after reconciliation: %v %+v", err, res)
	}
}
