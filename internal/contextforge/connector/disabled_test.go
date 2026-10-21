package connector_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cfharness"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func sessionTools(t *testing.T, g *cfharness.FullGateway) []string {
	t.Helper()
	cs, _, _ := g.Client(nil)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, tl := range res.Tools {
		out = append(out, tl.Name)
	}
	return out
}

func hasPrefixed(names []string, prefix string) bool {
	for _, n := range names {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// TestImportedPackagesStartDisabled is FR-22.13 with a local entry (a
// pinned PyPI wheel built through packaging) and a hosted entry imported
// while a complete Gateway runs: both are recorded verified-disabled; the
// active policy revision is the same before and after; their tools are in
// no session catalog while they are disabled (even with [[server]] entries
// and grants), nor while they are enabled but not granted; enabled and
// granted, they are presented.
func TestImportedPackagesStartDisabled(t *testing.T) {
	reqtest.Verifies(t, "FR-22.13")
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{{ID: "dis-h", URL: "https://dis-h.example.com/mcp"}}, Local: true})
	g1 := e.StartGateway(cfharness.GatewayOptions{Approve: true})
	before := g1.App.Decider.Snapshot().Revision
	p, err := e.Probe("dis-h", connector.LocalImport{})
	if err != nil || p.State != "ready" {
		t.Fatalf("hosted probe: %v %+v", err, p)
	}
	got, err := e.Conn.Decide(p.ID, true, p.Decision.SHA256, "op")
	if err != nil {
		t.Fatal(err)
	}
	hosted, _ := e.Lib.Get(got.ServerID, got.Revision)
	local := e.ImportLocalEntry()
	for _, r := range []library.Revision{hosted, local} {
		if r.State != library.StateVerifiedDisabled {
			t.Fatalf("%s imported %s", r.Key(), r.State)
		}
	}
	if after := g1.App.Decider.Snapshot().Revision; after != before {
		t.Fatalf("the import changed the active policy revision from %s to %s", before, after)
	}
	tools := sessionTools(t, g1)
	if hasPrefixed(tools, hosted.Alias+"_") || hasPrefixed(tools, local.Alias+"_") {
		t.Fatalf("imported tools in a session catalog: %v", tools)
	}
	g1.Stop()

	// Configured and granted, still disabled.
	g2 := e.StartGateway(cfharness.GatewayOptions{Approve: true}, hosted, local)
	if tools := sessionTools(t, g2); hasPrefixed(tools, hosted.Alias+"_") || hasPrefixed(tools, local.Alias+"_") {
		t.Fatalf("disabled packages' tools presented: %v", tools)
	}
	g2.Stop()

	for _, r := range []library.Revision{hosted, local} {
		if _, err := e.Lib.Enable(r.ServerID, r.Revision, library.EnableOptions{Standalone: true}); err != nil {
			t.Fatal(err)
		}
	}
	// Enabled, not granted.
	g3 := e.StartGateway(cfharness.GatewayOptions{Approve: true, Ungranted: []string{"echo", "get_time", "convert_to_markdown"}}, hosted, local)
	if tools := sessionTools(t, g3); hasPrefixed(tools, hosted.Alias+"_") || hasPrefixed(tools, local.Alias+"_") {
		t.Fatalf("ungranted tools presented: %v", tools)
	}
	g3.Stop()

	// Enabled and granted.
	g4 := e.StartGateway(cfharness.GatewayOptions{Approve: true}, hosted, local)
	tools = sessionTools(t, g4)
	if !hasPrefixed(tools, hosted.Alias+"_") || !hasPrefixed(tools, local.Alias+"_") {
		for _, ev := range g4.Events() {
			if ev.Class != "call" && ev.Class != "filter" {
				t.Logf("event %s %s %s %s %v", ev.Class, ev.Outcome, ev.ReasonCode, ev.ServerRevision, ev.Detail)
			}
		}
		t.Fatalf("enabled and granted tools not presented: %v", tools)
	}
	cs, _, _ := g4.Client(nil)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: local.Alias + "_convert_to_markdown", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("the local package's tool: %v %+v", err, res)
	}
}
