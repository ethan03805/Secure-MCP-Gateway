package connector_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cfharness"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func waitRevState(t *testing.T, e *cfharness.Env, r library.Revision, state string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := e.Lib.Get(r.ServerID, r.Revision); got.State == state {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _ := e.Lib.Get(r.ServerID, r.Revision)
	t.Fatalf("%s is %s, want %s", r.Key(), got.State, state)
}

// TestDriftThroughContextForge is SR-3.8-2 with two hosted packages: a
// change of package A's tool list served through the bundled instance
// (a tool added, a description changed, the gateway renamed, with no
// list-change notification) suspends A for drift at the reconciliation
// while B keeps serving; then the instance is started from another
// verified image, and B, whose tools were checked against the previous
// image, is suspended for drift when it is launched, with a
// contextforge_drift event naming both digests.
func TestDriftThroughContextForge(t *testing.T) {
	reqtest.Verifies(t, "SR-3.8-2")
	e := cfharness.New(t, cfharness.Options{Entries: []cfharness.Entry{{ID: "dr-a", URL: "https://dr-a.example.com/mcp"}, {ID: "dr-b", URL: "https://dr-b.example.com/mcp"}}})
	ra := e.Import("dr-a", connector.LocalImport{})
	rb := e.Import("dr-b", connector.LocalImport{})
	g, err := e.Launch(ra, rb)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := g.Call(rb.Alias+"_echo", map[string]any{}); err != nil || res.IsError {
		t.Fatalf("B before: %v %+v", err, res)
	}
	e.StandIn.RugPull("smcp-dr-a")
	e.Conn.ReconcileNow()
	waitRevState(t, e, ra, library.StateSuspended)
	if got, _ := e.Lib.Get(rb.ServerID, rb.Revision); got.State != library.StateEnabled {
		t.Fatalf("B is %s after A's drift", got.State)
	}
	// Another verified image.
	ctx := context.Background()
	if err := e.Conn.StopInstance(ctx, "op"); err != nil {
		t.Fatal(err)
	}
	other := "sha256:" + strings.Repeat("ab", 32)
	e.SetImageDigest(other)
	if err := os.Remove(filepath.Join(e.State, "contextforge", "verified.json")); err != nil {
		t.Fatal(err)
	}
	_, _ = e.Launch(rb)
	waitRevState(t, e, rb, library.StateSuspended)
	found := false
	for _, ev := range e.Rec.Events() {
		if ev.Class != connector.ClassDrift || ev.ServerRevision != rb.Key() {
			continue
		}
		d, _ := ev.Detail.(map[string]any)
		if d["kind"] == "instance_digest" && d["running_digest"] == other && d["recorded_digest"] != "" && d["recorded_digest"] != other {
			found = true
		}
	}
	if !found {
		t.Fatal("no contextforge_drift event naming the recorded and running digests")
	}
}
