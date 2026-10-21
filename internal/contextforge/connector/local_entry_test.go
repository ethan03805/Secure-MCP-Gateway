package connector

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cftest"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/southbound"
)

// TestLocalEntryOutsideContextForge is FR-22.8: a package imported from a
// local catalog entry (markitdown, a PyPI wheel pinned by the operator) is
// enabled with the bundled instance stopped and then running; in both
// cases the library runtime launches it as an ordinary stdio server (a
// command, no URL), its tool answers through that instance, and the
// bundled instance (the ContextForge stand-in) receives no request.
func TestLocalEntryOutsideContextForge(t *testing.T) {
	reqtest.Verifies(t, "FR-22.8")
	need(t, "python3")
	f := newFixture(t, "bundled = true\n")
	f.enroll()
	si := &cftest.StandIn{AdminToken: "admin"}
	srv := httptest.NewServer(si)
	t.Cleanup(srv.Close)
	r := &upgRunner{base: srv.URL, release: "v1.0.11"}
	c, err := New(Options{Config: f.cfg, Library: f.lib, Recorder: f.rec, Broker: testBroker(t, f.rec), Version: "test", Runner: r, Verifier: upgVerifier{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	fr := registryOf(t, f)
	in := LocalImport{ArtifactType: "pypi", Package: "markitdown-mcp", Argv: []string{"python3", "-m", "markitdown_mcp"}, Licenses: []string{"MIT"},
		Version: "0.0.1", ArtifactSHA256: packaging.SHA256Hex(fr.whl)}
	p, err := c.ProposeLocal("markitdown", in, "op")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for p.State == stateBuilding && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		p, _ = c.Proposal(p.ID)
	}
	if p.State != stateReady {
		t.Fatalf("local import: %s %s %s", p.State, p.ReasonCode, p.Error)
	}
	got, err := c.Decide(p.ID, true, p.Decision.SHA256, "op")
	if err != nil {
		t.Fatal(err)
	}
	rev, err := f.lib.Enable(got.ServerID, got.Revision, library.EnableOptions{Standalone: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	call := func(label string) {
		t.Helper()
		rt := library.NewRuntime(f.lib, library.RuntimeOptions{Hosted: c.ResolveHosted})
		servers, launcher, err := rt.Prepare(f.rec, []config.Server{{Alias: rev.Alias, Package: rev.ServerID}},
			WrapLauncher(southbound.Wrap(pipeline.SubprocessLauncher{}), func() *Connector { return c }), true)
		if err != nil || len(servers) != 1 {
			t.Fatalf("%s: prepare %v %+v", label, err, servers)
		}
		if servers[0].URL != "" || servers[0].Command == "" {
			t.Fatalf("%s: the local package is not a stdio server: %+v", label, servers[0])
		}
		caps := pipeline.NewCapabilities(time.Minute)
		reg, err := backend.Start(ctx, servers, backend.Options{
			Limits:   backend.Limits{PerPrincipal: 2, Total: 4, Queue: 4, UpstreamTimeout: 20 * time.Second, ResultBytes: 1 << 20},
			Launcher: launcher, Manifests: rt, Capabilities: caps})
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		defer reg.Close()
		public := rev.Alias + "_convert_to_markdown"
		ref := reg.Resolve(public)
		if ref == nil {
			t.Fatalf("%s: %s not presented", label, public)
		}
		b := pipeline.Binding{CorrelationID: "c", DecisionID: "d", PolicyRevision: "r", PublicName: public}
		res, err := reg.Call(ctx, backend.Dispatch{Principal: "p", Ref: ref, Capability: caps.Issue(b), Binding: b})
		if err != nil || res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "local server") {
			t.Fatalf("%s: call %v %+v", label, err, res)
		}
	}
	if st := c.Instance().State; st != bundle.StateStopped {
		t.Fatalf("instance %s before the first call", st)
	}
	call("instance stopped")
	if err := c.StartInstance(ctx, "op"); err != nil {
		t.Fatal(err)
	}
	if st := c.Instance().State; st != bundle.StateHealthy {
		t.Fatalf("instance %s", st)
	}
	call("instance running")
	for _, q := range si.Requests() {
		t.Fatalf("the bundled instance received %s %s", q.Method, q.Path)
	}
}
