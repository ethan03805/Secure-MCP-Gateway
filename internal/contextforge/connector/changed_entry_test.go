package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/southbound"
)

// changedCatalog is the markitdown entry of the pinned catalog with
// another URL and description.
const changedCatalog = `catalog_servers:
  - id: markitdown
    name: "MarkItDown"
    category: "Document Management"
    url: "http://localhost:9999/changed"
    auth_type: "Open"
    provider: "Microsoft"
    description: "Changed after the import"
    requires_api_key: false
    repo: "https://github.com/microsoft/markitdown"
    install: "markitdown-mcp"
`

func callLocal(t *testing.T, f *fixture, c *Connector, rev library.Revision) string {
	t.Helper()
	rt := library.NewRuntime(f.lib, library.RuntimeOptions{Hosted: c.ResolveHosted})
	servers, launcher, err := rt.Prepare(f.rec, []config.Server{{Alias: rev.Alias, Package: rev.ServerID}},
		WrapLauncher(southbound.Wrap(pipeline.SubprocessLauncher{}), func() *Connector { return c }), true)
	if err != nil || len(servers) != 1 {
		t.Fatalf("prepare: %v %+v", err, servers)
	}
	caps := pipeline.NewCapabilities(time.Minute)
	reg, err := backend.Start(context.Background(), servers, backend.Options{
		Limits:   backend.Limits{PerPrincipal: 2, Total: 4, Queue: 4, UpstreamTimeout: 20 * time.Second, ResultBytes: 1 << 20},
		Launcher: launcher, Manifests: rt, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	public := rev.Alias + "_convert_to_markdown"
	ref := reg.Resolve(public)
	if ref == nil {
		t.Fatalf("%s not presented", public)
	}
	b := pipeline.Binding{CorrelationID: "c", DecisionID: "d", PolicyRevision: "r", PublicName: public}
	res, err := reg.Call(context.Background(), backend.Dispatch{Principal: "p", Ref: ref, Capability: caps.Issue(b), Binding: b})
	if err != nil || res.IsError {
		t.Fatalf("call: %v %+v", err, res)
	}
	return res.Content[0].(*mcp.TextContent).Text
}

func trustOf(t *testing.T, f *fixture, id, rev string) *packaging.TrustDecision {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.lib.Dir(), id, rev, packaging.ProvenanceFile))
	if err != nil {
		t.Fatal(err)
	}
	var pv packaging.Provenance
	if err := json.Unmarshal(raw, &pv); err != nil || pv.TrustDecision == nil {
		t.Fatalf("provenance of %s@%s: %v", id, rev, err)
	}
	return pv.TrustDecision
}

// TestChangedEntryReimport is FR-22.16 with a local entry: markitdown is
// imported and enabled; a catalog in which its URL and description differ
// marks it "changed"; the enabled revision keeps serving, unchanged; and
// the re-import from the changed catalog creates a new, disabled revision
// with a trust decision of its own.
func TestChangedEntryReimport(t *testing.T) {
	reqtest.Verifies(t, "FR-22.16")
	need(t, "python3")
	f := newFixture(t, "")
	f.enroll()
	fr := registryOf(t, f)
	in := LocalImport{ArtifactType: "pypi", Package: "markitdown-mcp", Argv: []string{"python3", "-m", "markitdown_mcp"}, Licenses: []string{"MIT"},
		Version: "0.0.1", ArtifactSHA256: packaging.SHA256Hex(fr.whl)}
	importWith := func(c *Connector) library.Revision {
		t.Helper()
		p, err := c.ProposeLocal("markitdown", in, "op")
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(2 * time.Minute)
		for p.State == stateBuilding && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
			p, _ = c.Proposal(p.ID)
		}
		if p.State != stateReady {
			t.Fatalf("import: %s %s %s", p.State, p.ReasonCode, p.Error)
		}
		got, err := c.Decide(p.ID, true, p.Decision.SHA256, "op")
		if err != nil {
			t.Fatal(err)
		}
		r, ok := f.lib.Get(got.ServerID, got.Revision)
		if !ok {
			t.Fatalf("%s@%s not in the library", got.ServerID, got.Revision)
		}
		return r
	}
	first := importWith(f.c)
	first, err := f.lib.Enable(first.ServerID, first.Revision, library.EnableOptions{Standalone: true})
	if err != nil {
		t.Fatal(err)
	}
	before := callLocal(t, f, f.c, first)
	_, manifestBefore, _ := f.lib.Manifest(first.ServerID, first.Revision)

	// The catalog changes under the Gateway.
	file := filepath.Join(t.TempDir(), "changed.yml")
	if err := os.WriteFile(file, []byte(changedCatalog), 0o600); err != nil {
		t.Fatal(err)
	}
	f.cfg.ContextForge.CatalogFile, f.cfg.ContextForge.CatalogSHA256 = file, packaging.SHA256Hex([]byte(changedCatalog))
	c2, err := New(Options{Config: f.cfg, Library: f.lib, Recorder: f.rec, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c2.Close)
	list, err := c2.List(Filter{Query: "markitdown"})
	if err != nil || len(list) != 1 || list[0].State != "changed" {
		t.Fatalf("list after the change: %+v %v", list, err)
	}
	if after := callLocal(t, f, c2, first); after != before {
		t.Fatalf("the enabled revision answers %q, before %q", after, before)
	}
	_, manifestAfter, _ := f.lib.Manifest(first.ServerID, first.Revision)
	if !bytes.Equal(manifestBefore, manifestAfter) {
		t.Fatal("the enabled revision's manifest changed")
	}
	if r, _ := f.lib.Get(first.ServerID, first.Revision); r.State != library.StateEnabled {
		t.Fatalf("enabled revision %s after the change", r.State)
	}

	// The re-import: a new revision, disabled, with its own decision.
	second := importWith(c2)
	if second.Revision == first.Revision || second.State != library.StateVerifiedDisabled {
		t.Fatalf("re-import %s %s, first %s", second.Revision, second.State, first.Revision)
	}
	if r, _ := f.lib.Get(first.ServerID, first.Revision); r.State != library.StateEnabled {
		t.Fatalf("first revision %s after the re-import", r.State)
	}
	d1, d2 := trustOf(t, f, first.ServerID, first.Revision), trustOf(t, f, second.ServerID, second.Revision)
	if d1.PresentedSHA256 == d2.PresentedSHA256 || !strings.HasPrefix(second.Revision, "0.0.1+cf.") {
		t.Fatalf("trust decisions %+v and %+v; second revision %s", d1, d2, second.Revision)
	}
	if list, _ := c2.List(Filter{Query: "markitdown"}); len(list) != 1 || list[0].State != "imported" {
		t.Fatalf("list after the re-import: %+v", list)
	}
}
