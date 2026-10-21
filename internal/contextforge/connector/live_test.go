package connector_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/cfharness"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// TestStarterSetLive is the run behind the FR-22.17 Demonstration
// (docs/verification/FR-22.17.md). It
// needs the network, Docker and cosign (SMCP_CONTEXTFORGE_LIVE=1): without
// the bundled instance no starter-set offer is made; with it, the offer
// probes the three starter entries of the release lock through the pinned
// image and real hosted egress, each with its own decision and signature;
// all three packages are disabled; enabling deepwiki makes its tools
// callable through a complete Gateway. A local entry of the pinned catalog
// (markitdown, its wheel from a local index) is imported too, and the
// provenance statements of it and of deepwiki are logged for inspection.
func TestStarterSetLive(t *testing.T) {
	if os.Getenv("SMCP_CONTEXTFORGE_LIVE") != "1" {
		t.Skip("set SMCP_CONTEXTFORGE_LIVE=1 to import the starter set from the real hosted servers")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker not installed")
	}
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign not installed")
	}
	// Without the bundled instance: no offer.
	off, err := config.Parse([]byte(fmt.Sprintf("[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g\"\n[state]\ndir = %q\n[approvals]\nnotify = \"off\"\n", t.TempDir())))
	if err != nil {
		t.Fatal(err)
	}
	offLib, err := library.Open(library.Options{StateDir: off.State.Dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { offLib.Close() })
	offConn, err := connector.New(connector.Options{Config: off, Library: offLib, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = offConn.ProposeStarterSet("op")
	t.Logf("without the bundled instance: starter-set offer refused with %s", packaging.ReasonOf(err))
	if packaging.ReasonOf(err) != contextforge.ReasonContextForgeDisabled {
		t.Fatalf("offer without the bundled instance: %v", err)
	}
	offConn.Close()

	e := cfharness.New(t, cfharness.Options{Image: true, Engine: docker, Pinned: true, Local: true})
	ps, err := e.Conn.ProposeStarterSet("op")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("starter set of the release lock: %v; %d proposals", contextforge.ReleaseLock().ContextForge.StarterSet, len(ps))
	var revs []library.Revision
	for _, p := range ps {
		deadline := time.Now().Add(5 * time.Minute)
		for p.State == "building" && time.Now().Before(deadline) {
			time.Sleep(250 * time.Millisecond)
			p, _ = e.Conn.Proposal(p.ID)
		}
		if p.State != "ready" {
			t.Fatalf("%s: %s %s %s", p.EntryID, p.State, p.ReasonCode, p.Error)
		}
		f := p.Decision.Fields
		t.Logf("proposal %s: entry %s, class %s, provider %s, URL %s, auth %s, risk %s, side effects %v, egress %v, secret slots %v, code not inspectable %v, decision SHA-256 %s, tools %v",
			p.ID, p.EntryID, f.Class, f.Provider, f.URL, f.AuthType, f.RiskClass, f.SideEffects, f.Egress, f.SecretSlots, f.NotInspected, p.Decision.SHA256, f.Tools)
		got, err := e.Conn.Decide(p.ID, true, p.Decision.SHA256, "op")
		if err != nil || got.Outcome != "imported" {
			t.Fatalf("%s accept: %v %+v", p.EntryID, err, got)
		}
		r, _ := e.Lib.Get(got.ServerID, got.Revision)
		t.Logf("imported %s as %s, state %s, signed by the catalog import key %s", p.EntryID, r.Key(), r.State, e.Conn.KeyID())
		if r.State != library.StateVerifiedDisabled {
			t.Fatalf("%s is %s", r.Key(), r.State)
		}
		revs = append(revs, r)
	}
	// Enabling one makes its tools callable through the Gateway.
	var deepwiki library.Revision
	for _, r := range revs {
		if r.ServerID == "deepwiki" {
			deepwiki = r
		}
	}
	if deepwiki.ServerID == "" {
		t.Fatal("deepwiki not imported")
	}
	if _, err := e.Lib.Enable(deepwiki.ServerID, deepwiki.Revision, library.EnableOptions{}); err != nil {
		t.Fatal(err)
	}
	g := e.StartGateway(cfharness.GatewayOptions{Approve: true}, deepwiki)
	cs, _, _ := g.Client(nil)
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range list.Tools {
		names = append(names, tl.Name)
	}
	t.Logf("session catalog after enabling deepwiki: %v", names)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: deepwiki.Alias + "_read_wiki_structure", Arguments: map[string]any{"repoName": "modelcontextprotocol/go-sdk"}})
	if err != nil || res.IsError {
		t.Fatalf("deepwiki call: %v %+v", err, res)
	}
	txt := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			txt = tc.Text
		}
	}
	if len(txt) > 200 {
		txt = txt[:200]
	}
	t.Logf("%s_read_wiki_structure through the Gateway answered: %q", deepwiki.Alias, txt)
	for _, r := range revs {
		if r.ServerID != deepwiki.ServerID {
			if got, _ := e.Lib.Get(r.ServerID, r.Revision); got.State != library.StateVerifiedDisabled {
				t.Fatalf("%s is %s", r.Key(), got.State)
			}
		}
	}
	g.Stop()

	// The provenance statements of a hosted and a local package imported
	// from the pinned catalog (FR-22.11 lists their members).
	local := e.ImportLocalEntry()
	for _, r := range []library.Revision{deepwiki, local} {
		raw, err := os.ReadFile(filepath.Join(e.Lib.Dir(), r.ServerID, r.Revision, packaging.ProvenanceFile))
		if err != nil {
			t.Fatal(err)
		}
		var pv map[string]any
		_ = json.Unmarshal(raw, &pv)
		out, _ := json.MarshalIndent(map[string]any{"contextforge": pv["contextforge"], "trust_decision": pv["trust_decision"], "probe": pv["probe"]}, "", "  ")
		t.Logf("provenance of %s:\n%s", r.Key(), strings.TrimSpace(string(out)))
	}
	lock := contextforge.ReleaseLock().ContextForge
	cat, _ := contextforge.PinnedCatalog()
	for _, id := range []string{"deepwiki", "markitdown"} {
		en := cat.Entry(id)
		t.Logf("pinned catalog %s (%s), entry %s: SHA-256 %s, URL %q, repo %q, install %q", lock.Version, cat.SHA256, id, en.SHA256(), en.URL, en.Repo, en.Install)
	}
	t.Logf("release lock image %s (%s)", lock.ImageRef("linux/arm64"), lock.Image.IndexDigest)
}
