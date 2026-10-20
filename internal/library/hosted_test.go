package library

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const hostedDecision = "Import ContextForge catalog entry deepwiki (DeepWiki) as deepwiki@1+cf.1.\nThe code of this hosted server cannot be inspected.\n"

// hostedPackage writes a hosted package (manifest_version 2), lets edit
// change the written manifest JSON (refreshing the digests that name it)
// and signs it.
func hostedPackage(t *testing.T, k pkgtest.Key, rev string, prov func(p *packaging.Provenance), edit func(m map[string]any)) string {
	t.Helper()
	desc := "Read a wiki."
	m := &packaging.Manifest{
		Server:    packaging.ServerInfo{ID: "deepwiki", Revision: rev, Alias: "deepwiki", Publisher: "Devin"},
		Upstream:  &packaging.Upstream{Kind: "contextforge-hosted", URL: "https://mcp.deepwiki.com/mcp", Transport: "STREAMABLEHTTP", EntryID: "deepwiki", EntrySHA256: packaging.SHA256Hex([]byte("e")), GatewayName: "smcp-deepwiki", GatewaySlug: "smcp-deepwiki"},
		Era:       "2025-11-25",
		RiskClass: "moderate",
		Tools: []packaging.Tool{{Name: "read_wiki", BackendName: "smcp-deepwiki-read-wiki", Description: desc, DescriptionSHA256: packaging.SHA256Hex([]byte(desc)),
			InputSchema: json.RawMessage(`{"type":"object"}`), SideEffect: "external", SourceTrust: "untrusted"}},
		Capabilities: packaging.Capabilities{Filesystem: []packaging.FilesystemSlot{}, Egress: []packaging.EgressRule{{Host: "mcp.deepwiki.com", Ports: []int{443}, Methods: []string{"POST"}}}},
	}
	p := packaging.Provenance{Builder: packaging.Builder{Tool: "test"}, Probe: packaging.ProbeEnvironment{Launcher: "contextforge", Network: "host", EnvNames: []string{}},
		TrustDecision: &packaging.TrustDecision{Actor: "op", Time: "2026-10-19T00:00:00Z", Text: hostedDecision, PresentedSHA256: packaging.SHA256Hex([]byte(hostedDecision))}}
	if prov != nil {
		prov(&p)
	}
	dir := filepath.Join(t.TempDir(), "pkg")
	if _, err := packaging.WriteHosted(dir, m, p, "test", "1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		path := filepath.Join(dir, packaging.ManifestFile)
		raw, _ := os.ReadFile(path)
		var doc map[string]any
		_ = json.Unmarshal(raw, &doc)
		edit(doc)
		raw, _ = json.MarshalIndent(doc, "", "  ")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		var ix packaging.Index
		ixRaw, _ := os.ReadFile(filepath.Join(dir, packaging.IndexFile))
		_ = json.Unmarshal(ixRaw, &ix)
		ix.Manifest.SHA256, ix.Manifest.Size = packaging.SHA256Hex(raw), int64(len(raw))
		if v, ok := doc["risk_class"].(string); ok {
			ix.RiskClass = v
		}
		if err := packaging.WriteJSON(filepath.Join(dir, packaging.IndexFile), ix, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := packaging.Sign(dir, k.Private, time.Now()); err != nil {
		t.Fatal(err)
	}
	return dir
}

// SR-3-6: a hosted package lacking each admission condition in turn is
// rejected naming it, and one meeting all is imported. FR-22.22 (library
// part): with [contextforge] bundled false a hosted package can neither be
// imported nor enabled.
func TestHostedAdmission(t *testing.T) {
	reqtest.Verifies(t, "SR-3-6")
	reqtest.Partial(t, "FR-22.22", "FR-22.13")
	e := newEnv(t, "moderate", "high")
	bundled := true
	e.lib.hostedAllowed = func() bool { return bundled }
	cases := []struct {
		name   string
		prov   func(p *packaging.Provenance)
		edit   func(m map[string]any)
		reason string
		names  string
	}{
		{"no trust decision", func(p *packaging.Provenance) { p.TrustDecision = nil }, nil, ReasonHostedAdmission, "no trust decision"},
		{"no acknowledgment", func(p *packaging.Provenance) {
			p.TrustDecision.Text = "Import it."
			p.TrustDecision.PresentedSHA256 = packaging.SHA256Hex([]byte("Import it."))
		}, nil, ReasonHostedAdmission, "cannot be inspected"},
		{"trusted tool", nil, func(m map[string]any) { m["tools"].([]any)[0].(map[string]any)["source_trust"] = "trusted" }, packaging.ReasonManifestSchema, "source_trust"},
		{"low risk", nil, func(m map[string]any) { m["risk_class"] = "low" }, packaging.ReasonManifestSchema, "risk_class"},
	}
	for i, c := range cases {
		dir := hostedPackage(t, e.key, "1+cf."+string(rune('1'+i)), c.prov, c.edit)
		_, err := e.lib.Import(dir, ImportOptions{})
		if reason(err) != c.reason || !strings.Contains(err.Error(), c.names) {
			t.Errorf("%s: %v, want %s naming %q", c.name, err, c.reason, c.names)
		}
	}
	// The bundled instance off: refused.
	bundled = false
	if _, err := e.lib.Import(hostedPackage(t, e.key, "2+cf.1", nil, nil), ImportOptions{}); reason(err) != ReasonContextForgeDisabled {
		t.Fatalf("bundled off: %v", err)
	}
	// All conditions: imported, verified-disabled, no artifact tree.
	bundled = true
	rc, err := e.lib.Import(hostedPackage(t, e.key, "2+cf.1", nil, nil), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rev, _ := e.lib.Get(rc.ServerID, rc.Revision)
	if rev.State != StateVerifiedDisabled || rev.TreeSHA256 != "" || rev.ArtifactType != packaging.ArtifactHosted {
		t.Fatalf("revision %+v", rev)
	}
	bundled = false
	if _, err := e.lib.Enable(rc.ServerID, rc.Revision, EnableOptions{}); reason(err) != ReasonContextForgeDisabled {
		t.Fatalf("enable with bundled off: %v", err)
	}
	bundled = true
	if _, err := e.lib.Enable(rc.ServerID, rc.Revision, EnableOptions{}); err != nil {
		t.Fatal(err)
	}
	m, _, err := e.lib.Manifest(rc.ServerID, rc.Revision)
	if err != nil || !m.Hosted() || m.FindBackend("smcp-deepwiki-read-wiki") == nil {
		t.Fatalf("manifest %v %+v", err, m)
	}
}
