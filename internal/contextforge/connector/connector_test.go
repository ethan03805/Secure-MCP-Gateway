package connector

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// jsServer and pyServer are dependency-free MCP stdio servers.
const jsServer = `const rl = require('readline').createInterface({input: process.stdin});
const send = (m) => process.stdout.write(JSON.stringify(m) + "\n");
rl.on('line', (l) => {
  let m; try { m = JSON.parse(l); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === 'initialize') return send({jsonrpc: '2.0', id: m.id, result: {protocolVersion: '2025-11-25', capabilities: {tools: {}}, serverInfo: {name: 'pw', version: '1'}}});
  if (m.method === 'tools/list') return send({jsonrpc: '2.0', id: m.id, result: {tools: [{name: 'browser_snapshot', description: 'Take a snapshot.', inputSchema: {type: 'object'}}]}});
  send({jsonrpc: '2.0', id: m.id, error: {code: -32601, message: 'method not found'}});
});
`

const pyServer = `import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if "id" not in m:
        continue
    if m.get("method") == "initialize":
        out = {"jsonrpc": "2.0", "id": m["id"], "result": {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "md", "version": "1"}}}
    elif m.get("method") == "tools/list":
        out = {"jsonrpc": "2.0", "id": m["id"], "result": {"tools": [{"name": "convert_to_markdown", "description": "Convert a URI.", "inputSchema": {"type": "object"}}]}}
    else:
        out = {"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32601, "message": "method not found"}}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
`

func tgz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(files[n]))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func wheel() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{"markitdown_mcp/__init__.py": "", "markitdown_mcp/__main__.py": pyServer,
		"markitdown_mcp-0.0.1.dist-info/METADATA": "Metadata-Version: 2.1\nName: markitdown-mcp\nVersion: 0.0.1\n"} {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(body))
	}
	_ = zw.Close()
	return buf.Bytes()
}

func integrity(b []byte) string {
	s := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}

// registry serves @playwright/mcp 0.0.41 and markitdown-mcp 0.0.1.
type registry struct {
	srv *httptest.Server
	tgz []byte
	whl []byte
}

func newRegistry(t *testing.T) *registry {
	t.Helper()
	r := &registry{tgz: tgz(t, map[string]string{"package/package.json": `{"name":"@playwright/mcp","version":"0.0.41"}`, "package/cli.js": jsServer}), whl: wheel()}
	mux := http.NewServeMux()
	mux.HandleFunc("/npm/@playwright/mcp/-/mcp-0.0.41.tgz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(r.tgz) })
	mux.HandleFunc("/pypi/pypi/markitdown-mcp/0.0.1/json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"urls": []any{
			map[string]any{"filename": "markitdown_mcp-0.0.1-py3-none-any.whl", "url": r.srv.URL + "/files/markitdown_mcp-0.0.1-py3-none-any.whl", "packagetype": "bdist_wheel", "digests": map[string]string{"sha256": packaging.SHA256Hex(r.whl)}},
			map[string]any{"filename": "markitdown_mcp-0.0.1.tar.gz", "url": r.srv.URL + "/files/markitdown_mcp-0.0.1.tar.gz", "packagetype": "sdist", "digests": map[string]string{"sha256": packaging.SHA256Hex([]byte("sdist"))}},
		}})
	})
	mux.HandleFunc("/files/markitdown_mcp-0.0.1-py3-none-any.whl", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(r.whl) })
	r.srv = httptest.NewServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

type fixture struct {
	t     *testing.T
	state string
	cfg   *config.Config
	lib   *library.Library
	rec   *audit.Memory
	c     *Connector
}

func newFixture(t *testing.T, extra string) *fixture {
	t.Helper()
	state := t.TempDir()
	reg := newRegistry(t)
	cfg, err := config.Parse([]byte(fmt.Sprintf("[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g\"\n[state]\ndir = %q\n[approvals]\nnotify = \"off\"\n[contextforge]\nnpm_registry = %q\npypi_index = %q\n%s",
		state, reg.srv.URL+"/npm", reg.srv.URL+"/pypi", extra)))
	if err != nil {
		t.Fatal(err)
	}
	lib, err := library.Open(library.Options{StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lib.Close() })
	rec := &audit.Memory{}
	lib.SetRecorder(rec)
	c, err := New(Options{Config: cfg, Library: lib, Recorder: rec, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return &fixture{t: t, state: state, cfg: cfg, lib: lib, rec: rec, c: c}
}

// enroll makes the catalog import key a trust anchor, as an Administrator
// does with smcpctl trust add.
func (f *fixture) enroll() {
	f.t.Helper()
	a, err := packaging.LoadAnchors(f.state)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := a.Add("contextforge-import", f.c.pub, []string{"moderate", "high"}, time.Now().Add(time.Hour), time.Now(), "admin"); err != nil {
		f.t.Fatal(err)
	}
	if err := a.Save(); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) wait(id string) proposal {
	f.t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		p, ok := f.c.Proposal(id)
		if !ok {
			f.t.Fatalf("proposal %s gone", id)
		}
		if p.State != stateBuilding {
			return p
		}
		time.Sleep(50 * time.Millisecond)
	}
	f.t.Fatalf("proposal %s still building", id)
	return proposal{}
}

func (f *fixture) events(class string) []audit.Event {
	var out []audit.Event
	for _, e := range f.rec.Events() {
		if e.Class == class {
			out = append(out, e)
		}
	}
	return out
}

func need(t *testing.T, tool string) {
	t.Helper()
	if _, err := exec.LookPath(tool); err != nil {
		t.Skipf("%s not installed", tool)
	}
}

// FR-22.6: the markitdown and playwright-mcp entries of the pinned catalog
// imported without a version and with "latest" are refused with the
// FR-14.2 reason; with an exact version and digest the package's artifact
// is the pinned one. The install text is only read (FR-22.7).
func TestLocalImportPinned(t *testing.T) {
	reqtest.Verifies(t, "FR-22.6")
	need(t, "node")
	need(t, "python3")
	f := newFixture(t, "")
	f.enroll()
	cases := []struct {
		entry string
		base  LocalImport
		pin   func(*LocalImport, *registry)
		tool  string
	}{
		{"playwright-mcp", LocalImport{Argv: []string{"node", "node_modules/@playwright/mcp/cli.js"}, Licenses: []string{"Apache-2.0"}},
			func(in *LocalImport, r *registry) { in.Version, in.Integrity = "0.0.41", integrity(r.tgz) }, "browser_snapshot"},
		{"markitdown", LocalImport{ArtifactType: "pypi", Package: "markitdown-mcp", Argv: []string{"python3", "-m", "markitdown_mcp"}, Licenses: []string{"MIT"}},
			func(in *LocalImport, r *registry) {
				in.Version, in.ArtifactSHA256 = "0.0.1", packaging.SHA256Hex(r.whl)
			}, "convert_to_markdown"},
	}
	for _, tc := range cases {
		for _, v := range []string{"", "latest"} {
			in := tc.base
			in.Version = v
			_, err := f.c.ProposeLocal(tc.entry, in, "op")
			if packaging.ReasonOf(err) != packaging.ReasonUnpinned {
				t.Fatalf("%s version %q: %v", tc.entry, v, err)
			}
		}
	}
	// Exact pins: rebuild the digests from the fixture's own registry.
	fr := registryOf(t, f)
	for _, tc := range cases {
		in := tc.base
		tc.pin(&in, fr)
		p, err := f.c.ProposeLocal(tc.entry, in, "op")
		if err != nil {
			t.Fatalf("%s: %v", tc.entry, err)
		}
		p = f.wait(p.ID)
		if p.State != stateReady {
			t.Fatalf("%s: %s %s %s", tc.entry, p.State, p.ReasonCode, p.Error)
		}
		got, err := f.c.Decide(p.ID, true, p.Decision.SHA256, "op")
		if err != nil {
			t.Fatalf("%s accept: %v", tc.entry, err)
		}
		m, _, err := f.lib.Manifest(got.ServerID, got.Revision)
		if err != nil {
			t.Fatal(err)
		}
		// The artifact is the pinned one: the registry digest recorded in
		// the manifest is the operator's pin.
		pinned := in.Integrity
		if pinned == "" {
			pinned = "sha256:" + in.ArtifactSHA256
		}
		if m.Artifact.RegistryIntegrity != pinned {
			t.Errorf("%s: artifact registry digest %s, want the pin %s", tc.entry, m.Artifact.RegistryIntegrity, pinned)
		}
		if m.Artifact.Version != in.Version || len(m.Tools) != 1 || m.Tools[0].Name != tc.tool || m.Tools[0].SourceTrust != "untrusted" {
			t.Errorf("%s manifest %+v tools %+v", tc.entry, m.Artifact, m.Tools)
		}
	}
}

// registryOf returns the registry serving the fixture's configuration.
func registryOf(t *testing.T, f *fixture) *registry {
	t.Helper()
	resp, err := http.Get(strings.TrimSuffix(f.cfg.ContextForge.NPMRegistry, "/npm") + "/npm/@playwright/mcp/-/mcp-0.0.41.tgz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	resp2, err := http.Get(strings.TrimSuffix(f.cfg.ContextForge.PyPIIndex, "/pypi") + "/files/markitdown_mcp-0.0.1-py3-none-any.whl")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var w bytes.Buffer
	_, _ = w.ReadFrom(resp2.Body)
	return &registry{tgz: b.Bytes(), whl: w.Bytes()}
}

// FR-22.12, FR-22.13 and FR-22.14 through the Connector: a refused, an
// accepted and a declined import. The accepted package carries the
// presented decision in its signed provenance and is verified-disabled;
// the declined one leaves no package; each attempt has one catalog_import
// event and each decision one catalog_trust_decision event.
func TestTrustDecisionAndEvidence(t *testing.T) {
	reqtest.Partial(t, "FR-22.12", "FR-22.13", "FR-22.14", "FR-22.11")
	need(t, "node")
	f := newFixture(t, "")
	fr := registryOf(t, f)
	in := LocalImport{Version: "0.0.41", Integrity: integrity(fr.tgz), Argv: []string{"node", "node_modules/@playwright/mcp/cli.js"}, Licenses: []string{"Apache-2.0"}}

	// Refused: no version.
	bad := in
	bad.Version = ""
	if _, err := f.c.ProposeLocal("playwright-mcp", bad, "op"); err == nil {
		t.Fatal("unpinned import accepted")
	}

	p, err := f.c.ProposeLocal("playwright-mcp", in, "op")
	if err != nil {
		t.Fatal(err)
	}
	p = f.wait(p.ID)
	if p.State != stateReady {
		t.Fatalf("%s %s", p.State, p.Error)
	}
	fields := p.Decision.Fields
	for _, want := range []string{"Class: local", "Provider: Microsoft", "Auth type: Open", "browser_snapshot (external, untrusted)", "Risk class: moderate",
		"Egress destinations: none", "Secret slots: none", "ContextForge and IBM have not reviewed this server"} {
		if !strings.Contains(p.Decision.Text, want) {
			t.Errorf("decision text lacks %q:\n%s", want, p.Decision.Text)
		}
	}
	if fields.Class != "local" || fields.RiskClass != "moderate" || len(fields.Tools) != 1 {
		t.Fatalf("fields %+v", fields)
	}
	// A wrong digest and an unenrolled key leave the proposal waiting.
	var de *DecisionError
	if _, err := f.c.Decide(p.ID, true, strings.Repeat("0", 64), "op"); !errors.As(err, &de) || de.Code != ReasonDecisionMismatch {
		t.Fatalf("wrong digest: %v", err)
	}
	if _, err := f.c.Decide(p.ID, true, p.Decision.SHA256, "op"); !errors.As(err, &de) || de.Code != ReasonImportKeyUnenrolled {
		t.Fatalf("unenrolled key: %v", err)
	}
	f.enroll()
	got, err := f.c.Decide(p.ID, true, p.Decision.SHA256, "op")
	if err != nil || got.Outcome != "imported" {
		t.Fatalf("accept: %v %+v", err, got)
	}
	rev, ok := f.lib.Get(got.ServerID, got.Revision)
	if !ok || rev.State != library.StateVerifiedDisabled || !strings.HasSuffix(got.Revision, "+cf.1") {
		t.Fatalf("revision %+v", rev)
	}
	raw, err := os.ReadFile(filepath.Join(f.lib.Dir(), got.ServerID, got.Revision, packaging.ProvenanceFile))
	if err != nil {
		t.Fatal(err)
	}
	var pv packaging.Provenance
	if err := json.Unmarshal(raw, &pv); err != nil {
		t.Fatal(err)
	}
	cat, _ := contextforge.PinnedCatalog()
	e := cat.Entry("playwright-mcp")
	if pv.TrustDecision == nil || pv.TrustDecision.Actor != "op" || pv.TrustDecision.PresentedSHA256 != p.Decision.SHA256 || pv.TrustDecision.Text != p.Decision.Text {
		t.Fatalf("trust decision %+v", pv.TrustDecision)
	}
	if o := pv.ContextForge; o == nil || o.CatalogSHA256 != cat.SHA256 || o.ContextForgeRelease != "v1.0.11" || o.EntryID != e.ID || o.EntrySHA256 != e.SHA256() ||
		o.Install != e.Install || o.Repo != e.Repo || o.URL != e.URL {
		t.Fatalf("contextforge provenance %+v", pv.ContextForge)
	}
	if st := f.c.stateOf(e); st.State != "imported" || len(st.Revisions) != 1 {
		t.Fatalf("import state %+v", st)
	}

	// Declined: no package, no new revision.
	p2, err := f.c.ProposeLocal("playwright-mcp", in, "op")
	if err != nil {
		t.Fatal(err)
	}
	p2 = f.wait(p2.ID)
	if _, err := f.c.Decide(p2.ID, false, "", "op2"); err != nil {
		t.Fatal(err)
	}
	if n := len(f.lib.Revisions()); n != 1 {
		t.Fatalf("%d revisions after a decline", n)
	}
	if _, err := os.Stat(filepath.Join(f.c.dir, stagingDir, p2.ID)); !os.IsNotExist(err) {
		t.Fatalf("declined package left in staging: %v", err)
	}

	imports := f.events(ClassImport)
	outcomes := []string{}
	for _, ev := range imports {
		outcomes = append(outcomes, ev.Outcome)
		d := ev.Detail.(map[string]any)
		for _, k := range []string{"entry_id", "entry_sha256", "class", "catalog_sha256", "actor", "outcome"} {
			if d[k] == nil || d[k] == "" {
				t.Errorf("%s event lacks %s: %v", ev.Outcome, k, d)
			}
		}
		if ev.Outcome == "imported" && (d["server_id"] != got.ServerID || d["revision"] != got.Revision || ev.ServerRevision != got.ServerID+"@"+got.Revision) {
			t.Errorf("imported event %v", d)
		}
		if ev.Outcome == "refused" && ev.ReasonCode != packaging.ReasonUnpinned {
			t.Errorf("refused event reason %q", ev.ReasonCode)
		}
	}
	if strings.Join(outcomes, ",") != "refused,imported,declined" {
		t.Fatalf("catalog_import outcomes %v", outcomes)
	}
	decisions := f.events(ClassTrustDecision)
	if len(decisions) != 2 || decisions[0].Outcome != "accepted" || decisions[1].Outcome != "declined" {
		t.Fatalf("trust decision events %+v", decisions)
	}
}

// FR-22.22 (part): with [contextforge] bundled false (the default) a hosted
// import is refused with CONTEXTFORGE_DISABLED and a local import is not.
// Unsupported entries are refused with their reasons.
func TestHostedImportNeedsBundledInstance(t *testing.T) {
	reqtest.Partial(t, "FR-22.22")
	f := newFixture(t, "")
	if f.cfg.ContextForge.Bundled {
		t.Fatal("bundled defaults to true")
	}
	_, err := f.c.ProposeLocal("deepwiki", LocalImport{}, "op")
	if packaging.ReasonOf(err) != contextforge.ReasonContextForgeDisabled {
		t.Fatalf("hosted import: %v", err)
	}
	_, err = f.c.ProposeLocal("asana", LocalImport{}, "op")
	if packaging.ReasonOf(err) != ReasonEntryUnsupported || !strings.Contains(err.Error(), "OAuth 2.1") {
		t.Fatalf("unsupported import: %v", err)
	}
	ev := f.events(ClassImport)
	if len(ev) != 2 || ev[0].ReasonCode != contextforge.ReasonContextForgeDisabled {
		t.Fatalf("events %+v", ev)
	}
}

// FR-22.16 (part): when the catalog in use changes an imported entry's
// digest, the entry is marked changed.
func TestChangedEntry(t *testing.T) {
	reqtest.Partial(t, "FR-22.16")
	f := newFixture(t, "")
	cat, _ := contextforge.PinnedCatalog()
	e := cat.Entry("playwright-mcp")
	f.c.mu.Lock()
	_ = f.c.imports.add(importRecord{EntryID: e.ID, EntrySHA256: e.SHA256(), CatalogSHA256: cat.SHA256, Class: "local", ServerID: "playwright-mcp", Revision: "1+cf.1"})
	f.c.mu.Unlock()
	if st := f.c.stateOf(e); st.State != "imported" {
		t.Fatalf("state %+v", st)
	}
	// An operator catalog in which the entry's URL and description differ.
	op := []byte("catalog_servers:\n  - id: playwright-mcp\n    name: Playwright\n    provider: Microsoft\n    auth_type: Open\n    url: https://changed.example/mcp\n    description: changed\n    repo: https://github.com/microsoft/playwright-mcp\n    install: npx @playwright/mcp@latest\n")
	file := filepath.Join(t.TempDir(), "c.yml")
	if err := os.WriteFile(file, op, 0o600); err != nil {
		t.Fatal(err)
	}
	f.cfg.ContextForge.CatalogFile, f.cfg.ContextForge.CatalogSHA256 = file, packaging.SHA256Hex(op)
	c2, err := New(Options{Config: f.cfg, Library: f.lib, Recorder: f.rec})
	if err != nil {
		t.Fatal(err)
	}
	list, err := c2.List(Filter{Query: "playwright"})
	if err != nil || len(list) != 1 || list[0].State != "changed" {
		t.Fatalf("list %+v %v", list, err)
	}
}

// FR-22.1 (part) in the Connector: a configured operator catalog with a
// wrong confirmed digest is refused and reported, and the Gateway keeps
// running without a catalog.
func TestConfiguredCatalogRefused(t *testing.T) {
	reqtest.Partial(t, "FR-22.1")
	file := filepath.Join(t.TempDir(), "c.yml")
	if err := os.WriteFile(file, []byte("catalog_servers: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, fmt.Sprintf("catalog_file = %q\ncatalog_sha256 = %q\n", file, strings.Repeat("a", 64)))
	st := f.c.Status()
	if st.CatalogReason != contextforge.ReasonCatalogDigestMismatch || st.CatalogEntries != 0 {
		t.Fatalf("status %+v", st)
	}
	if _, err := f.c.List(Filter{}); packaging.ReasonOf(err) != contextforge.ReasonCatalogDigestMismatch {
		t.Fatalf("list: %v", err)
	}
}

// FR-22.4 (part): filters by class, category and auth type and a text
// search.
func TestListFilters(t *testing.T) {
	reqtest.Partial(t, "FR-22.4")
	f := newFixture(t, "")
	all, _ := f.c.List(Filter{})
	if len(all) != 135 {
		t.Fatalf("%d entries", len(all))
	}
	local, _ := f.c.List(Filter{Class: "local"})
	if len(local) != 4 {
		t.Fatalf("%d local", len(local))
	}
	open, _ := f.c.List(Filter{Class: "hosted", AuthType: "open"})
	if len(open) != 26 {
		t.Fatalf("%d hosted Open", len(open))
	}
	q, _ := f.c.List(Filter{Query: "DEEPWIKI"})
	if len(q) != 1 || q[0].ID != "deepwiki" || q[0].State != "not_imported" {
		t.Fatalf("search %+v", q)
	}
	cat, _ := f.c.List(Filter{Category: q[0].Category})
	if len(cat) == 0 {
		t.Fatal("category filter found nothing")
	}
}
