package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/consoleauth"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/connector"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const cfJSServer = `const rl = require('readline').createInterface({input: process.stdin});
const send = (m) => process.stdout.write(JSON.stringify(m) + "\n");
rl.on('line', (l) => {
  let m; try { m = JSON.parse(l); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === 'initialize') return send({jsonrpc: '2.0', id: m.id, result: {protocolVersion: '2025-11-25', capabilities: {tools: {}}, serverInfo: {name: 'pw', version: '1'}}});
  if (m.method === 'tools/list') return send({jsonrpc: '2.0', id: m.id, result: {tools: [{name: 'browser_snapshot', description: 'Take a snapshot.', inputSchema: {type: 'object'}}]}});
  send({jsonrpc: '2.0', id: m.id, error: {code: -32601, message: 'method not found'}});
});
`

type cfGateway struct {
	cfgPath string
	cfg     *config.Config
	state   string
	tgz     []byte
	mu      sync.Mutex
	events  []audit.Event
}

func (g *cfGateway) Observe(e audit.Event) {
	g.mu.Lock()
	g.events = append(g.events, e)
	g.mu.Unlock()
}

func (g *cfGateway) has(class, reason string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, e := range g.events {
		if e.Class == class && (reason == "" || e.ReasonCode == reason) {
			return true
		}
	}
	return false
}

// startCFGateway runs a Gateway in process with the ContextForge Connector
// wired as cmd/smcpd wires it, an npm registry serving @playwright/mcp
// 0.0.41, and an Auditor console account.
func startCFGateway(t *testing.T) *cfGateway {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct{ name, body string }{{"package/cli.js", cfJSServer}, {"package/package.json", `{"name":"@playwright/mcp","version":"0.0.41"}`}} {
		_ = tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(f.body))
	}
	_ = tw.Close()
	_ = gz.Close()
	g := &cfGateway{tgz: buf.Bytes()}
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/npm/@playwright/mcp/-/mcp-0.0.41.tgz" {
			_, _ = w.Write(g.tgz)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(reg.Close)

	dir := t.TempDir()
	g.state = filepath.Join(dir, "state")
	if err := keys.Ensure(g.state, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	hash := func(pw string) string {
		h, err := keys.HashPassword(pw)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	writeFile(t, dir, "policy.json", `{"revision":"r1","framework_profiles":{"dev":{"templates":["ro"],"default_template":"ro"}},"templates":{"ro":{"rules":[]}}}`)
	g.cfgPath = writeFile(t, dir, "smcp.toml", fmt.Sprintf(`
[listener]
address = "127.0.0.1:%s"
[admin_listener]
address = "127.0.0.1:%s"
[state]
dir = %q
[admin]
username = "admin"
password_hash = %q
[approvals]
notify = "off"
[[console.account]]
username = "aud"
password_hash = %q
role = "auditor"
[policy]
file = "policy.json"
[contextforge]
npm_registry = %q
`, freePort(t), freePort(t), g.state, hash("admin password 12"), hash("auditor password 12"), reg.URL+"/npm"))
	cfg, err := config.Load(g.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g.cfg = cfg
	pkgs, err := library.OpenRuntime(cfg, diag.Discard())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, cfg, app.Options{Log: diag.Discard(), Packages: pkgs})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	consoleauth.New(consoleauth.Options{Config: cfg, Evidence: a.Evidence, Log: diag.Discard()}).Register(a.Admin)
	cf, err := connector.New(connector.Options{Config: cfg, Library: pkgs.Library(), Recorder: a.Evidence, Version: "test"})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cf.RegisterRoutes(a.Admin)
	a.Evidence.AddObserver("catalog-cli-test", g, 0)
	if err := a.Listen(); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done; cf.Close(); a.Close() })
	return g
}

// FR-22.5 (part): list, show and import through the control API with the
// operator credential, and the Auditor's import refused with
// ADMIN_ROLE_REFUSED while the Auditor may list. Not covered: the same
// actions through G-15, and hosted entries.
func TestCatalogCLIThroughGateway(t *testing.T) {
	reqtest.Partial(t, "FR-22.5")
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	g := startCFGateway(t)
	cfg := []string{"--config", g.cfgPath}

	out, stderr, code := runCatalog(t, append([]string{"status", "--json"}, cfg...)...)
	if code != 0 {
		t.Fatalf("status: %d %s", code, stderr)
	}
	var st connector.Status
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.Bundled || st.ImportKey.Enrolled || st.CatalogRelease != "v1.0.11" {
		t.Fatalf("status %+v %v", st, err)
	}
	// The Administrator enrolls the catalog import key once.
	a, err := packaging.LoadAnchors(g.state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add("contextforge-import", []byte(st.ImportKey.PublicKey), []string{"moderate", "high"}, time.Now().Add(time.Hour), time.Now(), "admin"); err != nil {
		t.Fatal(err)
	}
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}

	out, stderr, code = runCatalog(t, append([]string{"list", "--class", "local"}, cfg...)...)
	if code != 0 || !strings.Contains(out, "4 of 135 entries") || !regexp.MustCompile(`playwright-mcp\s+local\s+Open\s+not_imported`).MatchString(out) {
		t.Fatalf("list: %d %s\n%s", code, stderr, out)
	}

	s := sha512.Sum512(g.tgz)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(s[:])
	out, stderr, code = runCatalog(t, append([]string{"import", "playwright-mcp", "--version", "0.0.41", "--integrity", integrity,
		"--argv", "node", "--argv", "node_modules/@playwright/mcp/cli.js", "--license", "Apache-2.0"}, cfg...)...)
	if code != 0 {
		t.Fatalf("import: %d %s\n%s", code, stderr, out)
	}
	m := regexp.MustCompile(`smcpctl catalog decide ([0-9a-f]+) --accept ([0-9a-f]{64})`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "Tools (1): browser_snapshot (external, untrusted)") {
		t.Fatalf("import output:\n%s", out)
	}
	out, stderr, code = runCatalog(t, append([]string{"decide", m[1], "--accept", m[2]}, cfg...)...)
	if code != 0 || !strings.Contains(out, "imported playwright-mcp@0.0.41+cf.1 as verified-disabled") {
		t.Fatalf("decide: %d %s\n%s", code, stderr, out)
	}
	out, _, _ = runCatalog(t, append([]string{"list", "--query", "playwright"}, cfg...)...)
	if !regexp.MustCompile(`playwright-mcp\s+local\s+Open\s+imported`).MatchString(out) {
		t.Fatalf("list after import:\n%s", out)
	}
	if !g.has(connector.ClassImport, "") || !g.has(connector.ClassTrustDecision, "") {
		t.Fatal("import evidence missing")
	}

	// The Auditor lists but cannot import.
	tok := consoleToken(t, g.cfg, "aud", "auditor password 12", "auditor")
	if st, body := rawAdmin(t, g.cfg, tok, http.MethodGet, "/api/v1/contextforge/catalog?class=local"); st != http.StatusOK || !strings.Contains(body, "playwright-mcp") {
		t.Fatalf("auditor list: %d %s", st, body)
	}
	if st, body := rawAdmin(t, g.cfg, tok, http.MethodPost, "/api/v1/contextforge/catalog/markitdown/import"); st != http.StatusForbidden {
		t.Fatalf("auditor import: %d %s", st, body)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !g.has("auth_failure", "ADMIN_ROLE_REFUSED") {
		if time.Now().After(deadline) {
			t.Fatal("no ADMIN_ROLE_REFUSED evidence for the Auditor's import")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
