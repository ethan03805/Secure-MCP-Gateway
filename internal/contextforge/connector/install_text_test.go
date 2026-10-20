package connector

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestInstallTextNeverRuns is FR-22.7: two entries of an operator
// catalog, one whose install text is "npx x; touch <marker>" and one that
// names an npm package whose preinstall, install and postinstall scripts
// write a marker file. With shims for every shell and package manager
// placed first on PATH (each records that it ran), the first import is
// refused before anything runs, the second fetches the operator-pinned
// tarball (FR-14.1), probes the server inside it and is accepted; neither
// marker exists, no shim ran, and the proposals show the install texts
// verbatim.
func TestInstallTextNeverRuns(t *testing.T) {
	reqtest.Verifies(t, "FR-22.7")
	need(t, "node")
	f := newFixture(t, "")
	f.enroll()
	dir := t.TempDir()
	shellMarker, pkgMarker, ran := filepath.Join(dir, "pwned-shell"), filepath.Join(dir, "pwned-install"), filepath.Join(dir, "ran.log")
	shims := filepath.Join(dir, "shims")
	if err := os.MkdirAll(shims, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"sh", "bash", "dash", "zsh", "npm", "npx", "pnpm", "pnpx", "yarn", "bun", "bunx", "uv", "uvx", "pip", "pip3", "pipx", "touch"} {
		shim := fmt.Sprintf("#!/bin/sh\necho %s >> %s\n", n, ran)
		if err := os.WriteFile(filepath.Join(shims, n), []byte(shim), 0o755); err != nil { // #nosec G306 -- an executable shim of the test
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", shims+string(os.PathListSeparator)+os.Getenv("PATH"))

	write := fmt.Sprintf("require('fs').writeFileSync(%q, 'x')", pkgMarker)
	pkgJSON := fmt.Sprintf(`{"name":"@smcp/marker-mcp","version":"1.0.0","scripts":{"preinstall":"node -e \"%[1]s\"","install":"node -e \"%[1]s\"","postinstall":"node -e \"%[1]s\""}}`,
		strings.ReplaceAll(write, `"`, `\"`))
	tarball := tgz(t, map[string]string{"package/package.json": pkgJSON, "package/cli.js": jsServer})
	mux := http.NewServeMux()
	mux.HandleFunc("/npm/@smcp/marker-mcp/-/marker-mcp-1.0.0.tgz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tarball) })
	reg := httptest.NewServer(mux)
	t.Cleanup(reg.Close)

	catalog := fmt.Sprintf(`catalog_servers:
  - id: shell-x
    name: Shell
    provider: Example
    auth_type: Open
    repo: https://example.com/shell-x
    install: "npx x; touch %s"
  - id: marker-pkg
    name: Marker
    provider: Example
    auth_type: Open
    repo: https://example.com/marker
    install: "npx @smcp/marker-mcp"
`, shellMarker)
	file := filepath.Join(dir, "catalog.yml")
	if err := os.WriteFile(file, []byte(catalog), 0o600); err != nil {
		t.Fatal(err)
	}
	f.cfg.ContextForge.CatalogFile, f.cfg.ContextForge.CatalogSHA256 = file, packaging.SHA256Hex([]byte(catalog))
	f.cfg.ContextForge.NPMRegistry = reg.URL + "/npm"
	c, err := New(Options{Config: f.cfg, Library: f.lib, Recorder: f.rec, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)

	// The shell-bearing text: no artifact can be proposed from it, so the
	// import needs an operator-named artifact and is refused without one.
	list, err := c.List(Filter{Query: "shell-x"})
	if err != nil || len(list) != 1 || list[0].Install != "npx x; touch "+shellMarker {
		t.Fatalf("shell-x shown as %+v (%v)", list, err)
	}
	if _, err := c.ProposeLocal("shell-x", LocalImport{Version: "1.0.0", Integrity: integrity(tarball), Argv: []string{"node", "cli.js"}, Licenses: []string{"MIT"}}, "op"); packaging.ReasonOf(err) != packaging.ReasonUnpinned {
		t.Fatalf("shell-x import: %v", err)
	}
	// The package with install scripts, pinned by the operator.
	p, err := c.ProposeLocal("marker-pkg", LocalImport{Version: "1.0.0", Integrity: integrity(tarball), Argv: []string{"node", "node_modules/@smcp/marker-mcp/cli.js"}, Licenses: []string{"MIT"}}, "op")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for p.State == stateBuilding && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		p, _ = c.Proposal(p.ID)
	}
	if p.State != stateReady {
		t.Fatalf("marker-pkg: %s %s %s", p.State, p.ReasonCode, p.Error)
	}
	got, err := c.Decide(p.ID, true, p.Decision.SHA256, "op")
	if err != nil || got.Outcome != "imported" {
		t.Fatalf("accept: %v %+v", err, got)
	}
	if list, _ := c.List(Filter{Query: "marker-pkg"}); len(list) != 1 || list[0].Install != "npx @smcp/marker-mcp" {
		t.Fatalf("marker-pkg shown as %+v", list)
	}
	for _, m := range []string{shellMarker, pkgMarker} {
		if _, err := os.Stat(m); !os.IsNotExist(err) {
			t.Fatalf("marker %s exists (%v)", m, err)
		}
	}
	if raw, err := os.ReadFile(ran); err == nil {
		t.Fatalf("a shell or package manager ran: %s", raw)
	}
}
