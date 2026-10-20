package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

// TestConnectEnforcedClientView: on an Enforced host /etc/smcp/smcp.toml
// (root:smcp 0640) is not readable by the user who runs the clients, so
// `smcpctl connect --config /etc/smcp/smcp.toml` reads the client view the
// Gateway publishes in CP-46 public/ and points the client at the published
// CA certificate, which that user can read. Without the view it fails and
// names the remedy.
func TestConnectEnforcedClientView(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not stop reads on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0000 file")
	}
	g := gwtest.Start(t, "")
	root := t.TempDir()
	hostRoot = root
	t.Cleanup(func() { hostRoot = "" })
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SMCP_HARNESS_ROOT", t.TempDir())

	cfgPath := filepath.Join(root, "etc", "smcp", "smcp.toml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("# not readable\n"), 0o000); err != nil {
		t.Fatal(err)
	}

	code, out, errs := rctl(t, "connect", "claude-code", "--config", cfgPath, "--dry-run", "--json", "--no-lockdown")
	if code == 0 || !strings.Contains(errs, "client view") || !strings.Contains(errs, "smcpctl install --profile enforced") {
		t.Fatalf("without a client view: %d %s %s", code, out, errs)
	}

	pub := filepath.Join(root, config.EnforcedPublicDir)
	if err := os.MkdirAll(pub, 0o755); err != nil {
		t.Fatal(err)
	}
	view := g.Config.ClientView(pub)
	view.Profile = "enforced"
	if _, err := keys.PublishPublic(g.Config.State.Dir, pub, view); err != nil {
		t.Fatal(err)
	}
	code, out, errs = rctl(t, "connect", "claude-code", "--config", cfgPath, "--dry-run", "--json", "--no-lockdown")
	if code != 0 {
		t.Fatalf("with the client view: %d %s %s", code, out, errs)
	}
	if !json.Valid([]byte(out)) {
		t.Fatalf("dry-run output is not JSON:\n%s", out)
	}
	caPath := filepath.Join(pub, config.PublicCAFile)
	if !strings.Contains(out, g.MCPURL()) || !strings.Contains(out, caPath) {
		t.Fatalf("the plan does not name the MCP endpoint %s and the published CA %s:\n%s", g.MCPURL(), caPath, out)
	}
	if strings.Contains(out, filepath.Join(g.Config.State.Dir, keys.CACertFile)) {
		t.Fatalf("the plan names the state directory's CA, which the user cannot read:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude.json")); err == nil {
		t.Fatal("dry run wrote files")
	}
}
