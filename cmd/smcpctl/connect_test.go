package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestConnectIsClientsSetupAlias: `smcpctl connect` behaves exactly like
// `smcpctl clients setup` (FR-15.11): the same dry-run output and exit
// status, the same files written and restored, the same error for an
// unknown client, and the alias is listed in the usage text.
func TestConnectIsClientsSetupAlias(t *testing.T) {
	reqtest.Verifies(t, "FR-15.11")
	g := gwtest.Start(t, "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SMCP_HARNESS_ROOT", t.TempDir())

	setupCode, setupOut, setupErr := rctl(t, "clients", "setup", "claude-code", "--config", g.CfgPath, "--dry-run", "--no-lockdown")
	connCode, connOut, connErr := rctl(t, "connect", "claude-code", "--config", g.CfgPath, "--dry-run", "--no-lockdown")
	if setupCode != 0 || !strings.Contains(setupOut, "dry run") {
		t.Fatalf("clients setup dry run: %d %s %s", setupCode, setupOut, setupErr)
	}
	if connCode != setupCode || connOut != setupOut || connErr != setupErr {
		t.Fatalf("connect differs from clients setup:\nconnect (%d):\n%s%s\nclients setup (%d):\n%s%s", connCode, connOut, connErr, setupCode, setupOut, setupErr)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude.json")); err == nil {
		t.Fatal("dry run wrote files")
	}

	orig := []byte(`{"theme":"dark"}`)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := rctl(t, "connect", "claude-code", "--config", g.CfgPath, "--no-lockdown"); code != 0 {
		t.Fatalf("connect: %s %s", out, errs)
	}
	b, _ := os.ReadFile(filepath.Join(home, ".claude.json"))
	if !strings.Contains(string(b), g.MCPURL()) || !strings.Contains(string(b), "dark") {
		t.Fatalf("claude.json after connect: %s", b)
	}
	if code, out, errs := rctl(t, "connect", "claude-code", "--config", g.CfgPath, "--remove"); code != 0 {
		t.Fatalf("connect --remove: %s %s", out, errs)
	}
	b, _ = os.ReadFile(filepath.Join(home, ".claude.json"))
	if !bytes.Equal(b, orig) {
		t.Fatalf("not restored: %s", b)
	}

	c1, o1, e1 := rctl(t, "clients", "setup", "no-such-client", "--config", g.CfgPath)
	c2, o2, e2 := rctl(t, "connect", "no-such-client", "--config", g.CfgPath)
	if c1 == 0 || c1 != c2 || o1 != o2 || e1 != e2 || !strings.Contains(e2, "unknown client") {
		t.Fatalf("unknown client: setup %d %q %q, connect %d %q %q", c1, o1, e1, c2, o2, e2)
	}
	if !strings.Contains(usage, "connect ") || !strings.Contains(clientsUsage, "smcpctl connect") {
		t.Fatal("connect is not in the usage text")
	}
}
