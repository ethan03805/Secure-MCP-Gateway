package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestClientsDetectAndJSONDryRun: the two machine-readable forms the
// desktop client setup reads (FR-20.10). `clients detect --json` lists every
// supported client with whether it is installed and set up, and changes
// nothing; `setup --dry-run --json` gives the same changes as the text dry
// run, writes nothing, and the setup state follows apply and --remove.
func TestClientsDetectAndJSONDryRun(t *testing.T) {
	reqtest.Partial(t, "FR-20.10")
	g := gwtest.Start(t, "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir()) // no client binary is found on PATH
	t.Setenv("SMCP_HARNESS_ROOT", t.TempDir())

	detect := func() map[string]detectedClient {
		t.Helper()
		code, out, errs := rctl(t, "clients", "detect", "--json")
		if code != 0 {
			t.Fatalf("detect: %s %s", out, errs)
		}
		var r struct {
			Clients []detectedClient `json:"clients"`
		}
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("detect output: %v\n%s", err, out)
		}
		m := map[string]detectedClient{}
		for _, c := range r.Clients {
			m[c.ID] = c
		}
		return m
	}
	d := detect()
	if len(d) != 7 || d["claude-code"].Name != "Claude Code" || d["claude-code"].Installed || d["codex"].Installed {
		t.Fatalf("detect on an empty home: %+v", d)
	}
	if !d["claude-code"].LockdownAvailable {
		t.Fatal("Claude Code has a lockdown mechanism")
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("detect wrote %v", entries)
	}

	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	d = detect()
	if !d["claude-code"].Installed || !d["codex"].Installed || d["gemini-cli"].Installed || d["claude-code"].Connected {
		t.Fatalf("detect with Claude Code and Codex: %+v", d)
	}

	code, out, errs := rctl(t, "clients", "setup", "claude-code", "--config", g.CfgPath, "--dry-run", "--json")
	if code != 0 {
		t.Fatalf("dry run json: %s %s", out, errs)
	}
	var plan dryRunJSON
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if plan.Client != "claude-code" || plan.Lockdown == nil || len(plan.Setup.Changes) == 0 {
		t.Fatalf("plan: %+v", plan)
	}
	var claude *changeJSON
	for i, c := range plan.Setup.Changes {
		if c.Path == filepath.Join(home, ".claude.json") {
			claude = &plan.Setup.Changes[i]
		}
	}
	if claude == nil || claude.Action != "update" || !strings.Contains(claude.Content, g.MCPURL()) || !strings.Contains(claude.Content, "dark") {
		t.Fatalf("claude.json change: %+v", claude)
	}
	// The same paths as the text dry run.
	_, text, _ := rctl(t, "clients", "setup", "claude-code", "--config", g.CfgPath, "--dry-run")
	for _, c := range plan.Setup.Changes {
		if !strings.Contains(text, c.Path) {
			t.Fatalf("text dry run lacks %s", c.Path)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(home, ".claude.json")); string(b) != `{"theme":"dark"}` {
		t.Fatalf("dry run wrote %s", b)
	}
	_, out, _ = rctl(t, "clients", "setup", "claude-code", "--config", g.CfgPath, "--dry-run", "--json", "--no-lockdown")
	if strings.Contains(out, `"lockdown": {`) {
		t.Fatalf("--no-lockdown still plans a lockdown: %s", out)
	}
	if c, _, e := rctl(t, "clients", "setup", "claude-code", "--config", g.CfgPath, "--json"); c == 0 || !strings.Contains(e, "--json needs --dry-run") {
		t.Fatalf("--json without --dry-run: %d %s", c, e)
	}

	if c, o, e := rctl(t, "clients", "setup", "claude-code", "--config", g.CfgPath, "--no-lockdown"); c != 0 {
		t.Fatalf("setup: %s %s", o, e)
	}
	if d := detect(); !d["claude-code"].Connected || d["claude-code"].Lockdown {
		t.Fatalf("after setup: %+v", d["claude-code"])
	}
	if c, o, e := rctl(t, "clients", "setup", "claude-code", "--config", g.CfgPath, "--remove"); c != 0 {
		t.Fatalf("remove: %s %s", o, e)
	}
	if d := detect(); d["claude-code"].Connected {
		t.Fatalf("after remove: %+v", d["claude-code"])
	}
}
