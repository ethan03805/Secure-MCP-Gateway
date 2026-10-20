package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/contextforge/bundle"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// FR-22.44 (terminal part): the setup question defaults to no and states
// what the bundled instance adds and its risk; only "y" or "yes" enables.
func TestContextForgeChoice(t *testing.T) {
	reqtest.Partial(t, "FR-22.44")
	for in, want := range map[string]bool{"y\n": true, "YES\n": true, "\n": false, "n\n": false, "": false, "maybe\n": false} {
		var out bytes.Buffer
		if got := askContextForge(strings.NewReader(in), &out); got != want {
			t.Errorf("answer %q: %v", in, got)
		}
		for _, line := range []string{"Adds: hosted servers from the IBM ContextForge catalog, reached only through the Gateway.",
			"Risk: a large third-party service runs on this host, and the code of hosted servers cannot be inspected.", "[y/N]"} {
			if !strings.Contains(out.String(), line) {
				t.Errorf("the question lacks %q", line)
			}
		}
	}
}

// FR-22.22 and FR-22.44 (bootstrap part): without the choice, bootstrap
// writes [contextforge] bundled = false and fetches nothing; with
// --with-contextforge it writes true and fetches the pinned image.
func TestBootstrapContextForgeChoice(t *testing.T) {
	reqtest.Partial(t, "FR-22.22", "FR-22.44")
	var pulled []string
	old := pullImage
	pullImage = func(_ context.Context, _ bundle.Engine, ref string) error { pulled = append(pulled, ref); return nil }
	t.Cleanup(func() { pullImage = old })
	oldTerm := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = oldTerm })
	secrets := t.TempDir()
	for _, choice := range []string{"", "yes"} {
		dir := t.TempDir()
		o := bootstrapOpts{dir: dir, adminFile: writeFile(t, secrets, "a", "admin password 12\n"), approverFile: writeFile(t, secrets, "p", "approver password 1\n"),
			refserver: filepath.Join(binDir, "smcp-refserver"), port: 18443, adminPort: 18444, metricsPort: 0, notify: "off", contextforge: choice, quiet: true}
		var out bytes.Buffer
		if _, err := runBootstrap(o, &out); err != nil {
			t.Fatalf("%q: %v", choice, err)
		}
		cfg, err := config.Load(filepath.Join(dir, "smcp.toml"))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(filepath.Join(dir, "smcp.toml"))
		if cfg.ContextForge.Bundled != (choice == "yes") || !strings.Contains(string(raw), "[contextforge]") {
			t.Fatalf("%q: bundled %v", choice, cfg.ContextForge.Bundled)
		}
		if choice == "" && len(pulled) != 0 {
			t.Fatalf("declined, yet fetched %v", pulled)
		}
	}
	if _, err := bundle.FindEngine(); err == nil && (len(pulled) != 1 || !strings.Contains(pulled[0], "@sha256:")) {
		t.Fatalf("accepted: pulled %v", pulled)
	}
}
