package app

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

// TestPublishClientView: smcpd publishes the client view of an Enforced
// configuration next to its state directory, logs (and survives) a missing
// directory, and publishes nothing for the Standalone profile.
func TestPublishClientView(t *testing.T) {
	base := t.TempDir()
	cfg := &config.Config{}
	cfg.State.Dir = filepath.Join(base, "state")
	cfg.Listener.Address = "127.0.0.1:8443"
	cfg.Listener.PublicURL = "https://127.0.0.1:8443"
	cfg.Listener.MCPPath = "/mcp"
	cfg.AdminListener.Address = "127.0.0.1:8444"
	if err := keys.Ensure(cfg.State.Dir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	pub := filepath.Join(base, config.PublicDirName)

	cfg.Profile.Mode = "standalone"
	PublishClientView(cfg, log)
	if _, err := os.Stat(pub); err == nil || logs.Len() != 0 {
		t.Fatalf("standalone published a client view: %s", logs.String())
	}

	cfg.Profile.Mode = "enforced"
	PublishClientView(cfg, log)
	if !strings.Contains(logs.String(), "client view not published") {
		t.Fatalf("missing directory not reported: %s", logs.String())
	}
	if err := os.Mkdir(pub, 0o755); err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	PublishClientView(cfg, log)
	if !strings.Contains(logs.String(), "client view published") {
		t.Fatalf("log: %s", logs.String())
	}
	v, err := config.LoadClientView(pub)
	if err != nil {
		t.Fatal(err)
	}
	if v.MCPURL != "https://127.0.0.1:8443/mcp" || v.AdminURL != "https://127.0.0.1:8444" || v.CAFile != filepath.Join(pub, config.PublicCAFile) {
		t.Fatalf("view %+v", v)
	}
	logs.Reset()
	PublishClientView(cfg, log)
	if logs.Len() != 0 {
		t.Fatalf("an unchanged view was written again: %s", logs.String())
	}
}
