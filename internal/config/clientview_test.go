package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientViewPublicDir(t *testing.T) {
	c := &Config{}
	c.State.Dir = "/var/lib/smcp/state"
	for _, mode := range []string{"", "standalone", "auto"} {
		c.Profile.Mode = mode
		if d := c.PublicDir(); d != "" {
			t.Fatalf("profile %q publishes a client view in %s", mode, d)
		}
	}
	c.Profile.Mode = "enforced"
	if d := c.PublicDir(); d != filepath.Join("/var/lib/smcp", "public") {
		t.Fatalf("enforced public dir %q", d)
	}
}

func TestClientViewRoundTrip(t *testing.T) {
	c := &Config{}
	c.Profile.Mode = "enforced"
	c.State.Dir = "/var/lib/smcp/state"
	c.Listener.Address = "127.0.0.1:8443"
	c.Listener.PublicURL = "https://127.0.0.1:8443"
	c.Listener.MCPPath = "/mcp"
	c.AdminListener.Address = "127.0.0.1:8444"
	c.Metrics.Enabled = true
	c.Metrics.Address = "127.0.0.1:9464"
	c.Admin.PasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"
	dir := filepath.Join(t.TempDir(), PublicDirName)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	v := c.ClientView(dir)
	if v.MCPURL != "https://127.0.0.1:8443/mcp" || v.AdminURL != "https://127.0.0.1:8444" || v.MetricsAddress != "127.0.0.1:9464" ||
		v.CAFile != filepath.Join(dir, PublicCAFile) {
		t.Fatalf("view %+v", v)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "argon2") {
		t.Fatalf("the client view carries the password hash: %s", b)
	}
	if err := os.WriteFile(filepath.Join(dir, ClientViewFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadClientView(dir)
	if err != nil {
		t.Fatal(err)
	}
	gc := got.Config(dir)
	if gc.ResourceURI() != c.ResourceURI() || gc.Profile.Mode != "enforced" || gc.Listener.Address != c.Listener.Address {
		t.Fatalf("config from the view: %+v", gc)
	}
	if gc.PublicDir() != filepath.Clean(dir) {
		t.Fatalf("the view's configuration finds its public dir at %q, not %q", gc.PublicDir(), dir)
	}

	for _, bad := range []string{`{}`, `{"mcp_url":"https://x/mcp","listener_address":"127.0.0.1:1","ca_file":"rel/ca.crt"}`, `not json`} {
		if err := os.WriteFile(filepath.Join(dir, ClientViewFile), []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadClientView(dir); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
