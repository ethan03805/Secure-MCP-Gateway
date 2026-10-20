//go:build windows

package harness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestWindowsClientSetupOnHost: on a Windows runner, clients setup and
// lockdown write each local client's files at the Windows paths of
// docs/clients/matrix.json (below a temporary user profile, and the
// system-wide paths below a temporary root), doctor then finds the
// Gateway configured for the client, remove restores every file, and a
// client without a Windows entry is refused as unsupported on windows
// (FR-21.17).
func TestWindowsClientSetupOnHost(t *testing.T) {
	reqtest.Partial(t, "FR-21.17")
	matrix := loadMatrixWindows(t)
	home, root := t.TempDir(), t.TempDir()
	e := Env{OS: "windows", Home: home, CWD: t.TempDir(), AppData: filepath.Join(home, "AppData", "Roaming"), Root: root,
		ProgramFiles: `C:\Program Files`, ProgramData: `C:\ProgramData`,
		Gateway: Gateway{MCPURL: "https://127.0.0.1:8443/mcp", CAFile: filepath.Join(home, "ca.crt"), Credentials: filepath.Join(home, "credentials.json"),
			Origins: []string{"https://127.0.0.1:8443"}, Standalone: true}}
	expand := func(p string) string {
		r := strings.NewReplacer("%USERPROFILE%", home, "%APPDATA%", e.AppData,
			"%ProgramFiles%", filepath.Join(root, "Program Files"), "%ProgramData%", filepath.Join(root, "ProgramData"))
		return r.Replace(p)
	}
	now := time.Now()
	for _, c := range Clients() {
		w := matrix[c.Name]
		if w == nil {
			continue
		}
		if w.Unsupported != "" {
			if err := c.Unsupported(e); err == nil {
				t.Errorf("%s: no unsupported on windows report", c.ID)
			}
			continue
		}
		setup, err := c.Setup(e, Options{})
		if err != nil {
			t.Fatalf("%s setup: %v", c.ID, err)
		}
		if _, err := Apply(setup, ManifestPath(home, c.ID, "setup"), "setup", now); err != nil {
			t.Fatalf("%s setup apply: %v", c.ID, err)
		}
		lock, err := c.Lockdown(e)
		if err != nil {
			t.Fatalf("%s lockdown: %v", c.ID, err)
		}
		if len(lock.Changes) > 0 {
			if _, err := Apply(lock, ManifestPath(home, c.ID, "lockdown"), "lockdown", now); err != nil {
				t.Fatalf("%s lockdown apply: %v", c.ID, err)
			}
		}
		for purpose, p := range w.Paths {
			b, err := os.ReadFile(expand(p))
			if err != nil {
				t.Errorf("%s %s: %v", c.ID, purpose, err)
				continue
			}
			if purpose != PurposeCATrust && !strings.Contains(string(b), GatewayName) {
				t.Errorf("%s %s: %s does not name the Gateway:\n%s", c.ID, purpose, p, b)
			}
		}
		r := Doctor(e, []string{c.ID}, func() []Finding { return nil })
		for _, f := range r.Findings {
			if f.Client == c.ID && strings.Contains(f.Message, "the Gateway is not configured") {
				t.Errorf("%s: doctor after setup: %s", c.ID, f.Message)
			}
		}
		for _, kind := range []string{"lockdown", "setup"} {
			mp := ManifestPath(home, c.ID, kind)
			if _, err := os.Stat(mp); err != nil {
				continue
			}
			if _, err := Remove(mp); err != nil {
				t.Errorf("%s %s remove: %v", c.ID, kind, err)
			}
		}
		for purpose, p := range w.Paths {
			if _, err := os.Stat(expand(p)); err == nil {
				t.Errorf("%s %s: %s remains after remove", c.ID, purpose, p)
			}
		}
	}
}
