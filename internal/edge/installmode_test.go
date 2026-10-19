package edge

import (
	"encoding/json"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/profile"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestHealthReportsInstallationMode: on a Windows host or in WSL the health
// report carries the installation mode next to the label "not enforced"
// and is never healthy (SR-4-2); elsewhere the field is absent. Partial:
// see internal/profile.
func TestHealthReportsInstallationMode(t *testing.T) {
	reqtest.Partial(t, "SR-4-2")
	h := newHarness(t, harnessOpts{})
	if b, _ := json.Marshal(h.gw.Health()); json.Valid(b) && string(b) != "" {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if _, ok := m["installation_mode"]; ok {
			t.Fatalf("installation_mode on macOS: %s", b)
		}
	}
	for _, mode := range []string{profile.ModeWindowsUser, profile.ModeWindowsMachine, profile.ModeWSL2} {
		host := profile.Host{OS: "windows", Arch: "amd64", InstallMode: mode}
		if mode == profile.ModeWSL2 {
			host = profile.Host{OS: "linux", Arch: "amd64", WSL: true, InstallMode: mode}
		}
		prof, err := profile.Resolve("auto", "subprocess", false, host)
		if err != nil {
			t.Fatal(err)
		}
		h.gw.prof = prof
		hl := h.gw.Health()
		if hl.State == "healthy" || hl.ReleaseLabel != "not enforced" || hl.InstallationMode != mode {
			t.Fatalf("%s: %+v", mode, hl)
		}
	}
}
