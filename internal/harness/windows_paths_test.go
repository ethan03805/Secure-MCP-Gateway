package harness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// matrixWindows is the windows entry of a local client in
// docs/clients/matrix.json (FR-21.17).
type matrixWindows struct {
	Paths       map[string]string `json:"paths"`
	Unsupported string            `json:"unsupported"`
}

func loadMatrixWindows(t *testing.T) map[string]*matrixWindows {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "clients", "matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Clients []struct {
			Client  string         `json:"client"`
			RunsOn  string         `json:"runsOn"`
			Windows *matrixWindows `json:"windows"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	out := map[string]*matrixWindows{}
	for _, c := range m.Clients {
		if c.RunsOn == "local" {
			out[c.Client] = c.Windows
		}
	}
	return out
}

// windowsEnv is a Windows user's environment for path planning.
func windowsEnv() Env {
	return Env{OS: "windows", Home: `C:\Users\u`, CWD: `C:\work`, AppData: `C:\Users\u\AppData\Roaming`,
		ProgramFiles: `C:\Program Files`, ProgramData: `C:\ProgramData`,
		Gateway: Gateway{MCPURL: "https://127.0.0.1:8443/mcp", CAFile: `C:\Users\u\smcp\state\tls\ca.crt`, Credentials: `C:\Users\u\AppData\Roaming\smcp\credentials.json`}}
}

// expandWindows replaces the folder variables the matrix uses.
func expandWindows(p string) string {
	return strings.NewReplacer("%USERPROFILE%", `C:\Users\u`, "%APPDATA%", `C:\Users\u\AppData\Roaming`,
		"%ProgramFiles%", `C:\Program Files`, "%ProgramData%", `C:\ProgramData`).Replace(p)
}

// TestWindowsClientPathsMatchMatrix: for every local client of Appendix K,
// the paths that clients setup (connection and CA trust) and lockdown write
// on Windows are the ones docs/clients/matrix.json records for Windows, and
// a client without a Windows entry is reported as unsupported on windows
// by setup, lockdown and doctor (FR-21.17). The planning is checked on
// every platform; TestWindowsClientSetupOnHost writes the files on a
// Windows runner.
func TestWindowsClientPathsMatchMatrix(t *testing.T) {
	reqtest.Partial(t, "FR-21.17")
	matrix := loadMatrixWindows(t)
	byName := map[string]*Client{}
	for _, c := range Clients() {
		byName[c.Name] = c
	}
	e := windowsEnv()
	slash := func(p string) string { return strings.ReplaceAll(p, "/", `\`) }
	for name, w := range matrix {
		c, ok := byName[name]
		if !ok {
			t.Errorf("%s: in the matrix but not a harness client", name)
			continue
		}
		if w == nil {
			t.Errorf("%s: the matrix has no windows entry", name)
			continue
		}
		if w.Unsupported != "" {
			if c.NoWindows != w.Unsupported {
				t.Errorf("%s: harness reason %q, matrix %q", name, c.NoWindows, w.Unsupported)
			}
			if err := c.Unsupported(e); err == nil || !strings.Contains(err.Error(), "unsupported on windows") {
				t.Errorf("%s: Unsupported = %v", name, err)
			}
			r := Doctor(e, []string{c.ID}, func() []Finding { return nil })
			found := false
			for _, f := range r.Findings {
				found = found || (f.Client == c.ID && strings.Contains(f.Message, "unsupported on windows"))
			}
			if !found {
				t.Errorf("%s: doctor does not report unsupported on windows: %+v", name, r.Findings)
			}
			continue
		}
		if c.NoWindows != "" || c.Unsupported(e) != nil {
			t.Errorf("%s: the matrix records Windows paths, the harness says %q", name, c.NoWindows)
		}
		got := map[string]string{}
		setup, err := c.Setup(e, Options{})
		if err != nil {
			t.Fatalf("%s setup: %v", name, err)
		}
		lock, err := c.Lockdown(e)
		if err != nil {
			t.Fatalf("%s lockdown: %v", name, err)
		}
		for _, ch := range append(setup.Changes, lock.Changes...) {
			got[ch.Purpose] = slash(ch.Path)
		}
		for purpose, p := range w.Paths {
			if got[purpose] != expandWindows(p) {
				t.Errorf("%s %s: harness writes %q, matrix records %q", name, purpose, got[purpose], expandWindows(p))
			}
		}
		for purpose, p := range got {
			if _, ok := w.Paths[purpose]; !ok {
				t.Errorf("%s %s: harness writes %q, which the matrix does not record", name, purpose, p)
			}
		}
	}
}
