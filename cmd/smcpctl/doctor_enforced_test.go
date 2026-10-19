package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/harness"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// doctorReport runs smcpctl doctor --json in-process and decodes the
// report; findings make it exit non-zero, which is not an error here.
func doctorReport(t *testing.T, args ...string) harness.Report {
	t.Helper()
	_, out, errs := rctl(t, append([]string{"doctor", "--json", "--client", "hermes"}, args...)...)
	var r harness.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("doctor --json: %v\n%s\n%s", err, out, errs)
	}
	return r
}

func readablePaths(r harness.Report) []string {
	var out []string
	for _, f := range r.Findings {
		if f.Kind == harness.KindReadable {
			out = append(out, f.Path)
		}
	}
	slices.Sort(out)
	return out
}

func hasInfo(r harness.Report, text string) bool {
	return slices.ContainsFunc(r.Findings, func(f harness.Finding) bool {
		return f.Kind == harness.KindInfo && strings.Contains(f.Message, text)
	})
}

// TestDoctorEnforcedFallback: when the harness user cannot read the
// configuration, as on an Enforced host (root:smcp 0640), doctor checks
// the CP-46 Enforced directories instead of failing, and reports exactly
// those this user can read. The directories live under a temporary host
// root here; TestDoctorEnforcedHostAsHarnessUser runs on a real Enforced
// installation.
func TestDoctorEnforcedFallback(t *testing.T) {
	reqtest.Partial(t, "FR-15.4")
	if os.Geteuid() == 0 {
		t.Skip("root reads every path")
	}
	root := t.TempDir()
	hostRoot = root
	t.Cleanup(func() { hostRoot = "" })
	modes := map[string]os.FileMode{"/etc/smcp": 0o100, "/var/lib/smcp": 0o100, "/var/lib/smcp/state": 0o100, "/var/lib/smcp/state/keys": 0o700, "/var/log/smcp": 0o755}
	for _, p := range []string{"/var/lib/smcp/state/keys", "/etc/smcp", "/var/log/smcp"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// root:smcp 0640 on the host; here a file this user cannot read.
	cfg := filepath.Join(root, "etc", "smcp", "smcp.toml")
	if err := os.WriteFile(cfg, []byte("[listener]\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	// Deepest first, so that parents stay searchable while children change.
	for _, p := range []string{"/var/lib/smcp/state/keys", "/var/lib/smcp/state", "/var/lib/smcp", "/etc/smcp", "/var/log/smcp"} {
		if err := os.Chmod(filepath.Join(root, p), modes[p]); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, p := range []string{"/var/lib/smcp", "/var/lib/smcp/state", "/etc/smcp"} {
			_ = os.Chmod(filepath.Join(root, p), 0o700)
		}
	})
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SMCP_HARNESS_ROOT", t.TempDir())
	creds := filepath.Join(home, "credentials.toml")
	if err := os.WriteFile(creds, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SMCP_CREDENTIALS", creds)

	r := doctorReport(t, "--config", cfg)
	if r.Profile != "enforced" || !hasInfo(r, "not readable by this user") {
		t.Fatalf("profile %s, findings %+v", r.Profile, r.Findings)
	}
	// keys (0700, own) is readable but sits below a directory this user can
	// search, not read; it is reported. The Enforced keys directory belongs
	// to smcp-keys, which TestDoctorEnforcedHostAsHarnessUser checks.
	want := []string{creds, filepath.Join(root, "/var/lib/smcp/state/keys"), filepath.Join(root, "/var/log/smcp")}
	slices.Sort(want)
	if got := readablePaths(r); !slices.Equal(got, want) {
		t.Fatalf("readable %v, want %v", got, want)
	}
	if hasInfo(r, "Gateway's own user identity") {
		t.Error("Standalone statement on an Enforced host")
	}
}
