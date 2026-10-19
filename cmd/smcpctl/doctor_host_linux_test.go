//go:build linux

package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestDoctorEnforcedHostAsHarnessUser runs `smcpctl doctor` on a host where
// scripts/ci-systemd.sh installed the Enforced profile, as the harness user
// (the CI runner account: not root, not in group smcp, so it cannot read
// /etc/smcp/smcp.toml), and then for a Standalone instance of the same user
// (FR-15.4, both halves of its verification statement):
//
//   - Enforced: the report is for the enforced profile without the
//     Standalone statement; the Enforced keys directory and every other path
//     below /var/lib/smcp/state are not reported; every reported path is one
//     this user can read, and every CP-46 Enforced directory and the
//     credential file this user can read (checked with test -r) is reported.
//   - Standalone: the Standalone statement is made, and the instance's
//     state directory and the credential file, both readable by the user
//     running the clients, are reported.
//
// It needs the installation, so it runs only with SMCP_ENFORCED_HOST_TEST=1
// from scripts/ci-systemd.sh (CI job linux-integration), before the
// uninstall.
func TestDoctorEnforcedHostAsHarnessUser(t *testing.T) {
	if os.Getenv("SMCP_ENFORCED_HOST_TEST") != "1" {
		t.Skip("needs the Enforced installation of scripts/ci-systemd.sh; set SMCP_ENFORCED_HOST_TEST=1 there")
	}
	reqtest.Verifies(t, "FR-15.4")
	if os.Geteuid() == 0 {
		t.Fatal("run as the harness user, not root")
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if gids, _ := u.GroupIds(); slices.ContainsFunc(gids, func(g string) bool { grp, err := user.LookupGroupId(g); return err == nil && grp.Name == "smcp" }) {
		t.Fatalf("%s is in group smcp; the harness user must not be", u.Username)
	}
	const cfg = "/etc/smcp/smcp.toml"
	if _, err := os.ReadFile(cfg); err == nil {
		t.Fatalf("%s is readable by the harness user", cfg)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SMCP_HARNESS_ROOT", t.TempDir())
	creds := filepath.Join(home, ".config", "smcp", "credentials.toml")
	if err := os.MkdirAll(filepath.Dir(creds), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(creds, []byte("[client]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SMCP_CREDENTIALS", creds)
	readableByTest := func(p string) bool { return exec.Command("test", "-r", p).Run() == nil }

	// Enforced host, as the harness user.
	r := doctorReport(t, "--config", cfg)
	if r.Profile != "enforced" || hasInfo(r, "Gateway's own user identity") || !hasInfo(r, "not readable by this user") {
		t.Fatalf("enforced report: profile %s, findings %+v", r.Profile, r.Findings)
	}
	got := readablePaths(r)
	for _, p := range got {
		if strings.HasPrefix(p, "/var/lib/smcp/state") {
			t.Errorf("doctor reports %s, below the state directory the harness user must not read", p)
		}
		if !readableByTest(p) {
			t.Errorf("doctor reports %s, which test -r says is not readable", p)
		}
	}
	for _, p := range append(slices.Clone(enforcedPaths), creds) {
		if _, err := os.Stat(p); err == nil && readableByTest(p) && !slices.Contains(got, p) {
			t.Errorf("%s is readable by the harness user but not reported", p)
		}
	}
	if !slices.Contains(got, creds) {
		t.Errorf("the credential file is not reported (readable %v)", got)
	}
	t.Logf("enforced host: readable %v", got)

	// Standalone instance of the same user.
	g := gwtest.Start(t, "\n[profile]\nmode = \"standalone\"\n")
	r = doctorReport(t, "--config", g.CfgPath)
	if r.Profile != "standalone" || !hasInfo(r, "Gateway's own user identity") {
		t.Fatalf("standalone report: profile %s, findings %+v", r.Profile, r.Findings)
	}
	got = readablePaths(r)
	for _, p := range []string{g.Config.State.Dir, creds} {
		if !slices.Contains(got, p) {
			t.Errorf("standalone: %s is readable but not reported (readable %v)", p, got)
		}
	}
	t.Logf("standalone: readable %v", got)
}
