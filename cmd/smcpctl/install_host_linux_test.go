//go:build linux

package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// enforcedHostEnv returns the inputs scripts/ci-systemd.sh passes to the
// Enforced host tests, or skips the test when they are absent.
func enforcedHostEnv(t *testing.T) (stage, adminPW, approverPW string, port int) {
	t.Helper()
	if os.Getenv("SMCP_ENFORCED_HOST_TEST") != "1" {
		t.Skip("changes the host (users, /etc/smcp, nftables, systemd units); set SMCP_ENFORCED_HOST_TEST=1 on a disposable host (scripts/ci-systemd.sh)")
	}
	stage, adminPW, approverPW = os.Getenv("SMCP_ENFORCED_STAGE"), os.Getenv("SMCP_ENFORCED_ADMIN_PW"), os.Getenv("SMCP_ENFORCED_APPROVER_PW")
	port, err := strconv.Atoi(os.Getenv("SMCP_SYSTEMD_PORT"))
	if stage == "" || adminPW == "" || approverPW == "" || err != nil {
		t.Fatal("SMCP_ENFORCED_STAGE, SMCP_ENFORCED_ADMIN_PW, SMCP_ENFORCED_APPROVER_PW and SMCP_SYSTEMD_PORT are required")
	}
	return stage, adminPW, approverPW, port
}

func enforcedInstallArgs(stage, adminPW, approverPW string, port int) []string {
	return []string{filepath.Join(stage, "smcpctl"), "install", "--profile", "enforced", "--bin-dir", stage,
		"--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--port", strconv.Itoa(port), "--admin-port", strconv.Itoa(port + 1), "--metrics-port", strconv.Itoa(port + 2), "--notify", "off"}
}

// hostState is what the Enforced install creates, as seen on the host.
type hostState struct {
	users, groups map[string]bool
	table         bool
	files         map[string]bool
}

func readHostState(t *testing.T) hostState {
	t.Helper()
	s := hostState{users: map[string]bool{}, groups: map[string]bool{}, files: map[string]bool{}}
	for _, u := range serviceIdentities {
		s.users[u] = exec.Command("getent", "passwd", u).Run() == nil
	}
	for _, g := range []string{"smcp", "smcp-srv"} {
		s.groups[g] = exec.Command("getent", "group", g).Run() == nil
	}
	_, err := sudoOut(t, "", "nft", "list", "table", "inet", "smcp")
	s.table = err == nil
	for _, p := range []string{"/etc/smcp", "/var/lib/smcp", "/var/log/smcp", "/etc/systemd/system/smcpd.service", "/etc/systemd/system/smcp-nftables.service", "/etc/apparmor.d/smcpd", "/etc/sudoers.d/smcp-srv"} {
		_, err := sudoOut(t, "", "test", "-e", p)
		s.files[p] = err == nil
	}
	return s
}

func (s hostState) empty() []string {
	var found []string
	for u, ok := range s.users {
		if ok {
			found = append(found, "user "+u)
		}
	}
	for g, ok := range s.groups {
		if ok {
			found = append(found, "group "+g)
		}
	}
	if s.table {
		found = append(found, "nftables table inet smcp")
	}
	for p, ok := range s.files {
		if ok {
			found = append(found, p)
		}
	}
	sort.Strings(found)
	return found
}

// subIDRanges reads the subordinate ranges of a file (/etc/subuid or
// /etc/subgid) by user.
func subIDRanges(t *testing.T, file string) map[string][2]int {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string][2]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) != 3 {
			continue
		}
		start, err1 := strconv.Atoi(p[1])
		count, err2 := strconv.Atoi(p[2])
		if err1 == nil && err2 == nil {
			out[p[0]] = [2]int{start, count}
		}
	}
	return out
}

// installedDigests returns the SHA-256 of every file of the configuration,
// policy, keys, TLS material, journal and units of the Enforced
// installation.
func installedDigests(t *testing.T) string {
	t.Helper()
	out, err := sudoOut(t, "", "sh", "-c", "find /etc/smcp /var/lib/smcp/policy /var/lib/smcp/state/keys /var/lib/smcp/state/tls /var/lib/smcp/state/journal "+
		"/etc/systemd/system/smcpd.service /etc/systemd/system/smcp-nftables.service -type f -exec sha256sum {} + | sort")
	if err != nil {
		t.Fatalf("digests: %v\n%s", err, out)
	}
	return out
}

// TestEnforcedInstallOnHost installs the Enforced profile with
// `smcpctl install --profile enforced` on the CI host (a GitHub-hosted
// Ubuntu runner, CI job linux-integration, from scripts/ci-systemd.sh) and
// checks FR-13.5 on the real host:
//
//   - a missing Section 1.5.1 prerequisite (running without root, which
//     the installer requires) stops the install before any change: it
//     names the prerequisite, and no identity, directory, unit, profile
//     or nftables table exists afterwards;
//   - with every prerequisite present (sudo), it creates the CP-46 service
//     identities, the subordinate UID and GID ranges of 65,536 of smcp-core
//     and smcp-srv (not overlapping), the CP-46 directories with their
//     owners and modes, the nftables table inet smcp, the AppArmor profiles
//     smcpd and smcp-server (loaded) and the systemd units (smcpd.service
//     active and running as smcp-core, /run/smcp 0750).
//
// It then runs the install again (FR-13.4, Enforced half): every step is
// reported present, none created or updated, and the configuration,
// policy, keys, TLS material, journal and units are byte-for-byte
// unchanged. The installation stays for the rest of scripts/ci-systemd.sh.
func TestEnforcedInstallOnHost(t *testing.T) {
	stage, adminPW, approverPW, port := enforcedHostEnv(t)
	reqtest.Verifies(t, "FR-13.5")
	reqtest.Partial(t, "FR-13.4")
	if os.Geteuid() == 0 {
		t.Fatal("run as an unprivileged user with passwordless sudo: the missing-prerequisite check runs the install without root")
	}
	args := enforcedInstallArgs(stage, adminPW, approverPW, port)
	if found := readHostState(t).empty(); len(found) > 0 {
		t.Fatalf("the host is not clean before the install: %v", found)
	}

	// 1. A missing prerequisite: nothing is changed.
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	t.Logf("install without root:\n%s", out)
	if err == nil {
		t.Fatal("the install without root succeeded")
	}
	for _, want := range []string{"prerequisites missing; nothing was changed", "root (run with sudo)"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("the refused install does not say %q", want)
		}
	}
	if found := readHostState(t).empty(); len(found) > 0 {
		t.Fatalf("the refused install changed the host: %v", found)
	}

	// 2. The install.
	first, err := sudoOut(t, "", args...)
	t.Logf("install:\n%s", first)
	if err != nil {
		t.Fatalf("smcpctl install --profile enforced: %v", err)
	}
	for _, want := range []string{"created user smcp-core", "created nftables table inet smcp", "created file /etc/systemd/system/smcpd.service", "created configuration /etc/smcp/smcp.toml", "health: "} {
		if !strings.Contains(first, want) {
			t.Errorf("install output lacks %q", want)
		}
	}
	if strings.Contains(first, "health: fail-closed") {
		t.Fatal("the installed Gateway is fail-closed")
	}

	// Identities and groups.
	for _, u := range serviceIdentities {
		g, err := exec.Command("id", "-gn", u).Output()
		if err != nil {
			t.Fatalf("service identity %s missing", u)
		}
		want := "smcp"
		if u == "smcp-srv" {
			want = "smcp-srv"
		}
		if strings.TrimSpace(string(g)) != want {
			t.Errorf("%s's primary group is %s, not %s", u, strings.TrimSpace(string(g)), want)
		}
	}
	// Subordinate ranges.
	for _, file := range []string{"/etc/subuid", "/etc/subgid"} {
		r := subIDRanges(t, file)
		core, srv := r["smcp-core"], r["smcp-srv"]
		for name, v := range map[string][2]int{"smcp-core": core, "smcp-srv": srv} {
			if v[1] < 65536 {
				t.Errorf("%s: %s has %d subordinate IDs, want 65536", file, name, v[1])
			}
		}
		if core[0] < srv[0]+srv[1] && srv[0] < core[0]+core[1] {
			t.Errorf("%s: the ranges of smcp-core %v and smcp-srv %v overlap", file, core, srv)
		}
	}
	// CP-46 directories (and the state directory and smcp-core's home).
	for p, want := range map[string]string{
		"/etc/smcp":                    "root:smcp 750",
		"/var/lib/smcp":                "root:smcp 755",
		"/var/lib/smcp/policy":         "smcp-core:smcp 700",
		"/var/lib/smcp/registry":       "smcp-core:smcp 700",
		"/var/lib/smcp/artifacts":      "smcp-core:smcp 700",
		"/var/lib/smcp/journal":        "smcp-evidence:smcp 700",
		"/var/lib/smcp/keys":           "smcp-keys:smcp 700",
		"/var/lib/smcp/vault":          "smcp-vault:smcp 700",
		"/var/lib/smcp/exports":        "smcp-core:smcp 750",
		"/var/lib/smcp/state":          "smcp-core:smcp 700",
		"/var/lib/smcp/home/smcp-core": "smcp-core:smcp 700",
		"/var/log/smcp":                "smcp-core:smcp 750",
		"/etc/smcp/smcp.toml":          "root:smcp 640",
		"/var/lib/smcp/state/journal":  "smcp-core:smcp 700",
	} {
		got, err := sudoOut(t, "", "stat", "-c", "%U:%G %a", p)
		if err != nil || strings.TrimSpace(got) != want {
			t.Errorf("%s is %q (%v), want %q", p, strings.TrimSpace(got), err, want)
		}
	}
	// nftables table.
	if nft, err := sudoOut(t, "", "nft", "list", "table", "inet", "smcp"); err != nil {
		t.Errorf("nftables table inet smcp: %v\n%s", err, nft)
	}
	// LSM profiles.
	if !dirExists("/sys/kernel/security/apparmor") {
		// The installer ships AppArmor profiles; on an SELinux host it
		// skips them, so this host cannot show the LSM clause.
		t.Fatal("AppArmor is not enabled on this host; FR-13.5 is checked on an AppArmor host (GitHub-hosted Ubuntu)")
	}
	{
		st, err := sudoOut(t, "", "cat", "/sys/kernel/security/apparmor/profiles")
		if err != nil {
			t.Fatalf("AppArmor profiles: %v", err)
		}
		for _, p := range []string{"smcpd", "smcp-server"} {
			if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(p) + ` \(enforce\)$`).MatchString(st) {
				t.Errorf("AppArmor profile %s is not loaded in enforce mode", p)
			}
			if _, err := sudoOut(t, "", "test", "-f", "/etc/apparmor.d/"+p); err != nil {
				t.Errorf("/etc/apparmor.d/%s missing", p)
			}
		}
	}
	// systemd units.
	for _, u := range []string{"/etc/systemd/system/smcpd.service", "/etc/systemd/system/smcp-nftables.service"} {
		if _, err := os.Stat(u); err != nil {
			t.Errorf("unit %s: %v", u, err)
		}
	}
	if err := exec.Command("systemctl", "is-active", "--quiet", "smcpd.service").Run(); err != nil {
		t.Error("smcpd.service is not active")
	}
	pid, _ := exec.Command("systemctl", "show", "-p", "MainPID", "--value", "smcpd.service").Output()
	if user, _ := exec.Command("ps", "-o", "user=", "-p", strings.TrimSpace(string(pid))).Output(); strings.TrimSpace(string(user)) != "smcp-core" {
		t.Errorf("smcpd runs as %q, not smcp-core", strings.TrimSpace(string(user)))
	}
	if got, err := sudoOut(t, "", "stat", "-c", "%a", "/run/smcp"); err != nil || strings.TrimSpace(got) != "750" {
		t.Errorf("/run/smcp mode %q (%v), want 750", strings.TrimSpace(got), err)
	}
	if t.Failed() {
		t.FailNow()
	}

	// 3. The second install changes nothing (FR-13.4, Enforced).
	before := installedDigests(t)
	if strings.Count(before, "\n") < 5 {
		t.Fatalf("too few installed files to compare:\n%s", before)
	}
	second, err := sudoOut(t, "", args...)
	t.Logf("second install:\n%s", second)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	present := 0
	for _, l := range strings.Split(second, "\n") {
		switch strings.SplitN(l, " ", 2)[0] {
		case "created", "updated":
			t.Errorf("the second install changed the host: %s", l)
		case "present":
			present++
		}
	}
	for _, want := range []string{"present configuration /etc/smcp/smcp.toml", "present nftables table inet smcp", "present started smcpd.service"} {
		if !strings.Contains(second, want) {
			t.Errorf("the second install does not report %q", want)
		}
	}
	if after := installedDigests(t); after != before {
		t.Errorf("the second install changed configuration, policy, keys, journal or units:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	t.Logf("second run: %d steps present, none created or updated", present)
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// TestStandaloneUninstallKeepsEnforcedHost runs `smcpctl uninstall` and
// `smcpctl uninstall --purge` of a Standalone installation (profile mode
// "standalone", bootstrapped in a temporary directory) as the runner user,
// who has passwordless sudo, on the host where TestEnforcedInstallOnHost
// installed the Enforced profile. Before the fix, the Standalone uninstall
// deleted the nftables table inet smcp, the AppArmor profiles and the
// system units of the Enforced installation. Now every Enforced object is
// still in place afterwards and smcpd.service is still active.
func TestStandaloneUninstallKeepsEnforcedHost(t *testing.T) {
	if os.Getenv("SMCP_ENFORCED_HOST_TEST") != "1" {
		t.Skip("needs an Enforced installation on a disposable host; set SMCP_ENFORCED_HOST_TEST=1 (scripts/ci-systemd.sh)")
	}
	reqtest.Partial(t, "FR-13.11")
	before := readHostState(t)
	if !before.table || !before.users["smcp-core"] || !before.files["/etc/systemd/system/smcpd.service"] {
		t.Fatalf("no Enforced installation on this host: %v", before.empty())
	}
	dir, cfg := instance(t)
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n[profile]\nmode = \"standalone\"\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	bin := t.TempDir()
	for _, n := range []string{"smcpd", "smcpctl", "smcp-refserver"} {
		copyBin(t, filepath.Join(binDir, n), filepath.Join(bin, n))
	}
	ctl := filepath.Join(t.TempDir(), "smcpctl")
	copyBin(t, filepath.Join(binDir, "smcpctl"), ctl)
	out, err := exec.Command(ctl, "uninstall", "--config", cfg, "--bin-dir", bin).CombinedOutput()
	t.Logf("standalone uninstall:\n%s", out)
	if err != nil {
		t.Fatalf("standalone uninstall: %v", err)
	}
	id, err := keys.EnsureInstallationID(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(ctl, "uninstall", "--purge", "--config", cfg, "--bin-dir", bin)
	cmd.Stdin = strings.NewReader(id + "\n")
	out, err = cmd.CombinedOutput()
	t.Logf("standalone purge:\n%s", out)
	if err != nil {
		t.Fatalf("standalone purge: %v", err)
	}
	after := readHostState(t)
	if a, b := strings.Join(after.empty(), "\n"), strings.Join(before.empty(), "\n"); a != b {
		t.Fatalf("the Standalone uninstall changed the Enforced installation:\nbefore:\n%s\nafter:\n%s", b, a)
	}
	if err := exec.Command("systemctl", "is-active", "--quiet", "smcpd.service").Run(); err != nil {
		t.Fatal("smcpd.service is no longer active")
	}
}
