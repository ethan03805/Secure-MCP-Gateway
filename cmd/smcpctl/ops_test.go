package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// instance bootstraps a Gateway directory and returns its config path.
func instance(t *testing.T) (dir, cfg string) {
	t.Helper()
	dir = t.TempDir()
	secrets := t.TempDir()
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", writeFile(t, secrets, "a", "admin password 12\n"),
		"--approver-password-file", writeFile(t, secrets, "b", "approver password 1\n"),
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", freePort(t), "--notify", "off")
	return dir, filepath.Join(dir, "smcp.toml")
}

func copyBin(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

func sha(t *testing.T, p string) string {
	t.Helper()
	b, _ := os.ReadFile(p)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func writeSums(t *testing.T, dir string, names ...string) {
	t.Helper()
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", sha(t, filepath.Join(dir, n)), n)
	}
	writeFile(t, dir, "SHA256SUMS", b.String())
}

func TestOfflineOpsCommands(t *testing.T) {
	// FR-12.7 operations subcommands offline: version, config migrate,
	// keys status and rotate --offline, backup (refusal and passphrase),
	// restore --verify-only and restore, journal export and verify --key.
	reqtest.Partial(t, "FR-12.7", "FR-17.6", "FR-13.13", "FR-7.14")
	dir, cfg := instance(t)
	if out := mustCtl(t, "version", "--short"); strings.TrimSpace(out) == "" {
		t.Fatal("no version")
	}
	if out := mustCtl(t, "config", "migrate", "--config", cfg); !strings.Contains(out, "nothing to migrate") {
		t.Fatal(out)
	}
	raw, _ := os.ReadFile(cfg)
	newer := writeFile(t, dir, "newer.toml", strings.Replace(string(raw), "schema_version = 1", "schema_version = 7", 1))
	if out, err := ctl(t, "", "config", "validate", "--config", newer); err == nil || !strings.Contains(out, "schema_version 7") || !strings.Contains(out, "up to 1") {
		t.Fatalf("newer config: %v %s", err, out)
	}
	if out := mustCtl(t, "keys", "status", "--config", cfg); !strings.Contains(out, `"installation_id"`) || !strings.Contains(out, `"evidence_trust_root"`) {
		t.Fatal(out)
	}
	mustCtl(t, "keys", "rotate", "tls", "--offline", "--config", cfg)
	if out := mustCtl(t, "keys", "rotate", "ca", "--overlap", "0", "--offline", "--config", cfg); !strings.Contains(out, "rotation") {
		t.Fatal(out)
	}
	if out, err := ctl(t, "", "keys", "rotate", "evidence", "--offline", "--config", cfg); err == nil || !strings.Contains(out, "running Gateway") {
		t.Fatalf("offline evidence rotation: %v %s", err, out)
	}
	// Produce some evidence, then back up offline.
	d := startDaemon(t, cfg)
	stopDaemon(t, d)
	if out, err := ctl(t, "", "backup", "--config", cfg); err == nil || !strings.Contains(out, "terminal") {
		t.Fatalf("backup without passphrase and terminal: %v %s", err, out)
	}
	pw := writeFile(t, t.TempDir(), "pw", "backup passphrase 1\n")
	out := mustCtl(t, "backup", "--config", cfg, "--passphrase-file", pw)
	if !strings.Contains(out, "backup written") || !strings.Contains(out, "evidence_journal") {
		t.Fatal(out)
	}
	archives, _ := filepath.Glob(filepath.Join(dir, "backups", "*.age"))
	if len(archives) != 1 {
		t.Fatalf("archives %v", archives)
	}
	if out := mustCtl(t, "restore", "--config", cfg, "--archive", archives[0], "--passphrase-file", pw, "--verify-only"); !strings.Contains(out, "nothing was changed") {
		t.Fatal(out)
	}
	if out := mustCtl(t, "restore", "--config", cfg, "--archive", archives[0], "--passphrase-file", pw); !strings.Contains(out, "previous state is kept") {
		t.Fatal(out)
	}
	mustCtl(t, "journal", "verify", "--config", cfg)
	exp := t.TempDir()
	if out := mustCtl(t, "journal", "export", "--config", cfg, "--to", exp); !strings.Contains(out, "exported") {
		t.Fatal(out)
	}
	if out := mustCtl(t, "journal", "verify", "--dir", filepath.Join(exp, "journal"), "--key", filepath.Join(exp, "keys", "evidence-genesis.pub")); !strings.Contains(out, "journal OK") {
		t.Fatal(out)
	}
}

func TestOnlineOpsCommands(t *testing.T) {
	// FR-12.7 against a running Gateway: health (with the label, FR-13.10),
	// reload, keys rotate, backup, and refusal of restore while running.
	reqtest.Partial(t, "FR-12.7", "FR-13.10", "FR-17.9")
	_, cfg := instance(t)
	d := startDaemon(t, cfg)
	out := mustCtl(t, "health", "--config", cfg)
	if !strings.HasPrefix(out, "health: degraded; causes: unconfined") || !strings.Contains(out, "release label: not enforced") {
		t.Fatalf("health: %s", out)
	}
	if out := mustCtl(t, "version", "--config", cfg); !strings.Contains(out, "not enforced") {
		t.Fatalf("version: %s", out)
	}
	if out := mustCtl(t, "reload", "--config", cfg); !strings.Contains(out, `"restart_required"`) {
		t.Fatal(out)
	}
	raw, _ := os.ReadFile(cfg)
	_ = os.WriteFile(cfg, []byte(strings.Replace(string(raw), "[policy]", "[log]\nlevel = \"debug\"\n[policy]", 1)), 0o600)
	if out := mustCtl(t, "reload", "--config", cfg); !strings.Contains(out, `"log.level"`) {
		t.Fatal(out)
	}
	// SIGHUP takes the same path.
	if err := d.Process.Signal(sighup); err != nil {
		t.Fatal(err)
	}
	if out := mustCtl(t, "keys", "rotate", "evidence", "--config", cfg); !strings.Contains(out, `"public_key"`) {
		t.Fatal(out)
	}
	if out, err := ctl(t, "", "health", "ack", "evidence_unavailable", "--config", cfg); err == nil || !strings.Contains(out, "not_latched") {
		t.Fatalf("ack of an unlatched cause: %v %s", err, out)
	}
	pw := writeFile(t, t.TempDir(), "pw", "backup passphrase 1\n")
	if out := mustCtl(t, "backup", "--config", cfg, "--passphrase-file", pw); !strings.Contains(out, "sha256") {
		t.Fatal(out)
	}
	if out, err := ctl(t, "", "restore", "--config", cfg, "--archive", "x.age", "--passphrase-file", pw); err == nil || !strings.Contains(out, "is running") {
		t.Fatalf("restore while running: %v %s", err, out)
	}
	time.Sleep(200 * time.Millisecond)
	stopDaemon(t, d)
	out = mustCtl(t, "journal", "verify", "--config", cfg)
	if !strings.Contains(out, "1 evidence-key transitions") {
		t.Fatal(out)
	}
	cfgObj, _ := config.Load(cfg)
	evs, _ := audit.ReadEvents(filepath.Join(cfgObj.State.Dir, "journal"))
	reloads := 0
	for _, e := range evs {
		if e.ReasonCode == "CONFIG_RELOADED" {
			reloads++
		}
	}
	if reloads != 3 {
		t.Fatalf("reload events %d (two commands and one SIGHUP)", reloads)
	}
}

func TestUninstallKeepsEvidenceAndPurge(t *testing.T) {
	// FR-13.11: binaries removed, journal, evidence key and backups kept,
	// and the kept journal verifies from another installation's smcpctl.
	// The service unit is removed under a test host root; the nftables
	// table, LSM profiles and service identities are not touched in tests
	// (partial). FR-13.12: wrong installation ID refused, then the digest
	// printed and everything removed (partial for the same reason).
	reqtest.Partial(t, "FR-13.11", "FR-13.12")
	hostRoot = t.TempDir()
	t.Cleanup(func() { hostRoot = "" })
	units := unitFiles()
	if len(units) > 0 {
		_ = os.MkdirAll(filepath.Dir(units[0].path), 0o700)
		writeFile(t, filepath.Dir(units[0].path), filepath.Base(units[0].path), "unit")
	}
	dir, cfg := instance(t)
	d := startDaemon(t, cfg)
	stopDaemon(t, d)
	bin := t.TempDir()
	for _, n := range []string{"smcpd", "smcpctl", "smcp-refserver"} {
		copyBin(t, filepath.Join(binDir, n), filepath.Join(bin, n))
	}
	_ = os.MkdirAll(filepath.Join(dir, "backups"), 0o700)
	writeFile(t, filepath.Join(dir, "backups"), "old.age", "x")
	var out bytes.Buffer
	if err := uninstallCmd([]string{"--config", cfg, "--bin-dir", bin}, strings.NewReader(""), &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, n := range []string{"smcpd", "smcpctl", "smcp-refserver"} {
		if _, err := os.Stat(filepath.Join(bin, n)); err == nil {
			t.Errorf("%s not removed", n)
		}
	}
	if len(units) > 0 {
		if _, err := os.Stat(units[0].path); err == nil {
			t.Errorf("unit %s not removed", units[0].path)
		}
	}
	state := filepath.Join(dir, "state")
	for _, p := range []string{filepath.Join(state, "journal"), filepath.Join(state, keys.EvidencePubFile), filepath.Join(dir, "backups", "old.age")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s not kept", p)
		}
	}
	// A fresh installation's smcpctl verifies the kept journal and key.
	if o := mustCtl(t, "journal", "verify", "--dir", filepath.Join(state, "journal"), "--key", filepath.Join(state, keys.EvidenceGenesisFile)); !strings.Contains(o, "journal OK") {
		t.Fatal(o)
	}

	out.Reset()
	if err := uninstallCmd([]string{"--purge", "--config", cfg, "--bin-dir", bin}, strings.NewReader("not-the-id\n"), &out); err == nil {
		t.Fatal("purge with a wrong installation ID")
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatal("refused purge removed state")
	}
	id, _ := keys.EnsureInstallationID(state)
	_, sum, _ := audit.LastSegment(filepath.Join(state, "journal"))
	out.Reset()
	if err := uninstallCmd([]string{"--purge", "--config", cfg, "--bin-dir", bin}, strings.NewReader(id+"\n"), &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "sha256 "+sum) {
		t.Fatalf("digest not printed:\n%s", out.String())
	}
	for _, p := range []string{state, cfg, filepath.Join(dir, "policy.json")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s not purged", p)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "backups", "old.age")); err != nil {
		t.Error("purge removed backups")
	}
}

func TestVerifyRelease(t *testing.T) {
	reqtest.Partial(t, "FR-13.7")
	rel := t.TempDir()
	writeFile(t, rel, "smcpd", "a")
	writeFile(t, rel, "smcpctl", "b")
	if err := verifyRelease(rel); err == nil {
		t.Fatal("release without SHA256SUMS")
	}
	writeSums(t, rel, "smcpd")
	if err := verifyRelease(rel); err == nil || !strings.Contains(err.Error(), "smcpctl") {
		t.Fatalf("missing smcpctl: %v", err)
	}
	writeSums(t, rel, "smcpd", "smcpctl")
	if err := verifyRelease(rel); err != nil {
		t.Fatal(err)
	}
	writeFile(t, rel, "smcpd", "tampered")
	if err := verifyRelease(rel); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("tampered: %v", err)
	}
}

func TestUpgradeAndRollback(t *testing.T) {
	// FR-13.7: backup, dispatch stopped, binaries swapped, migration run,
	// new version started and healthy within the bound. FR-13.8: a release
	// that never becomes healthy is rolled back to the previous binaries
	// and the pre-upgrade backup, and the previous version records
	// upgrade_rolled_back. The release signature (FR-13.2) and a failing
	// migration are not exercised (partial).
	reqtest.Partial(t, "FR-13.7", "FR-13.8")
	if testing.Short() {
		t.Skip("builds a second release")
	}
	dir, cfg := instance(t)
	inst := t.TempDir() // installed binaries
	for _, n := range []string{"smcpd", "smcpctl"} {
		copyBin(t, filepath.Join(binDir, n), filepath.Join(inst, n))
	}
	// The new release: version 9.9.9.
	rel := t.TempDir()
	goTool, _ := exec.LookPath("go")
	for _, pkg := range []string{"smcpd", "smcpctl"} {
		cmd := exec.Command(goTool, "build", "-ldflags", "-X github.com/ethan03805/secure-mcp-gateway/internal/backend.Version=9.9.9", "-o", filepath.Join(rel, pkg), "../"+pkg)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
	}
	writeSums(t, rel, "smcpd", "smcpctl")
	pidFile := filepath.Join(dir, "smcpd.pid")
	logFile := filepath.Join(dir, "smcpd.out")
	start := fmt.Sprintf(`nohup %q --config "$SMCP_CONFIG" >>%q 2>&1 & echo $! > %q`, filepath.Join(inst, "smcpd"), logFile, pidFile)
	stop := fmt.Sprintf(`p=$(cat %q); kill "$p" 2>/dev/null; while kill -0 "$p" 2>/dev/null; do sleep 0.1; done; true`, pidFile)
	t.Cleanup(func() { _ = exec.Command("/bin/sh", "-c", stop).Run() })
	if err := exec.Command("/bin/sh", "-c", "export SMCP_CONFIG="+cfg+"; "+start).Run(); err != nil {
		t.Fatal(err)
	}
	waitUp := func() {
		t.Helper()
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			if _, err := ctl(t, "", "health", "--config", cfg); err == nil {
				return
			}
		}
		b, _ := os.ReadFile(logFile)
		t.Fatalf("smcpd did not start:\n%s", b)
	}
	waitUp()
	pw := writeFile(t, t.TempDir(), "pw", "upgrade backup pass\n")
	up := func(release string) (string, error) {
		cmd := exec.Command(filepath.Join(inst, "smcpctl"), "upgrade", "--config", cfg, "--release", release, "--bin-dir", inst,
			"--passphrase-file", pw, "--start-cmd", start, "--stop-cmd", stop, "--health-timeout", "20s")
		var b bytes.Buffer
		cmd.Stdout, cmd.Stderr = &b, &b
		err := cmd.Run()
		return b.String(), err
	}
	out, err := up(rel)
	if err != nil {
		b, _ := os.ReadFile(logFile)
		t.Fatalf("upgrade: %v\n%s\nsmcpd log:\n%s", err, out, b)
	}
	if !strings.Contains(out, "backup written") || !strings.Contains(out, "dispatch stopped") || !strings.Contains(out, "version 9.9.9") || !strings.Contains(out, "upgrade complete") {
		t.Fatalf("upgrade output:\n%s", out)
	}
	if v := strings.TrimSpace(mustCtl(t, "version", "--short")); v == "9.9.9" {
		t.Fatal("test harness binary changed") // sanity: binDir is untouched
	}
	if sha(t, filepath.Join(inst, "smcpd")) != sha(t, filepath.Join(rel, "smcpd")) || sha(t, filepath.Join(inst, "smcpd.prev")) != sha(t, filepath.Join(binDir, "smcpd")) {
		t.Fatal("binaries not swapped with .prev kept")
	}

	// A fault-injected release whose daemon never becomes healthy.
	bad := t.TempDir()
	writeFile(t, bad, "smcpd", "#!/bin/sh\nexit 1\n")
	_ = os.Chmod(filepath.Join(bad, "smcpd"), 0o755)
	copyBin(t, filepath.Join(rel, "smcpctl"), filepath.Join(bad, "smcpctl"))
	writeSums(t, bad, "smcpd", "smcpctl")
	goodSmcpd := sha(t, filepath.Join(inst, "smcpd"))
	out, err = up(bad)
	if err == nil || !strings.Contains(out, "rolling back") || !strings.Contains(out, "previous version is running") {
		t.Fatalf("rollback: %v\n%s", err, out)
	}
	if sha(t, filepath.Join(inst, "smcpd")) != goodSmcpd {
		t.Fatal("previous smcpd not restored")
	}
	waitUp()
	// Stop and check the journal: it verifies and holds the rollback event.
	_ = exec.Command("/bin/sh", "-c", stop).Run()
	if o := mustCtl(t, "journal", "verify", "--config", cfg); !strings.Contains(o, "journal OK") {
		t.Fatal(o)
	}
	evs, _ := audit.ReadEvents(filepath.Join(dir, "state", "journal"))
	found := false
	for _, e := range evs {
		found = found || e.Outcome == "upgrade_rolled_back"
	}
	if !found {
		t.Fatal("upgrade_rolled_back not in the journal")
	}
}
