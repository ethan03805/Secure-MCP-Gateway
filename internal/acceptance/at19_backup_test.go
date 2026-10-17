package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestAT19BackupRestoreRollback is acceptance scenario AT-19 against the
// real binaries:
//
//   - a backup taken under load stops dispatch (emergency stop with reason
//     "backup"), writes and checksums the archive, then resumes; no call is
//     dispatched between the stop and the resume (SR-7.7-1);
//   - an archive with one altered byte fails restore verification;
//   - restoring a backup taken before a principal was suspended re-applies
//     the suspension from the current journal before service starts
//     (SR-7.8-1 as its verification states);
//   - a policy rollback leaves the suspension in force (SR-7.9-1);
//   - an upgrade to a release whose smcpd never becomes healthy restores
//     the previous binaries, which run with the journal intact, and the
//     journal records upgrade_rolled_back (FR-13.8, unhealthy case).
//
// Partial: SR-7.7-1 does not open the archive to list each component;
// SR-7.8-1 does not rebuild a graph mirror (none configured); SR-7.9-1
// rolls back the policy, not the application version; FR-13.8 does not
// inject a failing migration.
func TestAT19BackupRestoreRollback(t *testing.T) {
	g := newGateway(t, options{limits: "principal_calls_per_minute = 1000000"})
	g.start()
	g.scenario("AT-19")
	reqtest.Partial(t, "SR-7.7-1", "SR-7.8-1", "SR-7.9-1", "FR-13.8")
	pass := writeFile(t, t.TempDir(), "backup.pw", "acceptance backup passphrase\n", 0o600)

	// Backup under load.
	var stop atomic.Bool
	var wg sync.WaitGroup
	var released atomic.Int64
	for range 2 {
		cs := g.session(g.freshToken())
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; !stop.Load(); n++ {
				if _, isErr, err := call(cs, "ref_echo", map[string]any{"text": fmt.Sprint("load ", n)}); err == nil && !isErr {
					released.Add(1)
				} else {
					time.Sleep(10 * time.Millisecond)
				}
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	g.mustCtl("backup", "--passphrase-file", pass)
	time.Sleep(300 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
	archives, _ := filepath.Glob(filepath.Join(g.dir, "backups", "*.age"))
	if len(archives) != 1 {
		t.Fatalf("archives: %v", archives)
	}
	archive := archives[0]
	sumFile, err := os.ReadFile(archive + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(archive)
	sum := sha256.Sum256(raw)
	if !strings.Contains(string(sumFile), hex.EncodeToString(sum[:])) {
		t.Fatalf("checksum file %q does not match the archive", sumFile)
	}

	// Revoke after the backup: suspend the principal.
	if code, out := g.api("POST", "/api/v1/principals/claude-code-local/suspend", map[string]any{"reason": "AT-19"}); code >= 300 {
		t.Fatalf("suspend: %d %v", code, out)
	}
	g.stop()

	evs := g.events()
	stopAt, writtenAt, resumeAt := -1, -1, -1
	for i, e := range evs {
		switch {
		case e.str("reason_code") == "EMERGENCY_STOP" && e.detail()["reason"] == "backup" && stopAt < 0:
			stopAt = i
		case e.str("reason_code") == "BACKUP_WRITTEN" && stopAt >= 0 && writtenAt < 0:
			writtenAt = i
		case e.str("reason_code") == "EMERGENCY_RESUME" && writtenAt >= 0 && resumeAt < 0:
			resumeAt = i
		}
	}
	if stopAt < 0 || writtenAt < stopAt || resumeAt < writtenAt {
		t.Fatalf("backup sequence: stop %d, written %d, resume %d", stopAt, writtenAt, resumeAt)
	}
	dispatchedAfter := 0
	for i, e := range evs {
		if e.str("class") == "call" && e.str("phase") == "dispatched" {
			if i > stopAt && i < resumeAt {
				t.Fatalf("call dispatched during the backup (event %d between %d and %d)", i, stopAt, resumeAt)
			}
			if i > resumeAt {
				dispatchedAfter++
			}
		}
	}
	if released.Load() == 0 || dispatchedAfter == 0 {
		t.Fatalf("load: %d released, %d dispatched after the resume", released.Load(), dispatchedAfter)
	}

	// A tampered archive does not verify.
	bad := filepath.Join(t.TempDir(), filepath.Base(archive))
	tampered := append([]byte{}, raw...)
	tampered[len(tampered)/2] ^= 0xff
	if err := os.WriteFile(bad, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad+".sha256", sumFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := g.ctl("restore", "--archive", bad, "--passphrase-file", pass, "--verify-only"); err == nil {
		t.Fatalf("a tampered archive verified:\n%s", out)
	}

	// Restore the pre-suspension backup; the suspension comes back from
	// the current journal.
	g.mustCtl("restore", "--archive", archive, "--passphrase-file", pass, "--verify-only")
	g.mustCtl("restore", "--archive", archive, "--passphrase-file", pass)
	g.mustCtl("journal", "verify")
	g.start()
	g.expectSuspended("after restore")
	// SR-7.9-1: roll the policy back; the suspension stays.
	g.mustCtl("policy", "rollback", "r1", "--as", "at19-rollback")
	g.expectSuspended("after a policy rollback")
	g.stop()

	// FR-13.8: an upgrade whose new smcpd never becomes healthy rolls back.
	upgradeRollback(t, g, pass)
}

// upgradeRollback installs the binaries into a directory, then upgrades to
// a release whose smcpd exits at once, and requires the rollback.
func upgradeRollback(t *testing.T, g *gateway, pass string) {
	t.Helper()
	work := t.TempDir()
	installed, badrel := filepath.Join(work, "installed"), filepath.Join(work, "bad-release")
	for _, d := range []string{installed, badrel} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, b := range []string{"smcpd", "smcpctl"} {
		raw, err := os.ReadFile(filepath.Join(binDir, b))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, installed, b, string(raw), 0o755)
		if b == "smcpctl" {
			writeFile(t, badrel, b, string(raw), 0o755)
		}
	}
	writeFile(t, badrel, "smcpd", "#!/bin/sh\nexit 1\n", 0o755)
	var sums strings.Builder
	for _, b := range []string{"smcpd", "smcpctl"} {
		raw, _ := os.ReadFile(filepath.Join(badrel, b))
		s := sha256.Sum256(raw)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(s[:]), b)
	}
	writeFile(t, badrel, "SHA256SUMS", sums.String(), 0o644)
	pidfile, logf := filepath.Join(work, "smcpd.pid"), filepath.Join(work, "smcpd.log")
	start := fmt.Sprintf(`nohup %q --config "$SMCP_CONFIG" >>%q 2>&1 & echo $! > %q`, filepath.Join(installed, "smcpd"), logf, pidfile)
	stopCmd := fmt.Sprintf(`p=$(cat %q 2>/dev/null); [ -n "$p" ] && kill "$p" 2>/dev/null; while [ -n "$p" ] && kill -0 "$p" 2>/dev/null; do sleep 0.1; done; true`, pidfile)
	t.Cleanup(func() { _ = exec.Command("sh", "-c", stopCmd).Run() })
	sh := exec.Command("sh", "-c", start)
	sh.Env = append(os.Environ(), "SMCP_CONFIG="+g.cfg)
	if out, err := sh.CombinedOutput(); err != nil {
		t.Fatalf("start: %v %s", err, out)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := g.ctl("health"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(logf)
			t.Fatalf("installed smcpd did not start:\n%s", b)
		}
		time.Sleep(200 * time.Millisecond)
	}
	cmd := exec.Command(filepath.Join(installed, "smcpctl"), "upgrade", "--config", g.cfg, "--release", badrel, "--bin-dir", installed,
		"--passphrase-file", pass, "--start-cmd", start, "--stop-cmd", stopCmd, "--health-timeout", "10s")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "previous version is running") {
		t.Fatalf("fault-injected upgrade: err %v\n%s", err, out)
	}
	if _, err := g.ctl("health"); err != nil {
		t.Fatalf("the previous version is not serving after the rollback: %v", err)
	}
	if err := exec.Command("sh", "-c", stopCmd).Run(); err != nil {
		t.Fatal(err)
	}
	if out := g.mustCtl("journal", "verify"); !strings.Contains(out, "journal OK") {
		t.Fatal(out)
	}
	if !strings.Contains(g.journalText(), "upgrade_rolled_back") {
		t.Fatal("upgrade_rolled_back is not in the journal")
	}
}

// expectSuspended requires that the suspended principal claude-code-local
// is not served: its sign-in is refused, or its calls are.
func (g *gateway) expectSuspended(when string) {
	g.t.Helper()
	tok, err := g.signIn("", approverPassword)
	if err != nil {
		g.t.Logf("%s: sign-in refused: %v", when, err)
		return
	}
	cs := g.session(tok)
	if text, isErr, err := call(cs, "ref_echo", map[string]any{"text": when}); err == nil && !isErr {
		g.t.Fatalf("the suspended principal was served %s: %q", when, text)
	}
}
