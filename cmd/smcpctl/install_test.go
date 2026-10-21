package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// fakeManager stands in for launchctl and systemctl. Loading the launchd
// agent or starting the systemd unit starts the real smcpd from the test
// binaries with the configuration named in the unit, so that install's
// health check runs against a real Gateway.
type fakeManager struct {
	t      *testing.T
	cfg    func() string
	mu     sync.Mutex
	calls  []string
	loaded bool
	daemon *exec.Cmd
	// script handles `bash <install-enforced.sh> ...` (Enforced tests).
	script func(argv []string) error
}

func (f *fakeManager) start() {
	cmd := exec.Command(filepath.Join(binDir, "smcpd"), "--config", f.cfg())
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		f.t.Fatal(err)
	}
	f.daemon = cmd
	f.loaded = true
	f.t.Cleanup(f.stop)
}

func (f *fakeManager) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.daemon != nil && f.daemon.ProcessState == nil {
		_ = f.daemon.Process.Kill()
		_ = f.daemon.Wait()
	}
	f.daemon, f.loaded = nil, false
}

func (f *fakeManager) run(argv ...string) error {
	f.mu.Lock()
	f.calls = append(f.calls, strings.Join(argv, " "))
	f.mu.Unlock()
	switch {
	case argv[0] == "bash" && f.script != nil:
		return f.script(argv)
	case argv[0] == "launchctl" && argv[1] == "bootstrap":
		f.start()
	case argv[0] == "launchctl" && argv[1] == "bootout":
		f.stop()
	case argv[0] == "systemctl" && len(argv) > 2 && (argv[2] == "start" || argv[1] == "start"):
		f.start()
	}
	return nil
}

func (f *fakeManager) ok(argv ...string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "?"+strings.Join(argv, " "))
	switch {
	case argv[0] == "launchctl" && argv[1] == "print":
		return f.loaded
	case argv[0] == "systemctl" && strings.Contains(strings.Join(argv, " "), "is-enabled"):
		for _, c := range f.calls {
			if strings.Contains(c, " enable ") {
				return true
			}
		}
		return false
	case argv[0] == "systemctl" && strings.Contains(strings.Join(argv, " "), "is-active"):
		return f.loaded
	}
	return false
}

// digests returns the SHA-256 of every regular file under the given roots.
// It leaves out the running smcpd's journal health probe: a file the
// Health & Safety Monitor creates and removes in the journal directory
// every second (health.JournalWritable). It is not part of what install
// writes, and a walk can list it and then find it gone.
func digests(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, r := range roots {
		err := filepath.WalkDir(r, func(p string, d fs.DirEntry, err error) error {
			if err == nil && strings.HasPrefix(d.Name(), health.JournalProbePrefix) {
				return nil
			}
			if err != nil || d.IsDir() || !d.Type().IsRegular() {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			s := sha256.Sum256(b)
			out[p] = hex.EncodeToString(s[:])
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func stepLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		for _, v := range []string{"present ", "created ", "updated ", "skipped "} {
			if strings.HasPrefix(l, v) {
				lines = append(lines, l)
			}
		}
	}
	return lines
}

func testInstaller(t *testing.T, goos, home string, env map[string]string, f *fakeManager) (*installer, *bytes.Buffer) {
	t.Helper()
	pw := t.TempDir()
	var out bytes.Buffer
	in := &installer{goos: goos, home: home, getenv: func(k string) string { return env[k] }, uid: os.Getuid(),
		binDir: binDir, out: &out, run: f.run, ok: f.ok, healthWait: installHealthWait, win: defaultWinHooks(),
		chown:     func(string, string, string) error { return nil },
		chownTree: func(string, string, string) error { return nil },
		boot: bootstrapOpts{
			adminFile:    writeFile(t, pw, "admin.pw", "admin-password-123"),
			approverFile: writeFile(t, pw, "approver.pw", "approver-password-123"),
			notify:       "off", metricsPort: 0,
		}}
	in.boot.port = atoi(t, freePort(t))
	in.boot.adminPort = atoi(t, freePort(t))
	return in, &out
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestInstallStandalone(t *testing.T) {
	// FR-13.4 and FR-13.6 with the service manager faked: the launchd agent
	// (darwin) and the systemd user unit (linux) are written to a temporary
	// home and "loaded" by a fake launchctl or systemctl that starts the
	// real smcpd, so the health check is real; a real launchd or systemd
	// loading the unit is not exercised here (partial). The Enforced half
	// of FR-13.4 is TestInstallEnforcedFake.
	reqtest.Partial(t, "FR-13.4", "FR-13.6")
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			// A short home keeps paths readable in failures.
			home, err := os.MkdirTemp("", "smcp-home-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(home) })
			env := map[string]string{}
			if goos == "linux" {
				env["XDG_RUNTIME_DIR"] = filepath.Join(home, "run")
				if err := os.MkdirAll(env["XDG_RUNTIME_DIR"], 0o700); err != nil {
					t.Fatal(err)
				}
			}
			f := &fakeManager{t: t}
			in, out := testInstaller(t, goos, home, env, f)
			l, err := in.layout()
			if err != nil {
				t.Fatal(err)
			}
			cfgPath := filepath.Join(l.cfgDir, "smcp.toml")
			f.cfg = func() string { return cfgPath }

			if err := in.standalone(); err != nil {
				t.Fatalf("%v\n%s", err, out.String())
			}
			first := out.String()
			for _, want := range []string{"created directory " + l.cfgDir, "created directory " + l.stateDir, "created directory " + l.logDir,
				"created configuration " + cfgPath, "created service unit " + l.unit, "health: degraded", "This installation is not enforced"} {
				if !strings.Contains(first, want) {
					t.Errorf("first run lacks %q:\n%s", want, first)
				}
			}
			for _, d := range []string{l.cfgDir, l.stateDir, l.logDir} {
				if st, err := os.Stat(d); err != nil || st.Mode().Perm() != 0o700 {
					t.Errorf("%s: %v %v", d, st.Mode(), err)
				}
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Profile.Mode != "standalone" || cfg.State.Dir != l.stateDir || cfg.Log.File != filepath.Join(l.logDir, "smcpd.log") {
				t.Fatalf("profile %q state %q log %q", cfg.Profile.Mode, cfg.State.Dir, cfg.Log.File)
			}
			unit, _ := os.ReadFile(l.unit)
			smcpd := filepath.Join(binDir, "smcpd")
			switch goos {
			case "darwin":
				if !strings.Contains(string(unit), "<string>"+launchdLabel+"</string>") || !strings.Contains(string(unit), "<string>"+smcpd+"</string>") ||
					!strings.Contains(string(unit), "<string>"+xmlText(cfgPath)+"</string>") {
					t.Fatalf("plist:\n%s", unit)
				}
				if !strings.Contains(strings.Join(f.calls, "\n"), "launchctl bootstrap gui/") {
					t.Fatalf("launchctl not called: %v", f.calls)
				}
			case "linux":
				if !strings.Contains(string(unit), "ExecStart="+systemdQuote(smcpd)+" --config "+systemdQuote(cfgPath)) {
					t.Fatalf("unit:\n%s", unit)
				}
				if l.runtimeDir == "" || !strings.Contains(first, "created directory "+l.runtimeDir) {
					t.Fatalf("runtime directory: %q", l.runtimeDir)
				}
				calls := strings.Join(f.calls, "\n")
				for _, want := range []string{"systemctl --user daemon-reload", "systemctl --user enable --quiet smcpd.service", "systemctl --user start smcpd.service"} {
					if !strings.Contains(calls, want) {
						t.Fatalf("%q not called: %v", want, f.calls)
					}
				}
			}

			// Second run: every step present, files byte-for-byte unchanged.
			roots := []string{l.cfgDir, filepath.Join(l.stateDir, "keys"), filepath.Join(l.stateDir, "tls"), filepath.Join(l.stateDir, "journal"), l.unit}
			before := digests(t, roots...)
			out.Reset()
			if err := in.standalone(); err != nil {
				t.Fatalf("%v\n%s", err, out.String())
			}
			steps := stepLines(out.String())
			if len(steps) < 7 {
				t.Fatalf("second run reported %d steps:\n%s", len(steps), out.String())
			}
			for _, s := range steps {
				if !strings.HasPrefix(s, "present ") {
					t.Errorf("second run step not present: %s", s)
				}
			}
			after := digests(t, roots...)
			for p, d := range before {
				if after[p] != d {
					t.Errorf("%s changed on the second run", p)
				}
			}
			if len(after) != len(before) {
				t.Errorf("file count changed: %d -> %d", len(before), len(after))
			}
			if !strings.Contains(out.String(), "health: degraded") {
				t.Fatalf("second run health:\n%s", out.String())
			}
		})
	}
}

// TestInstallFromAppImage: setup run from an AppImage (FR-20.19) finds
// smcpctl on the image's mount, which exists only while the application
// runs. install copies the release binaries to
// $XDG_DATA_HOME/smcp-gateway/bin and the systemd user unit and the
// configuration name the copies, so the service still starts after the
// application quits.
func TestInstallFromAppImage(t *testing.T) {
	reqtest.Partial(t, "FR-20.19")
	home, err := os.MkdirTemp("", "smcp-home-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	env := map[string]string{
		"XDG_RUNTIME_DIR": filepath.Join(home, "run"),
		"APPIMAGE":        filepath.Join(home, "Downloads", "smcp-desktop.AppImage"),
		"APPDIR":          binDir,
	}
	if err := os.MkdirAll(env["XDG_RUNTIME_DIR"], 0o700); err != nil {
		t.Fatal(err)
	}
	f := &fakeManager{t: t}
	in, out := testInstaller(t, "linux", home, env, f)
	l, err := in.layout()
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(l.cfgDir, "smcp.toml")
	f.cfg = func() string { return cfgPath }
	if err := in.standalone(); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	copies := filepath.Join(home, ".local", "share", "smcp-gateway", "bin")
	for _, name := range []string{"smcpd", "smcpctl", "smcp-refserver"} {
		p := filepath.Join(copies, name)
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o755 {
			t.Fatalf("%s: %v %v", p, st, err)
		}
		if !strings.Contains(out.String(), "created binary "+p+" (from the AppImage "+env["APPIMAGE"]+")") {
			t.Errorf("no step for %s:\n%s", p, out.String())
		}
	}
	unit, _ := os.ReadFile(l.unit)
	if !strings.Contains(string(unit), "ExecStart="+systemdQuote(filepath.Join(copies, "smcpd"))+" --config ") {
		t.Fatalf("the unit does not run the copy:\n%s", unit)
	}
	// Nothing install wrote names the mount.
	for _, root := range []string{l.cfgDir, l.stateDir, l.unit} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if strings.Contains(string(b), binDir) {
				t.Errorf("%s names the AppImage mount %s", p, binDir)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// A second run finds the copies present.
	out.Reset()
	in.binDir = binDir
	if err := in.standalone(); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "present binary "+filepath.Join(copies, "smcpd")) {
		t.Fatalf("second run:\n%s", out.String())
	}
}

func TestInstallRefusals(t *testing.T) {
	reqtest.Partial(t, "FR-13.5")
	home := t.TempDir()
	f := &fakeManager{t: t}
	in, out := testInstaller(t, "freebsd", home, nil, f)
	if err := in.standalone(); err == nil || !strings.Contains(err.Error(), "macOS, Linux and Windows") {
		t.Fatalf("standalone on freebsd: %v", err)
	}
	in.goos = "darwin"
	if err := in.enforced(); err == nil || !strings.Contains(err.Error(), "needs Linux") {
		t.Fatalf("enforced on darwin: %v", err)
	}
	in.binDir = t.TempDir()
	if err := in.standalone(); err == nil || !strings.Contains(err.Error(), "smcpd not found") {
		t.Fatalf("missing binaries: %v", err)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("refused installs changed the home directory: %v\n%s", entries, out.String())
	}
	if len(f.calls) != 0 {
		t.Fatalf("refused installs ran %v", f.calls)
	}
}

func TestInstallEnforcedFake(t *testing.T) {
	// FR-13.5 with install-enforced.sh faked: install runs the embedded copy
	// of packaging/linux (checked byte-for-byte against the tree), stops
	// before writing anything when the script reports a missing
	// prerequisite, and otherwise writes /etc/smcp/smcp.toml with the
	// Enforced profile; a second run is all present (FR-13.4). The script's
	// own effects on a real host (identities, subordinate ranges, nftables,
	// AppArmor, units) are exercised by scripts/ci-systemd.sh, not here
	// (partial).
	reqtest.Partial(t, "FR-13.4", "FR-13.5")
	root := t.TempDir()
	hostRoot = root
	t.Cleanup(func() { hostRoot = "" })
	f := &fakeManager{t: t}
	in, out := testInstaller(t, "linux", t.TempDir(), nil, f)
	in.root, in.noStart = root, true

	// A host missing a prerequisite: the script exits 2 and nothing is written.
	f.script = func(argv []string) error { return errors.New("exit status 2") }
	if err := in.enforced(); err == nil || !strings.Contains(err.Error(), "install-enforced.sh stopped") {
		t.Fatalf("missing prerequisite: %v", err)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("a refused install wrote %v", entries)
	}

	var chowned []string
	in.chownTree = func(d, o, g string) error { chowned = append(chowned, d+" "+o+":"+g); return nil }
	in.chown = func(p, o, g string) error { chowned = append(chowned, p+" "+o+":"+g); return nil }
	scriptRuns := 0
	f.script = func(argv []string) error {
		scriptRuns++
		if len(argv) != 4 || argv[2] != "--bin-dir" || argv[3] != binDir {
			t.Fatalf("script argv %v", argv)
		}
		// The extracted tree is the repository's packaging/linux.
		dir := filepath.Dir(argv[1])
		for _, rel := range []string{"install-enforced.sh", "systemd/smcpd.service", "systemd/smcp-nftables.service", "nftables/smcp.nft", "apparmor/smcpd"} {
			got, err := os.ReadFile(filepath.Join(dir, rel))
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("..", "..", "packaging", "linux", rel))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("embedded %s differs from packaging/linux/%s", rel, rel)
			}
		}
		if st, _ := os.Stat(argv[1]); st.Mode().Perm()&0o100 == 0 {
			t.Fatal("extracted script is not executable")
		}
		// What the script does with --bin-dir and the state directory.
		for _, d := range []string{"/var/lib/smcp/state", "/usr/local/bin", "/etc/smcp"} {
			_ = os.MkdirAll(filepath.Join(root, d), 0o750)
		}
		copyBin(t, filepath.Join(binDir, "smcp-refserver"), filepath.Join(root, "/usr/local/bin/smcp-refserver"))
		return nil
	}
	if err := in.enforced(); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	cfgPath := filepath.Join(root, enforcedConfig)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile.Mode != "enforced" || cfg.Runtime.Sandbox != "podman" || cfg.State.Dir != filepath.Join(root, enforcedState) ||
		cfg.Policy.File != filepath.Join(root, enforcedPolicyDir, "policy.json") {
		t.Fatalf("profile %q sandbox %q state %q policy %q", cfg.Profile.Mode, cfg.Runtime.Sandbox, cfg.State.Dir, cfg.Policy.File)
	}
	// Backups go where smcpd can write and purge does not delete
	// (/var/lib/smcp/backups, created by install-enforced.sh), not next
	// to the read-only configuration (found by the install-guide job:
	// the upgrade's backup failed on /etc/smcp/backups).
	if cfg.Backup.Dir != filepath.Join(root, enforcedBackups) {
		t.Fatalf("backup dir %q", cfg.Backup.Dir)
	}
	script, _ := os.ReadFile(filepath.Join("..", "..", "packaging", "linux", "install-enforced.sh"))
	if !strings.Contains(string(script), "ensure_dir "+enforcedBackups+" smcp-core") {
		t.Fatal("install-enforced.sh does not create the backup directory for smcp-core")
	}
	if st, _ := os.Stat(cfgPath); st.Mode().Perm() != 0o640 {
		t.Fatalf("config mode %v", st.Mode())
	}
	// The client view (CP-46 public/): the CA certificate and the addresses,
	// world-readable, nothing secret, for users who cannot read /etc/smcp.
	pub := filepath.Join(root, config.EnforcedPublicDir)
	if !strings.Contains(string(script), "ensure_dir "+config.EnforcedPublicDir+" smcp-core \"$group\" 0755") {
		t.Fatal("install-enforced.sh does not create the client view directory for smcp-core, mode 0755")
	}
	stateCA, _ := os.ReadFile(filepath.Join(root, enforcedState, keys.CACertFile))
	pubCA, err := os.ReadFile(filepath.Join(pub, config.PublicCAFile))
	if err != nil || len(stateCA) == 0 || !bytes.Equal(pubCA, stateCA) {
		t.Fatalf("published CA differs from the state CA (%v)", err)
	}
	view, err := config.LoadClientView(pub)
	if err != nil {
		t.Fatal(err)
	}
	if view.Profile != "enforced" || view.MCPURL != cfg.ResourceURI() || view.AdminURL != cfg.AdminURL() || view.CAFile != filepath.Join(pub, config.PublicCAFile) {
		t.Fatalf("client view %+v", view)
	}
	for _, f := range []string{config.PublicCAFile, config.ClientViewFile} {
		if st, err := os.Stat(filepath.Join(pub, f)); err != nil || st.Mode().Perm() != 0o644 {
			t.Fatalf("%s: %v %v", f, err, st)
		}
	}
	rawView, _ := os.ReadFile(filepath.Join(pub, config.ClientViewFile))
	for _, secret := range []string{"argon2", "password", "token", "secret", "PRIVATE KEY"} {
		if strings.Contains(strings.ToLower(string(rawView)), strings.ToLower(secret)) {
			t.Fatalf("client view mentions %q: %s", secret, rawView)
		}
	}
	if _, err := os.Stat(filepath.Join(root, enforcedPolicyDir, "smcp.toml")); err == nil {
		t.Fatal("bootstrap copy of smcp.toml left in the policy directory")
	}
	ch := strings.Join(chowned, "\n")
	for _, want := range []string{filepath.Join(root, enforcedState) + " smcp-core:smcp", filepath.Join(root, enforcedPolicyDir) + " smcp-core:smcp", cfgPath + " root:smcp", pub + " smcp-core:smcp"} {
		if !strings.Contains(ch, want) {
			t.Fatalf("not chowned: %s\n%s", want, ch)
		}
	}
	if !strings.Contains(out.String(), "created configuration "+cfgPath) {
		t.Fatal(out.String())
	}

	before := digests(t, filepath.Join(root, "etc"), filepath.Join(root, "var"))
	out.Reset()
	if err := in.enforced(); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, s := range stepLines(out.String()) {
		if !strings.HasPrefix(s, "present ") && !strings.HasPrefix(s, "skipped ") {
			t.Errorf("second run step: %s", s)
		}
	}
	after := digests(t, filepath.Join(root, "etc"), filepath.Join(root, "var"))
	for p, d := range before {
		if after[p] != d {
			t.Errorf("%s changed on the second run", p)
		}
	}
	if scriptRuns != 2 {
		t.Fatalf("script ran %d times", scriptRuns)
	}
}

func TestInstallUnitQuoting(t *testing.T) {
	u := string(systemdUserUnit(`/opt/my bin/smcpd`, `/home/a%b/"c".toml`))
	if !strings.Contains(u, `ExecStart="/opt/my bin/smcpd" --config "/home/a%%b/\"c\".toml"`) {
		t.Fatal(u)
	}
	p := string(launchdPlist("/a&b/smcpd", "/c<d>.toml", "/logs"))
	if !strings.Contains(p, "<string>/a&amp;b/smcpd</string>") || !strings.Contains(p, "<string>/c&lt;d&gt;.toml</string>") {
		t.Fatal(p)
	}
}

func TestWithInstalledConfig(t *testing.T) {
	root := t.TempDir()
	hostRoot = root
	t.Cleanup(func() { hostRoot = "" })
	t.Chdir(t.TempDir())
	if got := withInstalledConfig([]string{"--purge"}); strings.Join(got, " ") != "--purge" && !strings.Contains(strings.Join(got, " "), standaloneConfigPath()) {
		t.Fatalf("%v", got)
	}
	_ = os.MkdirAll(filepath.Join(root, "etc", "smcp"), 0o750)
	writeFile(t, filepath.Join(root, "etc", "smcp"), "smcp.toml", "x")
	if got := withInstalledConfig([]string{"--purge"}); len(got) != 3 || got[1] != filepath.Join(root, enforcedConfig) {
		t.Fatalf("%v", got)
	}
	if got := withInstalledConfig([]string{"--config", "x.toml"}); len(got) != 2 {
		t.Fatalf("%v", got)
	}
}
