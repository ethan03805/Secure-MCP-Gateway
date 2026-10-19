package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsvc"
)

// winBinDir holds the test binaries under their Windows names.
func winBinDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for _, n := range []string{"smcpd", "smcp-refserver", "smcpctl"} {
		src := filepath.Join(binDir, exeName(runtime.GOOS, n))
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, n+".exe"), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

type fakeWin struct {
	version  winsvc.Version
	secured  []string
	runValue string
	daemon   *exec.Cmd
	noLaunch error // what launchSupported returns
}

func (w *fakeWin) hooks(t *testing.T) winHooks {
	return winHooks{
		launchSupported: func() error { return w.noLaunch },
		version:         func() winsvc.Version { return w.version },
		userSID:         func() (string, error) { return "S-1-5-21-1-2-3-1001", nil },
		secureDir:       func(d string) error { w.secured = append(w.secured, d); return nil },
		setRunValue:     func(c string) error { w.runValue = c; return nil },
		startDetached: func(exe string, args []string, dir string) (int, error) {
			// The supervisor flag exists only in the Windows build of smcpd;
			// the fake starts the Gateway itself.
			i := slices.Index(args, "-supervise")
			if i < 0 {
				t.Fatalf("smcpd started without -supervise: %v", args)
			}
			args = slices.Delete(slices.Clone(args), i, i+1)
			cmd := exec.Command(exe, args...)
			cmd.Dir = dir
			if err := cmd.Start(); err != nil {
				return 0, err
			}
			w.daemon = cmd
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			return cmd.Process.Pid, nil
		},
	}
}

func utf16Text(t *testing.T, b []byte) string {
	t.Helper()
	if len(b) < 2 || b[0] != 0xff || b[1] != 0xfe || len(b)%2 != 0 {
		t.Fatalf("task file is not UTF-16LE with a byte order mark")
	}
	u := make([]uint16, 0, len(b)/2-1)
	for i := 2; i < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return string(utf16.Decode(u))
}

// TestInstallWindowsUser runs the Windows per-user installation (FR-21.6)
// with the Windows calls faked: the CP-46 layout under %LOCALAPPDATA%, the
// DACL of each directory (FR-21.5), the task definition registered with
// schtasks /xml, the start of smcpd -supervise and the health check
// against the real Gateway, and the idempotent second run. Partial: the
// real Task Scheduler registration, the standard-user case and the
// restart after a failure are run on Windows by the windows CI job.
func TestInstallWindowsUser(t *testing.T) {
	reqtest.Partial(t, "FR-21.6", "FR-21.5")
	home := t.TempDir()
	local := filepath.Join(home, "AppData", "Local")
	f := &fakeManager{t: t}
	in, out := testInstaller(t, "windows", home, map[string]string{"LOCALAPPDATA": local}, f)
	in.binDir = winBinDir(t)
	w := &fakeWin{version: winsvc.Version{Major: 10, Build: 26100, Server: true}}
	in.win = w.hooks(t)
	l, err := in.layout()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(local, "smcp-gateway")
	if l.cfgDir != filepath.Join(base, "config") || l.stateDir != filepath.Join(base, "state") || l.logDir != filepath.Join(base, "log") {
		t.Fatalf("layout %+v", l)
	}
	if err := in.standalone(); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	exports := filepath.Join(base, "exports")
	for _, d := range []string{l.cfgDir, l.stateDir, l.logDir, exports} {
		if !slices.Contains(w.secured, d) {
			t.Errorf("DACL not set on %s (set: %v)", d, w.secured)
		}
	}
	cfgPath := filepath.Join(l.cfgDir, "smcp.toml")
	calls := strings.Join(f.calls, "\n")
	taskFile := filepath.Join(l.cfgDir, winTaskFile)
	if !strings.Contains(calls, "schtasks /create /tn smcp-gateway /xml "+taskFile+" /f") {
		t.Fatalf("schtasks not called: %v", f.calls)
	}
	b, err := os.ReadFile(taskFile)
	if err != nil {
		t.Fatal(err)
	}
	task := utf16Text(t, b)
	for _, want := range []string{"<UserId>S-1-5-21-1-2-3-1001</UserId>", "<LogonTrigger>", "<RunLevel>LeastPrivilege</RunLevel>",
		"<Command>" + filepath.Join(in.binDir, "smcpd.exe") + "</Command>", "-supervise -config", "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"} {
		if !strings.Contains(task, want) {
			t.Errorf("task definition lacks %q:\n%s", want, task)
		}
	}
	if w.daemon == nil || !strings.Contains(out.String(), "health: degraded") || !strings.Contains(out.String(), "not enforced") {
		t.Fatalf("not started or not healthy:\n%s", out.String())
	}
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg.Profile.Mode != "standalone" || cfg.State.Dir != l.stateDir {
		t.Fatalf("configuration: %+v %v", cfg, err)
	}

	// Second run: nothing new is created and smcpd is not started again.
	out.Reset()
	first := w.daemon
	if err := in.standalone(); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if w.daemon != first || !strings.Contains(out.String(), "present smcpd running") {
		t.Fatalf("second run:\n%s", out.String())
	}
	for _, s := range stepLines(out.String()) {
		if strings.HasPrefix(s, "created ") {
			t.Errorf("second run created: %s", s)
		}
	}
}

// TestInstallWindowsRunKeyFallback: when Windows refuses the task to the
// user, install writes the Run-key entry and prints the notice (FR-21.6).
func TestInstallWindowsRunKeyFallback(t *testing.T) {
	reqtest.Partial(t, "FR-21.6")
	home := t.TempDir()
	f := &fakeManager{t: t}
	in, out := testInstaller(t, "windows", home, map[string]string{"LOCALAPPDATA": filepath.Join(home, "L")}, f)
	in.binDir = winBinDir(t)
	in.noStart = true
	in.run = func(argv ...string) error {
		if argv[0] == "schtasks" {
			return errors.New("ERROR: Access is denied.")
		}
		return f.run(argv...)
	}
	w := &fakeWin{version: winsvc.Version{Major: 10, Build: 22631}}
	in.win = w.hooks(t)
	if err := in.standalone(); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	l, _ := in.layout()
	if !strings.Contains(w.runValue, `smcpd.exe`) || !strings.Contains(w.runValue, "-supervise -config") {
		t.Fatalf("Run value %q", w.runValue)
	}
	if _, err := os.Stat(filepath.Join(l.cfgDir, winRunFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(l.cfgDir, winTaskFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("task definition kept after the refusal: %v", err)
	}
	if !strings.Contains(out.String(), "Windows refused the Task Scheduler task") || !strings.Contains(out.String(), "does not restart it after a failure") {
		t.Fatalf("no notice:\n%s", out.String())
	}
}

// TestInstallWindowsVersionRefused: FR-21.1 with the reported build lowered
// below the minimum by the test hook; nothing is created.
func TestInstallWindowsVersionRefused(t *testing.T) {
	reqtest.Partial(t, "FR-21.1")
	for _, c := range []struct {
		v    winsvc.Version
		want string
	}{
		{winsvc.Version{Major: 10, Build: 22621}, "build 22621 is not supported: the Gateway needs Windows 11 version 23H2 (build 22631)"},
		{winsvc.Version{Major: 10, Build: 17763, Server: true}, "Windows Server 10.0 build 17763 is not supported: the Gateway needs Windows Server 2022 (build 20348)"},
	} {
		home := t.TempDir()
		f := &fakeManager{t: t}
		in, out := testInstaller(t, "windows", home, map[string]string{"LOCALAPPDATA": filepath.Join(home, "L")}, f)
		in.binDir = winBinDir(t)
		in.win = (&fakeWin{version: c.v}).hooks(t)
		err := in.standalone()
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "nothing was changed") {
			t.Fatalf("err = %v, want %q\n%s", err, c.want, out.String())
		}
		if _, err := os.Stat(filepath.Join(home, "L", "smcp-gateway")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("directories created after the refusal: %v", err)
		}
	}
	for _, ok := range []winsvc.Version{{Major: 10, Build: 22631}, {Major: 10, Build: 26100}, {Major: 10, Build: 20348, Server: true}, {Major: 10, Build: 26100, Server: true}} {
		if err := winsvc.CheckVersion(ok); err != nil {
			t.Errorf("%v refused: %v", ok, err)
		}
	}
}

// TestInstallWindowsWithoutLauncher: while server instances cannot be
// started on Windows (FR-21.11 not yet built), install configures no
// server, needs no smcp-refserver.exe, and smcpd starts healthy.
func TestInstallWindowsWithoutLauncher(t *testing.T) {
	reqtest.Partial(t, "FR-21.6")
	home := t.TempDir()
	f := &fakeManager{t: t}
	in, out := testInstaller(t, "windows", home, map[string]string{"LOCALAPPDATA": filepath.Join(home, "L")}, f)
	in.binDir = winBinDir(t)
	if err := os.Remove(filepath.Join(in.binDir, "smcp-refserver.exe")); err != nil {
		t.Fatal(err)
	}
	w := &fakeWin{version: winsvc.Version{Major: 10, Build: 26100}, noLaunch: errors.New("launch unsupported")}
	in.win = w.hooks(t)
	if err := in.standalone(); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	l, _ := in.layout()
	b, err := os.ReadFile(filepath.Join(l.cfgDir, "smcp.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "\n[[server]]") || strings.Contains(string(b), "The reference server below") || !strings.Contains(string(b), "No server is configured") {
		t.Fatalf("configuration still names a server:\n%s", b)
	}
	if !strings.Contains(out.String(), "no MCP server is configured") || !strings.Contains(out.String(), "health: degraded") {
		t.Fatalf("output:\n%s", out.String())
	}
}
