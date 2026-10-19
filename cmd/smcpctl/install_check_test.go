package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	linuxpkg "github.com/ethan03805/secure-mcp-gateway/packaging/linux"
)

// TestInstallCheck: `smcpctl install --check` (FR-13.5, FR-20.9) changes
// nothing, runs the embedded prerequisite check of install-enforced.sh with
// --host-only when not root, and names each missing prerequisite on a
// "  - " line, which the desktop setup shows before offering the Enforced
// profile.
func TestInstallCheck(t *testing.T) {
	reqtest.Partial(t, "FR-20.9", "FR-13.5")
	root := t.TempDir()
	hostRoot = root
	t.Cleanup(func() { hostRoot = "" })

	f := &fakeManager{t: t}
	home := t.TempDir()
	in, out := testInstaller(t, "linux", home, nil, f)
	in.root = root
	in.uid = 1000
	var argv []string
	f.script = func(a []string) error {
		argv = a
		fmt.Fprintf(in.out, "install-enforced: prerequisites missing; nothing was changed:\n  - podman\n  - kernel 6.8 or later (found 6.1.0)\n")
		return errors.New("exit status 2")
	}
	err := in.check("enforced")
	if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("missing prerequisites: %v", err)
	}
	if len(argv) != 4 || argv[0] != "bash" || filepath.Base(argv[1]) != "install-enforced.sh" || argv[2] != "--check" || argv[3] != "--host-only" {
		t.Fatalf("check argv %v", argv)
	}
	if got := missingLines(out.String()); strings.Join(got, "|") != "podman|kernel 6.8 or later (found 6.1.0)" {
		t.Fatalf("missing lines %q in %s", got, out)
	}

	// As root the root check stays in.
	in.uid = 0
	f.script = func(a []string) error { argv = a; return nil }
	if err := in.check("enforced"); err != nil {
		t.Fatal(err)
	}
	if len(argv) != 3 {
		t.Fatalf("root check argv %v", argv)
	}

	// Nothing on the host was touched: no CP-46 directory, unit or file.
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("check wrote %v", entries)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("check wrote %v in home", entries)
	}
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "bash ") {
			t.Fatalf("check ran %q", c)
		}
	}

	// Not Linux: refused with the reason on a "  - " line.
	mac, out := testInstaller(t, "darwin", home, nil, &fakeManager{t: t})
	if err := mac.check("enforced"); err == nil {
		t.Fatal("enforced check on darwin passed")
	}
	if got := missingLines(out.String()); len(got) != 1 || !strings.Contains(got[0], "Linux") {
		t.Fatalf("darwin: %q", out)
	}
	out.Reset()
	if err := mac.check("standalone"); err != nil || !strings.Contains(out.String(), "all prerequisites present") {
		t.Fatalf("standalone check: %v %s", err, out)
	}
	// Missing binaries are named.
	mac.binDir = t.TempDir()
	out.Reset()
	if err := mac.check("standalone"); err == nil || len(missingLines(out.String())) != 1 {
		t.Fatalf("standalone without binaries: %v %s", err, out)
	}
	if err := mac.check("other"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

// TestEnforcedScriptHostOnly runs the real embedded install-enforced.sh
// --check --host-only as the test user: root is not demanded, every
// missing prerequisite is listed and nothing is changed; --host-only
// without --check is refused.
func TestEnforcedScriptHostOnly(t *testing.T) {
	reqtest.Partial(t, "FR-20.9")
	bash, err := exec.LookPath("bash")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("needs bash")
	}
	dir := t.TempDir()
	if err := linuxpkg.Extract(dir); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "install-enforced.sh")
	out, err := exec.Command(bash, script, "--check", "--host-only").CombinedOutput()
	s := string(out)
	if strings.Contains(s, "root (run with sudo)") {
		t.Fatalf("--host-only still demands root:\n%s", s)
	}
	if err != nil && !strings.Contains(s, "prerequisites missing") {
		t.Fatalf("unexpected failure: %v\n%s", err, s)
	}
	if runtime.GOOS != "linux" && !strings.Contains(s, "  - Linux") {
		t.Fatalf("non-Linux host not named:\n%s", s)
	}
	if os.Getuid() != 0 {
		out, err := exec.Command(bash, script, "--check").CombinedOutput()
		if err == nil || !strings.Contains(string(out), "root (run with sudo)") {
			t.Fatalf("--check as a user did not demand root: %v\n%s", err, out)
		}
	}
	if out, err := exec.Command(bash, script, "--host-only").CombinedOutput(); err == nil || !strings.Contains(string(out), "--host-only needs --check") {
		t.Fatalf("--host-only alone: %v\n%s", err, out)
	}
}

func missingLines(out string) []string {
	var r []string
	for _, l := range strings.Split(out, "\n") {
		if s, ok := strings.CutPrefix(l, "  - "); ok {
			r = append(r, s)
		}
	}
	return r
}
