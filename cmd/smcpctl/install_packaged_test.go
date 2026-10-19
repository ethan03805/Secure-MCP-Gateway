package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

// packagedBinDir lays out what the smcp .deb or .rpm installs, under a
// temporary root: <root>/usr/bin with smcpd, smcpctl and smcp-refserver,
// and the marker <root>/usr/lib/smcp/package-format.
func packagedBinDir(t *testing.T, format string) string {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "usr", "bin")
	if err := os.MkdirAll(filepath.Join(root, "usr", "lib", "smcp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"smcpd", "smcpctl", "smcp-refserver"} {
		copyBin(t, filepath.Join(binDir, b), filepath.Join(bin, b))
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "lib", "smcp", packageMarker), []byte(format+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return bin
}

// TestInstallEnforcedPackagedBinaries: when smcpctl, smcpd and
// smcp-refserver come from the smcp .deb or .rpm, `smcpctl install
// --profile enforced` uses them where the package put them. It runs
// install-enforced.sh with --packaged-bin (no copy into /usr/local/bin,
// which apt and dnf would never update) and bootstraps the example server
// from the package's smcp-refserver. Binaries from anywhere else are still copied
// (--bin-dir; TestInstallEnforcedFake).
func TestInstallEnforcedPackagedBinaries(t *testing.T) {
	for _, format := range []string{"deb", "rpm"} {
		t.Run(format, func(t *testing.T) {
			root := t.TempDir()
			hostRoot = root
			t.Cleanup(func() { hostRoot = "" })
			f := &fakeManager{t: t}
			in, out := testInstaller(t, "linux", t.TempDir(), nil, f)
			in.root, in.noStart = root, true
			pkgBin := packagedBinDir(t, format)
			in.binDir = pkgBin
			f.script = func(argv []string) error {
				if len(argv) != 4 || argv[2] != "--packaged-bin" || argv[3] != pkgBin {
					t.Fatalf("script argv %v, want --packaged-bin %s", argv, pkgBin)
				}
				for _, d := range []string{"/var/lib/smcp/state", "/etc/smcp"} {
					_ = os.MkdirAll(filepath.Join(root, d), 0o750)
				}
				return nil
			}
			if err := in.enforced(); err != nil {
				t.Fatalf("%v\n%s", err, out.String())
			}
			if !strings.Contains(out.String(), "present binaries in "+pkgBin+" from the smcp "+format+" package, used in place") {
				t.Fatalf("install does not say it uses the packaged binaries:\n%s", out.String())
			}
			if _, err := os.Stat(filepath.Join(root, "usr", "local", "bin")); err == nil {
				t.Fatal("install created /usr/local/bin under the host root")
			}
			if in.serviceBin != pkgBin {
				t.Fatalf("service binary directory %q, want %q", in.serviceBin, pkgBin)
			}
			if _, err := config.Load(filepath.Join(root, enforcedConfig)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestInstallEnforcedScriptOptions runs install-enforced.sh with option
// errors, which it reports before checking prerequisites or touching the
// host, so the test needs neither root nor Linux.
func TestInstallEnforcedScriptOptions(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil || runtime.GOOS == "windows" {
		t.Skip("needs bash")
	}
	script := filepath.Join("..", "..", "packaging", "linux", "install-enforced.sh")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--packaged-bin", "usr/bin"}, "--packaged-bin needs an absolute path"},
		{[]string{"--packaged-bin", "/usr/bin|x"}, "--packaged-bin needs an absolute path"},
		{[]string{"--packaged-bin", "/usr/bin", "--bin-dir", "/tmp"}, "exclude each other"},
	} {
		out, err := exec.Command("bash", append([]string{script}, c.args...)...).CombinedOutput()
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() != 2 || !strings.Contains(string(out), c.want) {
			t.Errorf("%v: exit %v, output %q; want exit 2 and %q", c.args, err, out, c.want)
		}
	}
	// The unit the packaged path writes: ExecStart rewritten to the
	// package's directory, everything else as in the repository.
	unit, err := os.ReadFile(filepath.Join("..", "..", "packaging", "linux", "systemd", "smcpd.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "\nExecStart=/usr/local/bin/smcpd --config /etc/smcp/smcp.toml\n") {
		t.Fatal("smcpd.service no longer has the ExecStart line install-enforced.sh --packaged-bin rewrites")
	}
	b, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `sed "s|^ExecStart=/usr/local/bin/smcpd |ExecStart=$pkg_bin/smcpd |"`) {
		t.Fatal("install-enforced.sh does not rewrite ExecStart for --packaged-bin")
	}
	aa, err := os.ReadFile(filepath.Join("..", "..", "packaging", "linux", "apparmor", "smcpd"))
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{"/usr/{,local/}bin/smcpd mr,", "/usr/{,local/}bin/smcp-refserver r,"} {
		if !strings.Contains(string(aa), rule) {
			t.Errorf("the smcpd AppArmor profile lacks %q (the packaged binaries run under it)", rule)
		}
	}
}
