package installsh

import (
	"crypto/rand"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"aead.dev/minisign"
)

// TestInstallScriptPackageUpgradeOnHost upgrades an installed smcp .deb
// with `sudo install.sh --package` on a disposable Ubuntu runner (the
// installers workflow, after scripts/package-smoke.sh). The new package is
// served over HTTPS as a release whose checksum file the test signs with a
// key of its own, passed with --pubkey; the release key itself signs only
// published releases.
//
//  1. The package of this build, repacked as version 0.0.1~upgrade-test,
//     is installed as the previous version, and a Standalone instance is
//     bootstrapped in a temporary directory.
//  2. A release whose package has one byte changed, and a release whose
//     checksum file another key signed, are refused before the package
//     manager runs: the previous version stays installed and no package
//     file is saved.
//  3. The intact release upgrades the package; the configuration, keys and
//     journal of the instance are byte-for-byte unchanged (FR-20.21) and
//     the journal verifies with the new smcpctl.
//
// SMCP_PACKAGE_UPGRADE_TEST=1, SMCP_UPGRADE_DEB (the .deb of this build) and
// SMCP_UPGRADE_VERSION (its release version, as GoReleaser reports it).
func TestInstallScriptPackageUpgradeOnHost(t *testing.T) {
	if os.Getenv("SMCP_PACKAGE_UPGRADE_TEST") != "1" {
		t.Skip("installs and upgrades the smcp package with sudo; set SMCP_PACKAGE_UPGRADE_TEST=1 on a disposable Ubuntu host")
	}
	deb, ver := os.Getenv("SMCP_UPGRADE_DEB"), os.Getenv("SMCP_UPGRADE_VERSION")
	if deb == "" || ver == "" || runtime.GOOS != "linux" {
		t.Fatal("needs Linux, SMCP_UPGRADE_DEB and SMCP_UPGRADE_VERSION")
	}
	deb, _ = filepath.Abs(deb)
	sh := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	installedVersion := func() string {
		out, _ := exec.Command("dpkg-query", "-W", "-f", "${Version}", "smcp").Output()
		return strings.TrimSpace(string(out))
	}
	if v := installedVersion(); v != "" {
		t.Fatalf("smcp %s is installed before the test; run on a clean host", v)
	}
	work := t.TempDir()
	if err := os.Chmod(work, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "remove", "-y", "-qq", "smcp").Run()
		// install.sh ran as root and saved the package there; the
		// temporary directory's own cleanup runs as this user.
		_ = exec.Command("sudo", "-n", "rm", "-rf", filepath.Join(work, "pkgs")).Run()
	})

	// 1. The previous version and an instance.
	newVer := sh("dpkg-deb", "-f", deb, "Version")
	tree := filepath.Join(work, "old")
	sh("dpkg-deb", "-R", deb, tree)
	ctl := filepath.Join(tree, "DEBIAN", "control")
	b, err := os.ReadFile(ctl)
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.Replace(string(b), "Version: "+newVer+"\n", "Version: 0.0.1~upgrade-test\n", 1))
	if err := os.WriteFile(ctl, b, 0o644); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(work, "smcp_0.0.1_old.deb")
	sh("dpkg-deb", "--root-owner-group", "-b", tree, old)
	sh("sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-qq", old)
	if v := installedVersion(); v != "0.0.1~upgrade-test" {
		t.Fatalf("previous version not installed: %q", v)
	}
	st := filepath.Join(work, "st")
	pw := filepath.Join(work, "approver")
	if err := os.WriteFile(pw, []byte("upgrade-approver-password-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sh("/usr/bin/smcpctl", "bootstrap", "--dir", st, "--bootstrap-token", "--approver-password-file", pw, "--port", "28543", "--admin-port", "28544")
	cfg := filepath.Join(st, "smcp.toml")
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The Standalone profile also on a runner that has Podman.
	if _, err := f.WriteString("\n[profile]\nmode = \"standalone\"\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	// smcpd of the previous version writes the journal, then stops.
	daemon := exec.Command("/usr/bin/smcpd", "--config", cfg)
	var logs strings.Builder
	daemon.Stdout, daemon.Stderr = &logs, &logs
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	healthy := false
	for i := 0; i < 60 && !healthy; i++ {
		healthy = exec.Command("/usr/bin/smcpctl", "health", "--config", cfg).Run() == nil
		if !healthy {
			_ = exec.Command("sleep", "1").Run()
		}
	}
	_ = daemon.Process.Signal(os.Interrupt)
	_ = daemon.Wait()
	if !healthy {
		t.Fatalf("smcpd of the previous version did not answer health:\n%s", logs.String())
	}
	if m, _ := filepath.Glob(filepath.Join(st, "state", "journal", "segment-*.jsonl")); len(m) == 0 {
		t.Fatal("no journal segment was written")
	}
	digests := func() string {
		var lines []string
		_ = filepath.Walk(st, func(p string, info os.FileInfo, err error) error {
			if err == nil && info.Mode().IsRegular() && !strings.Contains(p, "/log/") {
				b, _ := os.ReadFile(p)
				lines = append(lines, sumLine(b, p))
			}
			return nil
		})
		sort.Strings(lines)
		return strings.Join(lines, "")
	}
	before := digests()

	// The release: the package under its release name, signed checksums.
	body, err := os.ReadFile(deb)
	if err != nil {
		t.Fatal(err)
	}
	name := "smcp_" + strings.Replace(ver, "-", "~", 1) + "_" + runtime.GOARCH + ".deb"
	if filepath.Base(deb) != name {
		t.Fatalf("install.sh would look for %s; the build's package is %s", name, filepath.Base(deb))
	}
	sums := "smcp_" + ver + "_checksums.txt"
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(k minisign.PrivateKey, s []byte) []byte {
		return signPrehashed(k, s, "smcp "+ver+" file:"+sums)
	}
	sumsBody := []byte(sumLine(body, name))
	intact := release{name: body, sums: sumsBody, sums + ".minisig": sign(priv, sumsBody)}

	run := func(rel release) (string, error) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, ok := rel[strings.TrimPrefix(r.URL.Path, "/rel/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(b)
		}))
		defer srv.Close()
		ca := filepath.Join(work, "ca.pem")
		if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
			t.Fatal(err)
		}
		script, _ := filepath.Abs(filepath.Join("..", "..", "install.sh"))
		out, err := exec.Command("sudo", "-n", "env", "CURL_CA_BUNDLE="+ca, "SSL_CERT_FILE="+ca, "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
			"sh", script, "--version", "v"+ver, "--base-url", srv.URL+"/rel/", "--pubkey", pub.String(), "--no-cosign",
			"--package=deb", "--dir", filepath.Join(work, "pkgs")).CombinedOutput()
		t.Logf("install.sh --package:\n%s", out)
		return string(out), err
	}
	refused := func(what, out string, err error, want string) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: install.sh succeeded", what)
		}
		if !strings.Contains(out, want) {
			t.Fatalf("%s: the refusal does not say %q", what, want)
		}
		if v := installedVersion(); v != "0.0.1~upgrade-test" {
			t.Fatalf("%s: smcp %s is installed after the refusal", what, v)
		}
		if _, err := os.Stat(filepath.Join(work, "pkgs", name)); err == nil {
			t.Fatalf("%s: the refused package was saved", what)
		}
	}

	// 2. Refusals.
	tampered := clone(intact)
	tampered[name][len(body)/2] ^= 0x01
	out, err := run(tampered)
	refused("one byte of the package changed", out, err, "checksum mismatch for "+name)
	_, other, _ := minisign.GenerateKey(rand.Reader)
	forged := clone(intact)
	forged[sums+".minisig"] = sign(other, sumsBody)
	out, err = run(forged)
	refused("checksum file signed by another key", out, err, "does not verify")

	// 3. The upgrade.
	out, err = run(intact)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if !strings.Contains(out, "checksum verified") || !strings.Contains(out, "installed "+name) {
		t.Fatal("the upgrade output does not report the verified checksum and the installed package")
	}
	if v := installedVersion(); v != newVer {
		t.Fatalf("after the upgrade smcp %q is installed, not %q", v, newVer)
	}
	if got := sh("/usr/bin/smcpctl", "version", "--short"); got != ver {
		t.Fatalf("smcpctl version --short: %q, want %q", got, ver)
	}
	if after := digests(); after != before {
		t.Fatalf("the upgrade changed the instance's configuration, keys or journal:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	sh("/usr/bin/smcpctl", "journal", "verify", "--dir", filepath.Join(st, "state", "journal"), "--key", filepath.Join(st, "state", "keys", "evidence-genesis.pub"))
}
