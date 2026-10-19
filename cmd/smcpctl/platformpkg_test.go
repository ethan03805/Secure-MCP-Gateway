package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/harness"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// writeMarker writes a package-format marker file.
func writeMarker(t *testing.T, path, format string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(format+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestPackageFormatMarker: smcpctl recognizes binaries installed by the
// .deb or .rpm (/usr/bin with /usr/lib/smcp/package-format) and by the
// macOS .pkg (/usr/local/lib/smcp with the marker beside the binaries and
// links in /usr/local/bin), and nothing else.
func TestPackageFormatMarker(t *testing.T) {
	reqtest.Partial(t, "FR-20.22")
	root := t.TempDir()

	linux := filepath.Join(root, "linux")
	writeMarker(t, filepath.Join(linux, "usr/lib/smcp", packageMarker), "deb")
	if err := os.MkdirAll(filepath.Join(linux, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := packageFormat(filepath.Join(linux, "usr/bin")); got != "deb" {
		t.Errorf("deb layout: %q", got)
	}

	mac := filepath.Join(root, "mac")
	lib := filepath.Join(mac, "usr/local/lib/smcp")
	writeMarker(t, filepath.Join(lib, packageMarker), "pkg")
	if err := os.WriteFile(filepath.Join(lib, "smcpctl"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(mac, "usr/local/bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../lib/smcp/smcpctl", filepath.Join(bin, "smcpctl")); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{lib, bin} {
		if got := packageFormat(d); got != "pkg" {
			t.Errorf("pkg layout %s: %q", d, got)
		}
	}

	other := filepath.Join(root, "other/bin")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := packageFormat(other); got != "" {
		t.Errorf("no marker: %q", got)
	}
	writeMarker(t, filepath.Join(other, packageMarker), "tarball")
	if got := packageFormat(other); got != "" {
		t.Errorf("unknown format: %q", got)
	}
}

// TestUninstallKeepsPackagedBinaries: `smcpctl uninstall` leaves binaries
// that a platform package installed to the package manager and says how to
// remove them, and keeps the evidence (FR-20.22); `smcpctl upgrade`
// refuses to replace them.
func TestUninstallKeepsPackagedBinaries(t *testing.T) {
	reqtest.Partial(t, "FR-20.22")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	root := t.TempDir()
	bin := filepath.Join(root, "usr/bin")
	writeMarker(t, filepath.Join(root, "usr/lib/smcp", packageMarker), "rpm")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range releaseBinaries {
		if err := os.WriteFile(filepath.Join(bin, n), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dir, cfg := instance(t)
	var out bytes.Buffer
	if err := uninstallCmd([]string{"--config", cfg, "--bin-dir", bin}, strings.NewReader(""), &out); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out.String())
	}
	for _, n := range releaseBinaries {
		if _, err := os.Stat(filepath.Join(bin, n)); err != nil {
			t.Errorf("uninstall removed the packaged %s", n)
		}
	}
	if !strings.Contains(out.String(), "installed by the smcp rpm package; remove them with sudo dnf remove smcp") {
		t.Errorf("uninstall output does not name the package removal:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "keys", "evidence-genesis.pub")); err != nil {
		t.Errorf("uninstall without --purge removed the evidence key: %v", err)
	}

	err := upgradeCmd([]string{"--config", cfg, "--bin-dir", bin, "--release", t.TempDir()}, &out)
	if err == nil || !strings.Contains(err.Error(), "installed by the smcp rpm package") {
		t.Errorf("upgrade of packaged binaries: %v", err)
	}
}

// TestPackageRemovalStopsOnlySystemService: the .deb and .rpm pre-removal
// command (`smcpctl uninstall --package-removal`) stops, disables and
// removes the system units smcpd.service and smcp-nftables.service and
// nothing else: a user's systemd unit, the configuration, the state with
// the evidence journal and keys, and the backups stay (FR-20.22, owner
// decision: Linux package removal stops system services only).
func TestPackageRemovalStopsOnlySystemService(t *testing.T) {
	reqtest.Partial(t, "FR-20.22")
	root := t.TempDir()
	hostRoot = root
	t.Cleanup(func() { hostRoot = "" })
	keep := []string{
		"/etc/smcp/smcp.toml",
		"/var/lib/smcp/state/journal/segment-000001.jsonl",
		"/var/lib/smcp/state/keys/evidence-genesis.pub",
		"/var/lib/smcp/backups/smcp-backup-1.age",
		"/home/u/.config/systemd/user/smcpd.service",
		"/etc/systemd/system/smcpd.service.d/smcp-srv.conf",
	}
	gone := []string{"/etc/systemd/system/smcpd.service", "/etc/systemd/system/smcp-nftables.service"}
	for _, p := range append(append([]string{}, keep...), gone...) {
		writeMarker(t, filepath.Join(root, p), "x")
	}
	var calls []string
	run := func(argv ...string) error { calls = append(calls, strings.Join(argv, " ")); return nil }
	var out bytes.Buffer
	if err := packageRemoval(&out, "linux", run); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s\ncalls: %q", out.String(), calls)
	want := []string{"systemctl disable --now smcpd.service", "systemctl disable --now smcp-nftables.service", "systemctl daemon-reload"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls %q, want %q", calls, want)
	}
	for _, p := range gone {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			t.Errorf("%s not removed", p)
		}
	}
	for _, p := range keep {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Errorf("%s removed", p)
		}
	}
	for _, s := range []string{"smcpctl uninstall --purge", "smcpctl uninstall` as each user"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("output does not name %q", s)
		}
	}

	// Nothing installed: no systemctl call but nothing fails either; and
	// on macOS there is no system service.
	calls = nil
	out.Reset()
	if err := packageRemoval(&out, "linux", run); err != nil || len(calls) != 0 {
		t.Errorf("second run: %v %q", err, calls)
	}
	if err := packageRemoval(&out, "darwin", run); err != nil || len(calls) != 0 {
		t.Errorf("darwin: %v %q", err, calls)
	}
	// The flag takes no other arguments, so the pre-removal script cannot
	// be turned into a full uninstall.
	if err := uninstallCmd([]string{"--package-removal", "--purge"}, strings.NewReader(""), &out); err == nil {
		t.Error("--package-removal --purge accepted")
	}
}

// TestLinuxPackageScripts runs the pre-removal script of the .deb and .rpm
// with each argument dpkg and rpm pass: it runs `smcpctl uninstall
// --package-removal` on removal (dpkg remove or purge, rpm 0) and does
// nothing on upgrade, and it exits 0 even when smcpctl fails (FR-20.22).
func TestLinuxPackageScripts(t *testing.T) {
	reqtest.Partial(t, "FR-20.22", "FR-20.21")
	script, err := os.ReadFile(filepath.Join(repoRoot, "packaging/installers/linux/prerm.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(script), "/usr/bin/smcpctl") != 2 {
		t.Fatalf("prerm.sh should call /usr/bin/smcpctl in one place")
	}
	for _, exit := range []int{0, 1} {
		dir := t.TempDir()
		log := filepath.Join(dir, "calls")
		fake := filepath.Join(dir, "smcpctl")
		if err := os.WriteFile(fake, []byte("#!/bin/sh\necho \"$*\" >> "+log+"\nexit "+string(rune('0'+exit))+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		s := filepath.Join(dir, "prerm")
		if err := os.WriteFile(s, []byte(strings.ReplaceAll(string(script), "/usr/bin/smcpctl", fake)), 0o755); err != nil {
			t.Fatal(err)
		}
		for arg, removes := range map[string]bool{"remove": true, "purge": true, "0": true, "upgrade": false, "failed-upgrade": false, "deconfigure": false, "1": false, "2": false} {
			_ = os.Remove(log)
			if out, err := exec.Command("sh", s, arg).CombinedOutput(); err != nil {
				t.Errorf("prerm %s (smcpctl exit %d): %v %s", arg, exit, err, out)
			}
			b, _ := os.ReadFile(log)
			if got := strings.TrimSpace(string(b)); removes && got != "uninstall --package-removal" || !removes && got != "" {
				t.Errorf("prerm %s ran smcpctl with %q", arg, got)
			}
		}
	}
	// The packages have no other maintainer script.
	for _, name := range []string{"postinst.sh", "preinst.sh", "postrm.sh", "postinstall.sh", "preinstall.sh", "postremove.sh"} {
		if _, err := os.Stat(filepath.Join(repoRoot, "packaging/installers/linux", name)); err == nil {
			t.Errorf("packaging/installers/linux/%s exists", name)
		}
	}
}

// goreleaserBlock returns the top-level YAML block of .goreleaser.yaml
// that starts with key (without comment lines).
func goreleaserBlock(t *testing.T, key string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	in := false
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line != "" && line[0] != ' ' {
			in = strings.HasPrefix(line, key+":")
		}
		if in {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		t.Fatalf(".goreleaser.yaml has no %s block", key)
	}
	return strings.Join(out, "\n")
}

// TestLinuxPackageConfig inspects the nFPM configuration of the smcp .deb
// and .rpm: the binaries in /usr/bin (FR-20.18), no dependency, only
// root-owned files that users cannot write (SR-4.11-2), nothing under
// /etc, no unit and no install script (FR-20.21), only the pre-removal
// script (FR-20.22). scripts/package-smoke.sh checks the built packages.
func TestLinuxPackageConfig(t *testing.T) {
	reqtest.Partial(t, "FR-20.18", "FR-20.21", "SR-4.11-2")
	n := goreleaserBlock(t, "nfpms")
	for _, want := range []string{
		"package_name: smcp",
		"bindir: /usr/bin",
		"formats: [deb, rpm]",
		"ids: [smcpd, smcpctl, smcp-session, smcp-stdio, smcp-connect, smcp-refserver]",
		"preremove: packaging/installers/linux/prerm.sh",
	} {
		if !strings.Contains(n, want) {
			t.Errorf("nfpms lacks %q", want)
		}
	}
	for _, bad := range []string{"depends:", "recommends:", "suggests:", "postinstall:", "preinstall:", "postremove:", "/etc/", "systemd", "/var/", "/home"} {
		if strings.Contains(n, bad) {
			t.Errorf("nfpms contains %q", bad)
		}
	}
	dsts := regexp.MustCompile(`(?m)^\s+(?:- )?dst: (\S+)$`).FindAllStringSubmatch(n, -1)
	if len(dsts) < 5 {
		t.Fatalf("found only %d contents", len(dsts))
	}
	for _, m := range dsts {
		if !strings.HasPrefix(m[1], "/usr/share/doc/smcp") && !strings.HasPrefix(m[1], "/usr/lib/smcp") {
			t.Errorf("content installed outside the package's own paths: %s", m[1])
		}
	}
	infos := regexp.MustCompile(`file_info: \{ mode: (\d+), owner: (\w+), group: (\w+) \}`).FindAllStringSubmatch(n, -1)
	if len(infos) != len(dsts) {
		t.Errorf("%d contents, %d with mode root:root file_info", len(dsts), len(infos))
	}
	dirs := strings.Count(n, "type: dir")
	if dirs != 2 {
		t.Errorf("%d directories, want /usr/lib/smcp and /usr/share/doc/smcp", dirs)
	}
	for i, m := range infos {
		want := "0644"
		if i < dirs { // the directories come first
			want = "0755"
		}
		if m[1] != want || m[2] != "root" || m[3] != "root" {
			t.Errorf("file_info %v, want %s root:root", m[1:], want)
		}
	}
	for _, f := range []string{"deb", "rpm"} {
		b, err := os.ReadFile(filepath.Join(repoRoot, "packaging/installers/linux/package-format."+f))
		if err != nil || strings.TrimSpace(string(b)) != f {
			t.Errorf("package-format.%s: %q %v", f, b, err)
		}
	}
}

// TestInstallersInChecksumFile: the checksum file covers every artifact
// (no ids filter, so the .deb and .rpm are in it) and the installers built
// outside GoReleaser (the macOS .pkg, the smoke-tested Linux packages of
// the release workflow), which are also uploaded to the release, so the
// minisign signature and the Sigstore bundle of the checksum file cover
// every installer (FR-20.23).
func TestInstallersInChecksumFile(t *testing.T) {
	reqtest.Partial(t, "FR-20.23")
	c := goreleaserBlock(t, "checksum")
	if strings.Contains(c, "ids:") {
		t.Error("the checksum block filters artifacts by id")
	}
	if !strings.Contains(c, "glob: build/installers/*") {
		t.Error("the checksum file does not list build/installers/*")
	}
	if !strings.Contains(goreleaserBlock(t, "release"), "glob: build/installers/*") {
		t.Error("the release does not upload build/installers/*")
	}
	if !strings.Contains(goreleaserBlock(t, "signs"), "artifacts: checksum") {
		t.Error("the minisign signature is not over the checksum file")
	}
	wf, err := os.ReadFile(filepath.Join(repoRoot, ".github/workflows/release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"needs: installers", "uses: ./.github/workflows/installers.yml", "--skip=nfpm", "build/installers"} {
		if !strings.Contains(string(wf), want) {
			t.Errorf("release.yml lacks %q", want)
		}
	}
}

// TestMacPkgBuildScript inspects packaging/installers/macos/build-pkg.sh:
// pkgbuild and productbuild (FR-20.17), the binaries in /usr/local/lib/smcp
// with links in /usr/local/bin, root ownership (SR-4.11-2), an ad-hoc
// signature on each binary and none on the .pkg (FR-20.26), no install
// scripts (FR-20.21). The installers workflow installs the built package.
func TestMacPkgBuildScript(t *testing.T) {
	reqtest.Partial(t, "FR-20.17", "FR-20.26", "FR-20.21", "SR-4.11-2")
	b, err := os.ReadFile(filepath.Join(repoRoot, "packaging/installers/macos/build-pkg.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"pkgbuild --root", "productbuild --distribution", "--ownership recommended", "--install-location /",
		`codesign --force --sign - `, `ln -s "../lib/smcp/$b" "$root/usr/local/bin/$b"`,
		"binaries=(smcpd smcpctl smcp-session smcp-stdio smcp-connect smcp-refserver)",
		`overwrite-permissions="false"`, `hostArchitectures="arm64"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("build-pkg.sh lacks %q", want)
		}
	}
	var code []string
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			code = append(code, line)
		}
	}
	for _, bad := range []string{"--scripts", "productsign", "--sign \"Developer", "/Library/LaunchDaemons", "/Library/LaunchAgents"} {
		if strings.Contains(strings.Join(code, "\n"), bad) {
			t.Errorf("build-pkg.sh contains %q", bad)
		}
	}
	m, err := os.ReadFile(filepath.Join(repoRoot, "packaging/installers/macos/package-format"))
	if err != nil || strings.TrimSpace(string(m)) != "pkg" {
		t.Errorf("macos/package-format: %q %v", m, err)
	}
}

// TestMacPkgLinuxBuildScript inspects build-pkg-linux.sh, which builds the
// released .pkg on Linux (docs/ci.md, "macOS runners"): the same binaries,
// links, identifier and Distribution as build-pkg.sh, every payload and Bom
// entry owned by 0:0 (root:wheel, SR-4.11-2), an rcodesign ad-hoc
// signature on each binary and none on the .pkg (FR-20.26), no scripts
// (FR-20.21); installers.yml builds the .pkg with it, and the release
// lists the held-back .pkg in the checksum file (FR-20.23).
func TestMacPkgLinuxBuildScript(t *testing.T) {
	reqtest.Partial(t, "FR-20.17", "FR-20.26", "FR-20.21", "SR-4.11-2")
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	s := read("packaging/installers/macos/build-pkg-linux.sh")
	for _, want := range []string{
		"binaries=(smcpd smcpctl smcp-session smcp-stdio smcp-connect smcp-refserver)",
		"identifier=io.github.ethan03805.smcp", `ln -s "../lib/smcp/$b" "$root/usr/local/bin/$b"`,
		`"$RCODESIGN" sign --binary-identifier`, "CodeSignatureFlags(ADHOC)",
		`"$LS4MKBOM" -u 0 -g 0`, `"$MKBOM" -i`, "octal(0, 6) + octal(0, 6)", // uid, gid 0
		`overwrite-permissions="false"`, `postinstall-action="none"`, `hostArchitectures="arm64"`,
		`install-location="/"`, `auth="root"`, "#smcp-component.pkg",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("build-pkg-linux.sh lacks %q", want)
		}
	}
	for _, bad := range []string{"Scripts", "productsign", "/Library/LaunchDaemons", "/Library/LaunchAgents"} {
		if strings.Contains(s, bad) {
			t.Errorf("build-pkg-linux.sh contains %q", bad)
		}
	}
	if w := read(".github/workflows/installers.yml"); !strings.Contains(w, "bash packaging/installers/macos/build-pkg-linux.sh") ||
		!strings.Contains(w, "uses: ./.github/workflows/installers-macos-smoke.yml") {
		t.Error("installers.yml does not build the .pkg with build-pkg-linux.sh and smoke-test it on macOS")
	}
	if !strings.Contains(goreleaserBlock(t, "checksum"), "glob: build/installers-pending/*") {
		t.Error("the checksum file does not list build/installers-pending/*")
	}
	if strings.Contains(goreleaserBlock(t, "release"), "installers-pending") {
		t.Error("GoReleaser uploads the .pkg before its macOS smoke test")
	}
	if r := read(".github/workflows/release.yml"); !strings.Contains(r, `if: always() && needs.release.result == 'success'`) ||
		!strings.Contains(r, `grep -qx "$want  $pkg" "build/sums/$sums"`) {
		t.Error("release.yml does not upload the .pkg after its smoke test against the signed checksum file")
	}
}

// TestDoctorReportsWritableBinaries: `smcpctl doctor` reports a Gateway
// binary or its directory that the user running it can write (SR-4.11-2):
// a failing finding in the Enforced profile, a warning in Standalone, and
// nothing when the binaries are not writable (as the packages install
// them); run as root it says the check needs the agents' user.
func TestDoctorReportsWritableBinaries(t *testing.T) {
	reqtest.Partial(t, "SR-4.11-2")
	dir := t.TempDir()
	for _, n := range []string{"smcpd", "smcpctl"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(dir, "smcpctl")
	all := func(string) bool { return true }
	none := func(string) bool { return false }

	f := binaryWritableFindings(exe, 1000, true, all)
	if len(f) != 3 {
		t.Fatalf("enforced, writable: %d findings %v", len(f), f)
	}
	for _, x := range f {
		if x.Kind != harness.KindBinaryWritable || !x.Fails() {
			t.Errorf("enforced finding %+v does not fail", x)
		}
	}
	for _, x := range binaryWritableFindings(exe, 1000, false, all) {
		if x.Kind != harness.KindWarning || x.Fails() || !strings.HasPrefix(x.Message, "binary-writable: ") {
			t.Errorf("standalone finding %+v", x)
		}
	}
	if f := binaryWritableFindings(exe, 1000, true, none); len(f) != 1 || f[0].Fails() {
		t.Errorf("not writable: %v", f)
	}
	if f := binaryWritableFindings(exe, 0, true, all); len(f) != 1 || f[0].Fails() || !strings.Contains(f[0].Message, "root") {
		t.Errorf("as root: %v", f)
	}
	// The real access check sees this test's own writable temp files.
	if os.Geteuid() != 0 {
		if f := binaryWritableFindings(exe, os.Geteuid(), true, canWritePath); len(f) != 3 {
			t.Errorf("access(2) check: %v", f)
		}
	}
}
