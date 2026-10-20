package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func readRepo(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestDesktopMsiBuildAndRelease: the smcp-desktop .msi (FR-20.20) carries
// the six commands of the smcp .msi beside the application with the msi
// package marker, embeds the WebView2 bootstrapper, is built for
// windows-amd64 and windows-arm64 and smoke-tested on windows-latest and
// windows-11-arm before it is uploaded, and the release counts it among
// the installers of the signed checksum file (FR-20.23). The install,
// start and removal themselves run in installers.yml
// (scripts/desktop-msi-smoke.ps1).
func TestDesktopMsiBuildAndRelease(t *testing.T) {
	reqtest.Partial(t, "FR-20.20", "FR-20.23")
	build := readRepo(t, "packaging/installers/desktop/build-msi.ps1")
	for _, b := range []string{"smcpd", "smcpctl", "smcp-session", "smcp-stdio", "smcp-connect", "smcp-refserver"} {
		if !strings.Contains(build, "'"+b+"'") {
			t.Errorf("build-msi.ps1 does not bundle %s", b)
		}
	}
	for _, want := range []string{
		`packaging\installers\windows\package-format`, // the marker smcpctl reads
		"--bundles msi",
		`smcp-desktop_{0}_windows_{1}.msi`,
		"PeMachine", // each binary is checked for the package's architecture
	} {
		if !strings.Contains(build, want) {
			t.Errorf("build-msi.ps1 lacks %q", want)
		}
	}
	if marker := strings.TrimSpace(readRepo(t, "packaging/installers/windows/package-format")); marker != "msi" {
		t.Errorf("package marker %q", marker)
	}
	conf := readRepo(t, "desktop/src-tauri/tauri.conf.json")
	if !regexp.MustCompile(`"webviewInstallMode":\s*\{\s*"type":\s*"embedBootstrapper"`).MatchString(conf) {
		t.Error("tauri.conf.json does not embed the WebView2 bootstrapper")
	}

	wf := readRepo(t, ".github/workflows/installers.yml")
	job := regexp.MustCompile(`(?ms)^  build-desktop-windows:\n.*?(?:\n  [a-z]|\z)`).FindString(wf)
	if job == "" {
		t.Fatal("installers.yml has no build-desktop-windows job")
	}
	for _, want := range []string{
		"needs: build-windows",
		"{ arch: amd64, wix: x64, runner: windows-latest }",
		"{ arch: arm64, wix: arm64, runner: windows-11-arm }",
		"./packaging/installers/desktop/build-msi.ps1",
		"./scripts/desktop-msi-smoke.ps1",
		"name: installers-desktop-windows-${{ matrix.arch }}",
	} {
		if !strings.Contains(job, want) {
			t.Errorf("build-desktop-windows lacks %q", want)
		}
	}
	// The package is uploaded only after the smoke test.
	if strings.Index(job, "desktop-msi-smoke.ps1") > strings.Index(job, "actions/upload-artifact") {
		t.Error("the .msi is uploaded before its smoke test")
	}
	smoke := readRepo(t, "scripts/desktop-msi-smoke.ps1")
	for _, want := range []string{"InvokeBootstrapper", "Get-Service smcpd", `Classes\smcp`, "does not chain to the Gateway CA", "LocalMachine\\Root", "smcp://approvals", "msiexec.exe -ArgumentList @('/x'"} {
		if !strings.Contains(smoke, want) {
			t.Errorf("desktop-msi-smoke.ps1 lacks %q", want)
		}
	}

	rel := readRepo(t, ".github/workflows/release.yml")
	for _, want := range []string{`smcp-desktop_${version}_windows_amd64.msi`, `smcp-desktop_${version}_windows_arm64.msi`} {
		if !strings.Contains(rel, want) {
			t.Errorf("release.yml does not expect %s", want)
		}
	}
	m := regexp.MustCompile(`\[ "\$n" -ge (\d+) \]`).FindStringSubmatch(rel)
	if m == nil {
		t.Fatal("release.yml does not count the installers")
	}
	// .deb x2, .rpm x2, .pkg, smcp .msi x2, desktop .deb x2, .rpm x2,
	// AppImage x2, smcp-desktop .msi x2 (the .dmg may be missing).
	if n, _ := strconv.Atoi(m[1]); n < 15 {
		t.Errorf("release.yml expects at least %d installers, want 15", n)
	}
}
