package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestInstallGuideHasWalkthrough: docs/install.md carries the block that
// the install-guide job runs as written, and the block covers install with
// install.sh (the signature and checksum checks), the service install, the
// upgrade from release files and the uninstall.
func TestInstallGuideHasWalkthrough(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "install.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	const head = "<!-- ci-install-guide: standalone -->\n```sh\n"
	i := strings.Index(s, head)
	if i < 0 {
		t.Fatal("docs/install.md has no ci-install-guide: standalone block")
	}
	block := s[i+len(head):]
	end := strings.Index(block, "\n```\n")
	if end < 0 {
		t.Fatal("the walkthrough block is not closed")
	}
	block = block[:end]
	for _, want := range []string{"install.sh | sh -s -- --version", "smcpctl install ", "smcpctl upgrade ", "smcpctl uninstall ", "journal verify"} {
		if !strings.Contains(block, want) {
			t.Errorf("the walkthrough lacks %q", want)
		}
	}
}

// TestInstallGuideWalkthrough follows the install guide as written
// (FR-18.1): scripts/ci-install-guide.sh runs the Standalone walkthrough
// block of docs/install.md unchanged on a clean account: install.sh with
// its signature and checksum checks (v1.0.0), smcpctl install with the
// host's service manager, the upgrade to v1.1.0 from the downloaded
// release files, and uninstall with the kept journal verified. On Ubuntu
// it then runs the Enforced walkthrough block: install.sh (v1.0.0), sudo
// smcpctl install --profile enforced, the upgrade to v1.1.0 under
// systemd, and uninstall with the kept journal verified.
//
// It installs into the user's home and service manager, so it runs only
// with SMCP_INSTALL_GUIDE_TEST=1, in the CI job install-guide (macos-latest,
// arm64; ubuntu-24.04). The status job merges the results only when both
// runners reported. FR-18.1 stays partial: a rollback and the Homebrew
// and from-source options are not followed by this run.
func TestInstallGuideWalkthrough(t *testing.T) {
	if os.Getenv("SMCP_INSTALL_GUIDE_TEST") != "1" {
		t.Skip("installs a release into the user's home and service manager; set SMCP_INSTALL_GUIDE_TEST=1 on a disposable runner")
	}
	switch {
	case runtime.GOOS == "darwin" && runtime.GOARCH == "arm64", runtime.GOOS == "linux":
	default:
		t.Fatalf("FR-18.1 names clean macOS arm64 and Ubuntu hosts, not %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	reqtest.Partial(t, "FR-18.1")
	blocks := []string{"standalone"}
	if runtime.GOOS == "linux" {
		blocks = append(blocks, "enforced")
	}
	for _, name := range blocks {
		cmd := exec.Command("bash", filepath.Join("..", "..", "scripts", "ci-install-guide.sh"), name, t.TempDir())
		out, err := cmd.CombinedOutput()
		t.Logf("%s", out)
		if err != nil {
			t.Fatalf("ci-install-guide.sh %s: %v", name, err)
		}
		for _, want := range []string{"==> install-guide: passed " + name + " (" + runtime.GOOS + ")", "1.1.0", "journal OK"} {
			if !strings.Contains(string(out), want) {
				t.Fatalf("%s: output lacks %q", name, want)
			}
		}
	}
}
