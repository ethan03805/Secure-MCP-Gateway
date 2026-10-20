//go:build windows

package packaging

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestWindowsSlotPathJunction: on Windows a filesystem slot is accepted
// under another letter case and through the runner's short (8.3) temporary
// directory name, and refused with reason PATH_REFUSED when it is a
// junction to a directory outside it, or a stream, device name, device
// prefix or UNC form (FR-21.25), at the slot check that ResolveLaunch and
// the machine-mode enable step run.
func TestWindowsSlotPathJunction(t *testing.T) {
	reqtest.Partial(t, "FR-21.25")
	root := t.TempDir() // a short name on the hosted runners (RUNNER~1)
	proj := filepath.Join(root, "Data", "Proj")
	if err := os.MkdirAll(filepath.Join(proj, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	junction := filepath.Join(proj, "out")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
	for _, p := range []string{proj, strings.ToUpper(proj), filepath.Join(strings.ToLower(proj), "x")} {
		if err := CheckSlotPath("work", p); err != nil {
			t.Errorf("%s refused: %v", p, err)
		}
	}
	for _, p := range []string{junction, proj + `\a.txt:hidden`, filepath.Join(proj, "NUL"), `\\?\` + proj, `\\localhost\C$\Windows`} {
		if err := CheckSlotPath("work", p); ReasonOf(err) != ReasonPathRefused {
			t.Errorf("%s: %v, want reason %s", p, err, ReasonPathRefused)
		}
	}
}
