//go:build windows

package acceptance

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// smallVolumeWindows creates a 320 MB NTFS volume (a dynamically expanding
// VHDX) with diskpart, which needs an administrator (the hosted runner's
// account is one), gives it a free drive letter and returns its root; the
// volume is detached at the end of the test. A drive letter, not a folder
// mount point: a mount point is a reparse point, and a filesystem slot
// below one is refused (FR-21.25).
func smallVolumeWindows(t *testing.T) string {
	t.Helper()
	letter := ""
	for c := 'Z'; c >= 'M'; c-- {
		if _, err := os.Stat(string(c) + `:\`); err != nil {
			letter = string(c)
			break
		}
	}
	if letter == "" {
		skipScenario(t, "no free drive letter for the small volume", "AT-20")
	}
	// Not t.TempDir: the VHDX can stay locked for a moment after the
	// detach, which must not fail the test.
	dir, err := os.MkdirTemp("", "smcp-at20-")
	if err != nil {
		t.Fatal(err)
	}
	vhd := filepath.Join(dir, "at20.vhdx")
	diskpart := func(script string) ([]byte, error) {
		f := filepath.Join(dir, "diskpart.txt")
		if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		return exec.Command("diskpart", "/s", f).CombinedOutput()
	}
	out, err := diskpart(`create vdisk file="` + vhd + `" maximum=320 type=expandable
select vdisk file="` + vhd + `"
attach vdisk
create partition primary
format fs=ntfs quick label=smcpat20
assign letter=` + letter + `
`)
	if err != nil {
		_ = os.RemoveAll(dir)
		skipScenario(t, "a small file system on Windows needs diskpart as an administrator: "+err.Error()+" "+string(out), "AT-20")
	}
	t.Cleanup(func() {
		for range 10 {
			if _, err := diskpart(`select vdisk file="` + vhd + `"
detach vdisk
`); err == nil {
				break
			}
			time.Sleep(time.Second)
		}
		_ = os.RemoveAll(dir)
	})
	return letter + `:\`
}
