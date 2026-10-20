//go:build windows

package acceptance

import (
	"os/exec"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

// setReadOnlyDir makes dir unwritable for this account, or writable again.
// Windows ignores the read-only attribute on a directory, so a deny entry
// for the account's write rights, inherited by the files below, stands in
// for mode 0500.
func setReadOnlyDir(t *testing.T, dir string, readOnly bool) {
	t.Helper()
	sid, err := winsec.ProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{dir, "/remove:d", "*" + sid}
	if readOnly {
		args = []string{dir, "/deny", "*" + sid + ":(OI)(CI)(W)"}
	}
	if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
		t.Fatalf("icacls %v: %v %s", args, err, out)
	}
}
