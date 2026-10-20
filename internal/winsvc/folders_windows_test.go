//go:build windows

package winsvc

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestMachineFoldersIgnoreEnvironment: security review v1.3, SR-20. The
// machine mode places the service binary and its state in the folders
// Windows reports, not in the folders the ProgramFiles and ProgramData
// environment variables name, which a process of the user can set.
func TestMachineFoldersIgnoreEnvironment(t *testing.T) {
	reqtest.Partial(t, "FR-21.6")
	t.Setenv("ProgramFiles", t.TempDir())
	t.Setenv("ProgramData", t.TempDir())
	for _, c := range []struct {
		name string
		got  string
		id   *windows.KNOWNFOLDERID
	}{
		{"ProgramFiles", ProgramFiles(), windows.FOLDERID_ProgramFiles},
		{"ProgramData", ProgramData(), windows.FOLDERID_ProgramData},
	} {
		want, err := windows.KnownFolderPath(c.id, 0)
		if err != nil {
			t.Fatal(err)
		}
		if strings.EqualFold(c.got, os.Getenv(c.name)) {
			t.Errorf("%s follows the environment variable: %s", c.name, c.got)
		}
		if !strings.EqualFold(c.got, want) {
			t.Errorf("%s = %s, want the known folder %s", c.name, c.got, want)
		}
	}
}
