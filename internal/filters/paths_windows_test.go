//go:build windows

package filters

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestWindowsPathRules: the request filter's path canonicalization on
// Windows (FR-21.25): case-insensitive containment after resolution, a
// leading separator is absolute and never joined to a root, and streams,
// device names, device prefixes, UNC hosts and a junction leaving the root
// are refused, the Windows-only forms with reason PATH_REFUSED. Partial:
// the filesystem slots are tested in internal/packaging, and the
// comparison of the request-filter fixtures with Linux is not made here.
func TestWindowsPathRules(t *testing.T) {
	reqtest.Partial(t, "FR-21.25")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "Proj", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A junction inside the root that points outside it.
	outside := t.TempDir()
	junction := filepath.Join(root, "Proj", "out")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
	grant := filepath.Join(root, "Proj")
	for _, p := range []string{
		`/etc/passwd`, `\etc\passwd`, `C:\Windows\System32`, `..\..\x`, `../../x`,
		filepath.Join(grant, "a.txt") + ":hidden", filepath.Join(grant, "NUL"), filepath.Join(grant, "com1.txt"),
		`\\?\` + grant, `\\.\PhysicalDrive0`, `\\host\share\x`, `C:x`,
		filepath.Join(junction, "f.txt"), junction,
		"file:///C:/Windows/System32",
	} {
		if c, rule := CanonicalPath(p, []string{grant}); rule == "" {
			t.Errorf("%q allowed as %q", p, c)
		}
	}
	// The Windows-only forms carry reason PATH_REFUSED; a junction leaving
	// the root is PATH_OUTSIDE_ROOTS, as a symbolic link is on Linux.
	for _, p := range []string{filepath.Join(grant, "a.txt") + ":hidden", filepath.Join(grant, "NUL"), `\\?\` + grant,
		`\\.\PhysicalDrive0`, `\\host\share\x`, `C:x`} {
		if _, rule := CanonicalPath(p, []string{grant}); !windowsRule[rule] {
			t.Errorf("%q: rule %q, want a PATH_REFUSED rule", p, rule)
		}
	}
	if _, rule := CanonicalPath(filepath.Join(junction, "f.txt"), []string{grant}); rule != "outside-roots" {
		t.Errorf("junction: rule %q, want outside-roots", rule)
	}
	// Case-insensitive containment: a differently cased path inside the
	// root is the same directory.
	upper := strings.ToUpper(grant[:1]) + strings.ToLower(grant[1:])
	for in, want := range map[string]string{
		filepath.Join(upper, "sub", "x.txt"): filepath.Join(grant, "sub", "x.txt"),
		`sub\x.txt`:                          filepath.Join(grant, "sub", "x.txt"),
		"sub/x.txt":                          filepath.Join(grant, "sub", "x.txt"),
	} {
		c, rule := CanonicalPath(in, []string{grant})
		if rule != "" || !strings.EqualFold(c, want) {
			t.Errorf("%q: got %q %q, want %q", in, c, rule, want)
		}
	}
}
