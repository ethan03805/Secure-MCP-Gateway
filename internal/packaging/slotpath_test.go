package packaging

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestSlotPathWindowsRules: the FR-21.25 rules for the host path of a
// filesystem slot, with the path resolution stubbed so they run on every
// platform: the case-insensitive path inside the grant is accepted, and a
// stream, a device name, a device prefix, a UNC host, a drive-relative
// form and a junction that leads outside the slot are refused with reason
// PATH_REFUSED. The resolution through GetFinalPathNameByHandle is tested
// on Windows (TestWindowsSlotPathJunction).
func TestSlotPathWindowsRules(t *testing.T) {
	reqtest.Partial(t, "FR-21.25")
	// The resolutions of a Windows host: C:\data\proj holds a junction
	// "out" to C:\Users; the other paths are themselves.
	long := func(p string) (string, error) {
		if strings.HasPrefix(strings.ToLower(p), `c:\missing`) {
			return "", fs.ErrNotExist
		}
		return p, nil
	}
	final := func(p string) (string, error) {
		lp := strings.ToLower(p)
		switch {
		case strings.HasPrefix(lp, `c:\data\proj\out`):
			return `C:\Users` + p[len(`C:\data\proj\out`):], nil
		case strings.HasPrefix(lp, `c:\data\proj`):
			return `C:\data\proj` + p[len(`C:\data\proj`):], nil
		case strings.HasPrefix(lp, `\data\proj`):
			return `C:` + p, nil
		}
		return p, nil
	}
	for _, p := range []string{`c:\DATA\Proj\x`, `C:\data\proj`, `\data\proj`, `C:\missing\dir`} {
		if err := checkWindowsSlot("work", p, long, final); err != nil {
			t.Errorf("%s refused: %v", p, err)
		}
	}
	denied := func(string) (string, error) { return "", errors.New("access is denied") }
	if err := checkWindowsSlot("work", `C:\data\proj`, long, denied); ReasonOf(err) != ReasonPathRefused {
		t.Errorf("an unresolvable slot: %v, want reason %s", err, ReasonPathRefused)
	}
	for _, p := range []string{`C:\data\proj\a.txt:hidden`, `C:\data\proj\NUL`, `C:\data\proj\com1.txt`, `\\?\C:\Windows`,
		`\\.\PhysicalDrive0`, `\\host\share`, `C:data`, `C:\data\proj\out`, `C:\data\proj\out\sub`, `data\proj`} {
		err := checkWindowsSlot("work", p, long, final)
		if ReasonOf(err) != ReasonPathRefused {
			t.Errorf("%s: %v, want reason %s", p, err, ReasonPathRefused)
		}
	}
}
