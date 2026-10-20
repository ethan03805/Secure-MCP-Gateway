package packaging

import (
	"errors"
	"fmt"
	"io/fs"
	"runtime"

	"github.com/ethan03805/secure-mcp-gateway/internal/winpath"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

// ReasonPathRefused refuses a filesystem slot whose host path breaks the
// Windows path rules of FR-21.25. It is also the request filter's reason
// for the same forms in a path argument (SRS Appendix B).
const ReasonPathRefused = "PATH_REFUSED"

// slotRuleText explains each winpath rule in a refusal.
var slotRuleText = map[string]string{
	winpath.RuleStream:        "names an alternate data stream",
	winpath.RuleDeviceName:    "names a reserved Windows device",
	winpath.RuleDevicePrefix:  "uses a Windows device path prefix",
	winpath.RuleUNC:           "names a network share",
	winpath.RuleDriveRelative: "is relative to a drive's current directory",
}

// CheckSlotPath applies the Windows path rules of FR-21.25 to the host path
// of a filesystem slot (enable and start): an alternate data stream, a
// reserved device name, a device prefix, a UNC host or a drive-relative
// form is refused, and so is a path whose final path (after junctions and
// symbolic links) is not the path itself or below it, compared
// case-insensitively after expanding short (8.3) names. Off Windows it
// returns nil; the POSIX checks of ResolveLaunch apply there.
func CheckSlotPath(slot, p string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	return checkWindowsSlot(slot, p, winsec.LongPath, winsec.FinalPath)
}

// checkWindowsSlot is CheckSlotPath with the path resolution passed in, so
// the rules are tested on every platform: long expands short names
// without following links, final follows them. A path that cannot be
// resolved because it does not exist is left to the directory check; any
// other resolution error refuses the slot.
func checkWindowsSlot(slot, p string, long, final func(string) (string, error)) error {
	if rule := winpath.Refused(p); rule != "" {
		return Errf(ReasonPathRefused, "slot %q path %q %s (FR-21.25)", slot, p, slotRuleText[rule])
	}
	if !winpath.IsAbs(p) {
		return Errf(ReasonPathRefused, "slot %q path %q must be absolute (FR-21.25)", slot, p)
	}
	lexical, err := long(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // left to the directory check of ResolveLaunch
	}
	if err != nil {
		return Wrap(ReasonPathRefused, fmt.Sprintf("slot %q path %q cannot be resolved (FR-21.25)", slot, p), err)
	}
	f, err := final(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return Wrap(ReasonPathRefused, fmt.Sprintf("slot %q path %q cannot be resolved (FR-21.25)", slot, p), err)
	}
	if len(lexical) >= 1 && (lexical[0] == '\\' || lexical[0] == '/') && len(f) >= 2 && f[1] == ':' {
		lexical = f[:2] + lexical // rooted on the current drive
	}
	if !winpath.Within(f, lexical) {
		return Errf(ReasonPathRefused, "slot %q path %q resolves through a junction or link to %q, outside itself (FR-21.25)", slot, p, f)
	}
	return nil
}
