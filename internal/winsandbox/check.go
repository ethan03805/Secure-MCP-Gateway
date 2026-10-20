package winsandbox

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrShellLaunch is returned by CheckCommand for a command interpreter or a
// batch file (FR-21.11, SR-4.8-2).
var ErrShellLaunch = errors.New("a command interpreter or batch file cannot be a server executable on Windows (SR-4.8-2)")

// interpreters are the programs SR-4.8-2 names, without extension.
var interpreters = []string{"cmd", "powershell", "pwsh"}

// CheckCommand refuses an executable path that Windows would run through a
// command interpreter, or that is one: a .bat or .cmd file, cmd.exe,
// powershell.exe or pwsh.exe (FR-21.11, SR-4.8-2). The path is read with
// Windows semantics on every platform, so a manifest can be checked
// anywhere: both slashes separate, case is ignored, and trailing dots and
// spaces, which Windows strips from a file name, are stripped first. A
// path that names an alternate data stream is refused too.
//
// A renamed copy of an interpreter is not recognized by name; that is a
// limit of this rule (SR-4.8-2 binds the Server Runtime Manager only, and
// the machine-mode containment limits what any backend starts).
func CheckCommand(path string) error {
	base := path
	if i := strings.LastIndexAny(base, `\/`); i >= 0 {
		base = base[i+1:]
	} else if len(base) >= 2 && base[1] == ':' {
		base = base[2:] // "C:cmd.exe", relative to the drive's directory
	}
	if strings.Contains(base, ":") {
		return fmt.Errorf("%w: %q names an alternate data stream", ErrShellLaunch, path)
	}
	base = strings.ToLower(strings.TrimRight(base, ". "))
	name, ext := base, ""
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		name, ext = base[:i], base[i:]
	}
	if ext == ".bat" || ext == ".cmd" {
		return fmt.Errorf("%w: %q is a batch file, which Windows runs through cmd.exe", ErrShellLaunch, path)
	}
	if slices.Contains(interpreters, name) && (ext == "" || ext == ".exe" || ext == ".com") {
		return fmt.Errorf("%w: %q is a command interpreter", ErrShellLaunch, path)
	}
	return nil
}
