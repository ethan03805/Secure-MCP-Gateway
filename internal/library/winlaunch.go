package library

import (
	"runtime"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsandbox"
)

// enableGOOS is the platform whose launch rules Enable applies; tests
// change it.
var enableGOOS = runtime.GOOS

// checkWindowsLaunch refuses, on Windows, to enable a native package whose
// executable is a command interpreter or a batch file, with reason
// SHELL_LAUNCH (FR-21.11, SR-4.8-2). Interpreter runtimes (node, python)
// run the configured interpreter, which the launch itself checks.
func checkWindowsLaunch(m *packaging.Manifest) error {
	if enableGOOS != "windows" || m.Launch.Runtime != "native" || len(m.Launch.Argv) == 0 {
		return nil
	}
	if err := winsandbox.CheckCommand(m.Launch.Argv[0]); err != nil {
		return errf(packaging.ReasonShellLaunch, "%v", err)
	}
	return nil
}
