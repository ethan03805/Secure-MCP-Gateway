package library

import (
	"fmt"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestWindowsEnableRefusesShellLaunch: on Windows a native package whose
// executable is a batch file or a command interpreter is not enabled, with
// reason SHELL_LAUNCH (FR-21.11, SR-4.8-2); on other platforms the rule does
// not apply. Partial: the launch-time refusal and the process trace are in
// internal/pipeline and internal/winsandbox.
func TestWindowsEnableRefusesShellLaunch(t *testing.T) {
	reqtest.Partial(t, "FR-21.11", "SR-4.8-2")
	defer func(g string) { enableGOOS = g }(enableGOOS)
	enableGOOS = "windows"
	e := newEnv(t)
	for i, exe := range []string{"bin/run.cmd", "bin/RUN.BAT", "cmd.exe", "pwsh.exe", "tools/powershell.exe"} {
		id := fmt.Sprintf("sh%d", i)
		if _, err := e.lib.Import(e.pkg(pkgtest.Spec{ID: id, Revision: "1", Alias: id, Edit: func(m *packaging.Manifest, p *packaging.Provenance) {
			m.Launch.Runtime = "native"
			m.Launch.Argv = []string{exe}
		}}), ImportOptions{}); err != nil {
			t.Fatalf("import %s: %v", exe, err)
		}
		if _, err := e.lib.Enable(id, "1", EnableOptions{}); reason(err) != packaging.ReasonShellLaunch {
			t.Errorf("%s enabled or refused for another reason: %v", exe, err)
		}
	}
	if _, err := e.lib.Import(e.pkg(pkgtest.Spec{ID: "ok", Revision: "1", Alias: "ok"}), ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.lib.Enable("ok", "1", EnableOptions{}); err != nil {
		t.Fatalf("ordinary package refused: %v", err)
	}
	enableGOOS = "linux"
	if _, err := e.lib.Enable("sh0", "1", EnableOptions{}); reason(err) == packaging.ReasonShellLaunch {
		t.Fatal("the Windows rule applied on linux")
	}
}
