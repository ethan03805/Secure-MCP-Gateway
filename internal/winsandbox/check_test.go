package winsandbox

import (
	"errors"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestCheckCommand: the interpreters and batch files of SR-4.8-2 are refused
// in every spelling Windows accepts for them; ordinary executables are not.
// Partial for FR-21.11 and SR-4.8-2: the refusal at enablement and launch and
// the process trace are in the Windows tests of internal/pipeline and
// internal/library.
func TestCheckCommand(t *testing.T) {
	reqtest.Partial(t, "FR-21.11", "SR-4.8-2")
	refused := []string{
		`C:\Windows\System32\cmd.exe`,
		`C:\Windows\System32\CMD.EXE`,
		`C:/Windows/System32/cmd.exe`,
		`C:\Windows\System32\cmd`,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`C:\Program Files\PowerShell\7\pwsh.exe`,
		`C:\tools\run.bat`,
		`C:\tools\run.BAT`,
		`C:\tools\run.cmd`,
		`C:\tools\run.cmd.`,
		`C:\tools\run.bat . .`,
		`C:\tools\cmd.exe.`,
		`C:\tools\run.bat::$DATA`,
		`C:\tools\server.exe:hidden`,
		`C:cmd.exe`,
		`\\?\C:\Windows\System32\cmd.exe`,
		`C:\Windows\System32\cmd.com`,
	}
	for _, p := range refused {
		if err := CheckCommand(p); !errors.Is(err, ErrShellLaunch) {
			t.Errorf("CheckCommand(%q) = %v, want ErrShellLaunch", p, err)
		}
	}
	allowed := []string{
		`C:\Program Files\nodejs\node.exe`,
		`C:\srv\server.exe`,
		`C:\srv\cmdline-tool.exe`,
		`C:\srv\batch.exe`,
		`C:\srv\pwsh-helper.exe`,
		`C:\srv\bat`,
		`/usr/local/bin/server`,
	}
	for _, p := range allowed {
		if err := CheckCommand(p); err != nil {
			t.Errorf("CheckCommand(%q) = %v, want nil", p, err)
		}
	}
}

func TestCPURate(t *testing.T) {
	for _, c := range []struct {
		cpus float64
		n    int
		want uint32
	}{
		{1, 4, 2500}, {0.5, 2, 2500}, {4, 4, 0}, {8, 4, 0}, {0, 4, 0}, {1e-6, 64, 1}, {1.5, 8, 1875},
	} {
		if got := cpuRate(c.cpus, c.n); got != c.want {
			t.Errorf("cpuRate(%v, %d) = %d, want %d", c.cpus, c.n, got, c.want)
		}
	}
}
