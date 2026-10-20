package winsandbox

import (
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestInterpreterStartedBy: the SR-4.8-2 trace check finds a command
// interpreter or batch file whose parent is smcpd, by image base name and
// case-insensitively, and ignores interpreters started by other processes
// (the test harness, a backend) and processes without an image.
func TestInterpreterStartedBy(t *testing.T) {
	reqtest.Partial(t, "SR-4.8-2")
	recs := []ProcessRecord{
		{PID: 10, ParentPID: 1, Image: `C:\Program Files\smcp-gateway\SMCPD.EXE`},
		{PID: 11, ParentPID: 10, Image: `C:\tmp\smcp-refserver.exe`},
		{PID: 12, ParentPID: 10, Image: `C:\Windows\System32\cmd.exe`},
		{PID: 13, ParentPID: 11, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{PID: 14, ParentPID: 1, Image: `C:\Windows\System32\cmd.exe`},
		{PID: 15, ParentPID: 10, Image: `C:\x\run.bat`},
		{PID: 16, ParentPID: 10, Image: ""},
	}
	got := InterpreterStartedBy(recs, "smcpd.exe")
	if len(got) != 2 || got[0].PID != 12 || got[1].PID != 15 {
		t.Fatalf("got %+v, want PIDs 12 and 15", got)
	}
	if got := InterpreterStartedBy(recs[1:], "smcpd.exe"); len(got) != 0 {
		t.Fatalf("without smcpd in the trace: %+v", got)
	}
}
