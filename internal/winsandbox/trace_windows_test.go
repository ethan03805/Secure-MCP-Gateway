//go:build windows

package winsandbox

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestWindowsProcessTrace: the trace job records a process the traced
// process starts, with its image and its parent, and its accounting counts
// it; the trace check then names cmd.exe as an interpreter started by the
// test binary (SR-4.8-2, the instrument of the Windows test-run trace).
func TestWindowsProcessTrace(t *testing.T) {
	reqtest.Partial(t, "SR-4.8-2")
	tr, err := TraceCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if out, err := exec.Command("cmd", "/c", "ping -n 2 127.0.0.1 >NUL").CombinedOutput(); err != nil {
		t.Fatalf("cmd: %v %s", err, out)
	}
	self := windows.GetCurrentProcessId()
	var found bool
	for deadline := time.Now().Add(5 * time.Second); !found && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		for _, r := range tr.Records() {
			found = found || (r.ParentPID == self && strings.EqualFold(baseName(r.Image), "cmd.exe"))
		}
	}
	if !found {
		t.Fatalf("cmd.exe not recorded: %+v", tr.Records())
	}
	total, err := tr.Total()
	if err != nil || total < 2 {
		t.Fatalf("accounting: %d processes, %v", total, err)
	}
	exe := Records(tr)
	if got := InterpreterStartedBy(exe, baseName(selfImage(t))); len(got) == 0 {
		t.Fatalf("the trace check does not name cmd.exe: %+v", exe)
	}
}

// Records adds the traced process itself, as a test harness would add the
// Gateway it started.
func Records(tr *ProcessTrace) []ProcessRecord {
	return append(tr.Records(), describeProcess(windows.GetCurrentProcessId()))
}

func selfImage(t *testing.T) string {
	t.Helper()
	r := describeProcess(windows.GetCurrentProcessId())
	if r.Image == "" {
		t.Fatal("own image unknown")
	}
	return r.Image
}
