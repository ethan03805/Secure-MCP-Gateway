//go:build windows

package acceptance

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsandbox"
)

// procTrace records every process the acceptance run creates: the test
// binary is placed in a trace Job Object before the first test, so smcpd,
// smcpctl, the backends and anything they start are in it from creation
// (SR-4.8-2).
var procTrace *winsandbox.ProcessTrace

func startProcessTrace() {
	t, err := winsandbox.TraceCurrentProcess()
	if err != nil {
		fmt.Fprintln(os.Stderr, "process trace not started:", err)
		return
	}
	procTrace = t
}

// TestWindowsZZProcessTrace runs after every other test of the package
// (tests run in file order, and this file sorts after them): over the
// whole Windows acceptance run, no command interpreter (cmd.exe,
// powershell.exe, pwsh.exe, a .bat or .cmd file) was started by smcpd
// (SR-4.8-2). Records whose process ended before it could be opened are
// counted; an interpreter could hide among them only if it lived for less
// than the time to open it. SMCP_PROCESS_TRACE names a file for the trace.
func TestWindowsZZProcessTrace(t *testing.T) {
	needBinaries(t)
	reqtest.Partial(t, "SR-4.8-2")
	if procTrace == nil {
		t.Fatal("the process trace did not start")
	}
	time.Sleep(500 * time.Millisecond) // the last completion packets
	recs := procTrace.Records()
	total, err := procTrace.Total()
	if err != nil {
		t.Fatal(err)
	}
	gateways, unnamed := 0, 0
	for _, r := range recs {
		switch {
		case r.Image == "":
			unnamed++
		case strings.EqualFold(baseNameOf(r.Image), "smcpd.exe"):
			gateways++
		}
	}
	t.Logf("trace: %d processes recorded (job accounting %d, the test binary included), %d smcpd, %d ended before they could be opened", len(recs), total, gateways, unnamed)
	if gateways == 0 {
		t.Fatal("no smcpd process in the trace")
	}
	if bad := winsandbox.InterpreterStartedBy(recs, "smcpd.exe"); len(bad) > 0 {
		t.Fatalf("smcpd started a command interpreter: %+v", bad)
	}
	if p := os.Getenv("SMCP_PROCESS_TRACE"); p != "" {
		b, _ := json.MarshalIndent(map[string]any{"total": total, "unnamed": unnamed, "processes": recs}, "", "  ")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Error(err)
		}
	}
}

func baseNameOf(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// TestWindowsConsoleStop: a console smcpd with a running backend stops in
// order on CTRL_BREAK, the console event that Windows lets one process
// send to another's process group: the Evidence Journal records the stop,
// smcpd exits 0 within the CP-47 health wait (60 s), and no backend
// process remains (FR-21.7). CTRL_CLOSE, CTRL_LOGOFF and CTRL_SHUTDOWN
// cannot be sent to another process; their handler is tested in
// cmd/smcpd (TestConsoleCloseHandling).
func TestWindowsConsoleStop(t *testing.T) {
	reqtest.Partial(t, "FR-21.7")
	g := newGateway(t, options{})
	if err := g.launchWith(&syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(150 * time.Millisecond) {
		if _, err := g.ctl("health"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("smcpd did not become healthy\n%s", g.logs.String())
		}
	}
	cs := g.session(g.token(""))
	g.mustCall(cs, "ref_echo", map[string]any{"text": "before the stop"}, "before the stop")
	pid := uint32(g.cmd.Process.Pid) //nolint:gosec // a process ID
	backends := childProcesses(t, pid)
	if len(backends) == 0 {
		t.Fatal("no backend process below smcpd")
	}
	start := time.Now()
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, pid); err != nil {
		t.Fatalf("CTRL_BREAK: %v", err)
	}
	select {
	case <-g.exited:
	case <-time.After(60 * time.Second):
		t.Fatalf("smcpd did not exit within 60 s of CTRL_BREAK\n%s", g.logs.String())
	}
	took := time.Since(start)
	if code := g.cmd.ProcessState.ExitCode(); code != 0 {
		t.Fatalf("smcpd exited with %d\n%s", code, g.logs.String())
	}
	g.cmd = nil
	t.Logf("CTRL_BREAK: smcpd exited 0 after %v", took)
	stopped := false
	for _, e := range g.events() {
		stopped = stopped || (e.str("class") == "gateway" && e.str("outcome") == "stopped")
	}
	if !stopped {
		t.Error("no stop record in the Evidence Journal")
	}
	for _, b := range backends {
		h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, b)
		if err != nil {
			continue // gone
		}
		ev, _ := windows.WaitForSingleObject(h, 5000)
		_ = windows.CloseHandle(h)
		if ev != windows.WAIT_OBJECT_0 {
			t.Errorf("backend process %d remains after the stop", b)
		}
	}
}

// childProcesses lists the IDs of the processes whose parent is pid.
func childProcesses(t *testing.T, pid uint32) []uint32 {
	t.Helper()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []uint32
	for err := windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ParentProcessID == pid {
			out = append(out, e.ProcessID)
		}
	}
	return out
}
