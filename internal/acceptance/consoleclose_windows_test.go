//go:build windows

package acceptance

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

var (
	kernel32Console      = windows.NewLazySystemDLL("kernel32.dll")
	user32Console        = windows.NewLazySystemDLL("user32.dll")
	procFreeConsole      = kernel32Console.NewProc("FreeConsole")
	procAttachConsole    = kernel32Console.NewProc("AttachConsole")
	procGetConsoleWindow = kernel32Console.NewProc("GetConsoleWindow")
	procPostMessageW     = user32Console.NewProc("PostMessageW")
)

const (
	wmSysCommand = 0x0112
	scClose      = 0xF060
)

// TestWindowsConsoleClose: a console smcpd with a running backend, in a
// console of its own, receives CTRL_CLOSE when that console's window is
// closed (WM_CLOSE, what the close button sends; a helper process
// attaches to the console to find the window). smcpd records the stop in
// the Evidence Journal first and exits within 4 seconds of the event, and
// no backend process remains: the backends end with their Job Objects'
// kill-on-close (FR-21.7). Partial: CTRL_LOGOFF and CTRL_SHUTDOWN, which
// Windows delivers only at a real logoff or shutdown, take the same
// handler (cmd/smcpd TestConsoleCloseHandling).
func TestWindowsConsoleClose(t *testing.T) {
	reqtest.Partial(t, "FR-21.7")
	g := newGateway(t, options{})
	if err := g.launchWith(&syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE}); err != nil {
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
	g.mustCall(cs, "ref_echo", map[string]any{"text": "before the close"}, "before the close")
	pid := g.cmd.Process.Pid
	backends := childProcesses(t, uint32(pid)) //nolint:gosec // a process ID
	if len(backends) == 0 {
		t.Fatal("no backend process below smcpd")
	}
	// The helper is this test binary in -short mode (TestMain builds
	// nothing then), running TestWindowsConsoleCloseHelper.
	helper := exec.Command(os.Args[0], "-test.run=^TestWindowsConsoleCloseHelper$", "-test.short", "-test.count=1", "-test.v")
	helper.Env = append(os.Environ(), "SMCP_CONSOLE_CLOSE_PID="+strconv.Itoa(pid))
	out, err := helper.CombinedOutput()
	posted := time.Now()
	if err != nil {
		t.Fatalf("console close helper: %v\n%s", err, out)
	}
	select {
	case <-g.exited:
	case <-time.After(10 * time.Second):
		t.Fatalf("smcpd did not exit after its console was closed\nhelper: %s\n%s", out, g.logs.String())
	}
	took := time.Since(posted)
	code := g.cmd.ProcessState.ExitCode()
	g.cmd = nil
	t.Logf("console closed: smcpd exited %d after %v", code, took)
	if took > 4*time.Second {
		t.Errorf("smcpd took %v after CTRL_CLOSE, more than 4 seconds", took)
	}
	if code != 0 {
		t.Errorf("smcpd exited %d: the stop record did not finish within its budget\n%s", code, g.logs.String())
	}
	stopped := false
	for _, e := range g.events() {
		if e.str("class") == "gateway" && e.str("outcome") == "stopped" {
			if d := e.detail(); d != nil && d["reason"] == "console_close" {
				stopped = true
			}
		}
	}
	if !stopped {
		t.Error("no stop record with reason console_close in the Evidence Journal")
	}
	for _, b := range backends {
		h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, b)
		if err != nil {
			continue // gone
		}
		ev, _ := windows.WaitForSingleObject(h, 5000)
		_ = windows.CloseHandle(h)
		if ev != windows.WAIT_OBJECT_0 {
			t.Errorf("backend process %d remains after the console was closed", b)
		}
	}
}

// TestWindowsConsoleCloseHelper runs only as the helper process of
// TestWindowsConsoleClose: it leaves its own console, attaches to the
// console of the process SMCP_CONSOLE_CLOSE_PID, reads that console's
// window, leaves it again and posts WM_CLOSE to the window.
func TestWindowsConsoleCloseHelper(t *testing.T) {
	v := os.Getenv("SMCP_CONSOLE_CLOSE_PID")
	if v == "" {
		t.Skip("helper process of TestWindowsConsoleClose")
	}
	pid, err := strconv.Atoi(v)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = procFreeConsole.Call()
	if r, _, e := procAttachConsole.Call(uintptr(pid)); r == 0 {
		t.Fatalf("AttachConsole(%d): %v", pid, e)
	}
	hwnd, _, _ := procGetConsoleWindow.Call()
	_, _, _ = procFreeConsole.Call()
	if hwnd == 0 {
		t.Fatalf("process %d's console has no window", pid)
	}
	// The close button sends WM_SYSCOMMAND SC_CLOSE, which the console
	// host turns into WM_CLOSE.
	if r, _, e := procPostMessageW.Call(hwnd, wmSysCommand, scClose, 0); r == 0 {
		t.Fatalf("PostMessage WM_SYSCOMMAND SC_CLOSE: %v", e)
	}
	fmt.Println("posted WM_CLOSE to the console window", hwnd)
}
