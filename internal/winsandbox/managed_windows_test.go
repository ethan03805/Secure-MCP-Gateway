//go:build windows

package winsandbox

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestWindowsManagedProcess: the bundled ContextForge instance's process
// form on Windows runs in its own Job Object from creation with the given
// environment, working directory and limits, reports contextforge_unconfined
// while it runs, and Stop ends it and the processes it started. Partial for
// FR-21.12 and FR-22.25: installing and starting ContextForge itself is the
// ContextForge Connector's.
func TestWindowsManagedProcess(t *testing.T) {
	reqtest.Partial(t, "FR-21.12", "FR-22.25")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var out bytes.Buffer
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	m, err := StartManaged(ManagedSpec{Path: exe, Env: []string{helperEnv + "=holdtree", "CF_ONLY=1"}, Dir: dir, Stdout: pw, Stderr: &out,
		Limits: Limits{MemoryBytes: 256 << 20, Processes: 4, CPUs: 1}})
	if err != nil {
		t.Fatal(err)
	}
	running := true
	check := ContextForgeUnconfinedCheck(func() bool { return running })
	if cs := check(time.Now()); len(cs) != 1 || cs[0].Name != CauseContextForgeUnconfined || cs[0].Critical {
		t.Fatalf("causes while running: %+v", cs)
	}
	line, _ := bufio.NewReader(pr).ReadString('\n')
	grandchild := strings.TrimSpace(line)
	gpid, err := strconv.Atoi(grandchild)
	if err != nil {
		t.Fatalf("helper output %q", line)
	}
	onlyBackend(t, m.Job(), m.PID(), gpid)
	pids, err := m.Job().PIDs()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(100 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	running = false
	if cs := check(time.Now()); cs != nil {
		t.Fatalf("causes after stop: %+v", cs)
	}
	for _, pid := range pids {
		h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
		if err != nil {
			continue // already gone
		}
		ev, _ := windows.WaitForSingleObject(h, 5000)
		windows.CloseHandle(h)
		if ev != windows.WAIT_OBJECT_0 {
			t.Errorf("process %d survived Stop", pid)
		}
	}
	var _ health.Check = check
}
