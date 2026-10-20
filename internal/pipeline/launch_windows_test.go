//go:build windows

package pipeline

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsandbox"
)

const helperEnv = "SMCP_PIPELINE_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		os.Exit(m.Run())
	case "probe": // run each "op:arg" probe, print the results as one JSON line
		probeMain(os.Args[1:])
	case "echo": // echo stdin lines, note them on stderr
		fmt.Fprintln(os.Stderr, "echo backend ready")
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			fmt.Println(sc.Text())
		}
	case "orphan": // leave a grandchild behind, print its PID, exit on stdin EOF
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(), helperEnv+"=sleep")
		w, _ := cmd.StdinPipe()
		if err := cmd.Start(); err != nil {
			fmt.Println("err", err)
			os.Exit(1)
		}
		fmt.Println(cmd.Process.Pid)
		_, _ = io.Copy(io.Discard, os.Stdin)
		_ = w // the grandchild keeps waiting
	case "sleep":
		_, _ = io.Copy(io.Discard, os.Stdin)
	case "spawn": // fork bomb: start sleepers until refused, then wait
		var keep []io.WriteCloser
		for range 64 {
			cmd := exec.Command(os.Args[0])
			cmd.Env = append(os.Environ(), helperEnv+"=sleep")
			w, _ := cmd.StdinPipe()
			if cmd.Start() != nil {
				break
			}
			keep = append(keep, w)
		}
		fmt.Println("spawned", len(keep))
		_, _ = io.Copy(io.Discard, os.Stdin)
	}
	os.Exit(0)
}

func helperSpec(t *testing.T, mode string) ServerSpec {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return ServerSpec{Alias: "t", Command: exe, Env: map[string]string{helperEnv: mode, "SYSTEMROOT": os.Getenv("SYSTEMROOT")}}
}

// TestWindowsSubprocessLauncher: a backend starts on Windows through the Job
// Object path, speaks over its pipes, its diagnostic output is kept, and
// Close ends it and every process it left behind (FR-21.12 kill-on-close at
// instance stop). Partial: the limits are tested in internal/winsandbox
// and below, the AppContainer of the machine mode is FR-21.13.
func TestWindowsSubprocessLauncher(t *testing.T) {
	reqtest.Partial(t, "FR-21.11", "FR-21.12")
	l := SubprocessLauncher{TerminateAfter: 500 * time.Millisecond}
	p, err := l.Launch(context.Background(), helperSpec(t, "echo"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(p, "hello & %PATH%\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(p).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "hello & %PATH%" {
		t.Fatalf("echo = %q, %v", line, err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Stderr(), "echo backend ready") {
		t.Fatalf("stderr = %q", p.Stderr())
	}

	p, err = l.Launch(context.Background(), helperSpec(t, "orphan"))
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(p)
	line, _ = r.ReadString('\n')
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		p.Close()
		t.Fatalf("orphan helper: %q", line)
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		p.Close()
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	start := time.Now()
	_ = p.Close()
	if ev, err := windows.WaitForSingleObject(h, 10_000); err != nil || ev != windows.WAIT_OBJECT_0 {
		t.Fatal("the backend's grandchild outlived the instance")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Close took %v", d)
	}
}

// TestWindowsLaunchRefusesInterpreters: SubprocessLauncher refuses cmd.exe,
// PowerShell and batch files before anything starts (SR-4.8-2).
func TestWindowsLaunchRefusesInterpreters(t *testing.T) {
	reqtest.Partial(t, "SR-4.8-2")
	sys := os.Getenv("SYSTEMROOT")
	for _, cmd := range []string{sys + `\System32\cmd.exe`, sys + `\System32\WindowsPowerShell\v1.0\powershell.exe`, `C:\srv\run.cmd`} {
		p, err := SubprocessLauncher{}.Launch(context.Background(), ServerSpec{Command: cmd, Args: []string{"/c", "echo"}})
		if !errors.Is(err, winsandbox.ErrShellLaunch) {
			if p != nil {
				p.Close()
			}
			t.Errorf("Launch(%s) = %v, want ErrShellLaunch", cmd, err)
		}
	}
}

// TestWindowsLaunchProcessLimit: the configured process limit reaches the
// instance's Job Object, and a fork bomb ends the whole instance (HF-20).
func TestWindowsLaunchProcessLimit(t *testing.T) {
	reqtest.Partial(t, "FR-21.12")
	l := SubprocessLauncher{TerminateAfter: 500 * time.Millisecond, Limits: func(ServerSpec) ResourceLimits {
		return ResourceLimits{Processes: 3}
	}}
	p, err := l.Launch(context.Background(), helperSpec(t, "spawn"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	b, _ := io.ReadAll(p) // ends when the instance is terminated
	if strings.Contains(string(b), "spawned 64") {
		t.Fatalf("fork bomb not limited: %s", b)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(p.Stderr(), "broke its processes limit") {
		if time.Now().After(deadline) {
			t.Fatalf("no limit report; stderr %q, stdout %q", p.Stderr(), b)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
