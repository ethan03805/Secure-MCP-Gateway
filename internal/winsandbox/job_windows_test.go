//go:build windows

package winsandbox

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// helperEnv selects the helper behavior when the test binary runs as a
// backend process.
const helperEnv = "SMCP_WINSANDBOX_HELPER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(helper(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// helper runs one hostile or probing behavior and reports on stdout.
func helper(mode string, args []string) int {
	switch mode {
	case "args":
		b, _ := json.Marshal(args)
		fmt.Println(string(b))
		_, _ = io.Copy(io.Discard, os.Stdin)
		return 0
	case "sleep":
		_, _ = io.Copy(io.Discard, os.Stdin)
		return 0
	case "alloc": // allocate and touch args[0] MiB in 8 MiB steps
		n, _ := strconv.Atoi(args[0])
		var held [][]byte
		for got := 0; got < n; got += 8 {
			b := make([]byte, 8<<20)
			for i := 0; i < len(b); i += 4096 {
				b[i] = 1
			}
			held = append(held, b)
			fmt.Println("allocated", got+8)
		}
		runtime.KeepAlive(held)
		return 0
	case "spawn": // start args[0] children that wait for stdin to close
		n, _ := strconv.Atoi(args[0])
		started := 0
		var lastErr error
		var keep []io.WriteCloser
		for started < n {
			w, err := startSleeper(0)
			if err != nil {
				lastErr = err
				break
			}
			keep = append(keep, w)
			started++
		}
		fmt.Printf("started %d err=%v\n", started, lastErr)
		_, _ = io.Copy(io.Discard, os.Stdin)
		runtime.KeepAlive(keep)
		return 0
	case "breakaway": // start a child outside the job
		_, err := startSleeper(windows.CREATE_BREAKAWAY_FROM_JOB)
		fmt.Printf("breakaway err=%v\n", err)
		_, _ = io.Copy(io.Discard, os.Stdin)
		return 0
	case "spin": // keep every processor busy for args[0] milliseconds
		ms, _ := strconv.Atoi(args[0])
		end := time.Now().Add(time.Duration(ms) * time.Millisecond)
		done := make(chan struct{})
		for range runtime.NumCPU() {
			go func() {
				x := 0
				for time.Now().Before(end) {
					x++
				}
				_ = x
				done <- struct{}{}
			}()
		}
		for range runtime.NumCPU() {
			<-done
		}
		fmt.Println("spun")
		return 0
	case "tree": // start one grandchild, print its PID, wait for stdin
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(), helperEnv+"=sleep")
		w, err := cmd.StdinPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			fmt.Println("tree err", err)
			return 1
		}
		fmt.Println(cmd.Process.Pid)
		_, _ = io.Copy(io.Discard, os.Stdin)
		w.Close()
		return 0
	case "gateway": // a stand-in for smcpd: start a "tree" backend in a job, print both PIDs, wait
		job, err := NewJob(Limits{MemoryBytes: 256 << 20, Processes: 8}, nil)
		if err != nil {
			fmt.Println("gateway err", err)
			return 1
		}
		p, out, in, err := startHelper(job, "tree", nil)
		if err != nil {
			fmt.Println("gateway err", err)
			return 1
		}
		line, _ := bufio.NewReader(out).ReadString('\n')
		fmt.Printf("%d %s", p.Pid, line)
		_, _ = io.Copy(io.Discard, os.Stdin)
		in.Close()
		return 0
	}
	fmt.Fprintln(os.Stderr, "unknown helper mode", mode)
	return 2
}

// startSleeper starts a "sleep" helper with extra creation flags and returns
// its stdin.
func startSleeper(flags uint32) (io.WriteCloser, error) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"=sleep")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags}
	w, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		w.Close()
		return nil, err
	}
	return w, nil
}

// startHelper starts the test binary in mode inside job through Start.
func startHelper(job *Job, mode string, args []string) (*os.Process, io.Reader, io.WriteCloser, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, nil, err
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	env := []string{helperEnv + "=" + mode}
	for _, k := range []string{"SYSTEMROOT", "TEMP", "TMP", "PATH"} {
		env = append(env, k+"="+os.Getenv(k))
	}
	p, err := Start(StartOptions{Path: exe, Args: args, Env: env, Stdin: inR, Stdout: outW, Stderr: outW, Job: job})
	inR.Close()
	outW.Close()
	if err != nil {
		inW.Close()
		outR.Close()
		return nil, nil, nil, err
	}
	return p, outR, inW, nil
}

func newJob(t *testing.T, l Limits) *Job {
	t.Helper()
	j, err := NewJob(l, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	return j
}

func readLine(t *testing.T, r io.Reader) string {
	t.Helper()
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && line == "" {
		t.Fatalf("read: %v", err)
	}
	return strings.TrimSpace(line)
}

// TestWindowsArgumentsAndJobFromCreation: the argument vector reaches the
// backend unchanged and unexpanded (spaces, quotes, &, |, %PATH%, empty and
// backslash-heavy arguments), and the backend is the only process of its Job
// Object and a member of it as soon as Start returns, without an
// AssignProcessToJobObject call. Partial for FR-21.11: enablement refusal is
// tested in internal/library and internal/pipeline.
func TestWindowsArgumentsAndJobFromCreation(t *testing.T) {
	reqtest.Partial(t, "FR-21.11")
	job := newJob(t, Limits{MemoryBytes: 256 << 20, Processes: 4, CPUs: 1})
	want := []string{"plain", "with space", `quote"inside`, `a & b | c`, "%PATH%", "", `C:\dir\`, `trail\\`, `\"x\"`, `^&<>`, "!x!"}
	p, out, in, err := startHelper(job, "args", want)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.Pid))
	if err == nil {
		in, err := job.Contains(h)
		windows.CloseHandle(h)
		if err != nil || !in {
			t.Errorf("process in job = %v, %v", in, err)
		}
	}
	var got []string
	if err := json.Unmarshal([]byte(readLine(t, out)), &got); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("arguments\n got  %q\n want %q", got, want)
	}
	onlyBackend(t, job, p.Pid)
	in.Close()
	if _, err := p.Wait(); err != nil {
		t.Fatal(err)
	}
}

// onlyBackend checks that the job holds the backend and otherwise only the
// console host Windows starts for a console program without a window.
func onlyBackend(t *testing.T, job *Job, pids ...int) {
	t.Helper()
	ps, err := job.PIDs()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range pids {
		if !slices.Contains(ps, uint32(want)) {
			t.Errorf("process %d not in the job (%v)", want, ps)
		}
	}
	for _, pid := range ps {
		if slices.Contains(pids, int(pid)) {
			continue
		}
		if img := imageName(pid); !strings.EqualFold(img, "conhost.exe") {
			t.Errorf("unexpected process %d (%s) in the job", pid, img)
		}
	}
}

func imageName(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "?"
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "?"
	}
	p := windows.UTF16ToString(buf[:n])
	return p[strings.LastIndexAny(p, `\/`)+1:]
}

// TestWindowsStartRefusesInterpreters: Start itself refuses the SR-4.8-2
// interpreters and batch files, so no caller can start one.
func TestWindowsStartRefusesInterpreters(t *testing.T) {
	reqtest.Partial(t, "SR-4.8-2")
	job := newJob(t, Limits{Processes: 2})
	sys := os.Getenv("SYSTEMROOT")
	bat := t.TempDir() + `\x.bat`
	if err := os.WriteFile(bat, []byte("@echo off\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{sys + `\System32\cmd.exe`, sys + `\System32\WindowsPowerShell\v1.0\powershell.exe`, bat, bat + "."} {
		_, err := Start(StartOptions{Path: path, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Job: job})
		if err == nil || !strings.Contains(err.Error(), "interpreter") && !strings.Contains(err.Error(), "batch") {
			t.Errorf("Start(%s) = %v", path, err)
		}
	}
	if acc, _ := job.Accounting(); acc.TotalProcesses != 0 {
		t.Fatalf("%d processes started", acc.TotalProcesses)
	}
}

// TestWindowsJobMemoryLimit: a backend that allocates beyond the memory
// limit fails at the limit and the job reports the violation (HF-21).
func TestWindowsJobMemoryLimit(t *testing.T) {
	reqtest.Partial(t, "FR-21.12")
	job := newJob(t, Limits{MemoryBytes: 96 << 20, Processes: 4})
	p, out, in, err := startHelper(job, "alloc", []string{"512"})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	outc := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(out)
		outc <- b
	}()
	// The process either dies at the limit or is stuck failing to commit;
	// either way the job reports the violation, and terminating the job
	// ends it.
	waitViolation(t, job, ViolationMemory)
	_ = job.Terminate(1)
	if _, err := p.Wait(); err != nil {
		t.Fatal(err)
	}
	var b []byte
	select {
	case b = <-outc:
	case <-time.After(10 * time.Second):
		t.Fatal("output did not end after the job was terminated")
	}
	last := 0
	for _, l := range strings.Split(string(b), "\n") {
		if n, ok := strings.CutPrefix(strings.TrimSpace(l), "allocated "); ok {
			last, _ = strconv.Atoi(n)
		}
	}
	if last > 96 {
		t.Fatalf("allocated %d MiB under a 96 MiB limit", last)
	}
}

// TestWindowsJobProcessLimit: a fork bomb stops at the active-process limit
// and the job reports the violation (HF-20); a child cannot break away.
func TestWindowsJobProcessLimit(t *testing.T) {
	reqtest.Partial(t, "FR-21.12")
	job := newJob(t, Limits{MemoryBytes: 512 << 20, Processes: 4})
	_, out, in, err := startHelper(job, "spawn", []string{"32"})
	if err != nil {
		t.Fatal(err)
	}
	line := readLine(t, out)
	var n int
	// The limit counts the backend but not its console host, so three
	// children fit (two is accepted in case a Windows build counts it).
	if _, err := fmt.Sscanf(line, "started %d", &n); err != nil || n < 2 || n > 3 {
		t.Fatalf("fork bomb under a limit of 4 processes: %q", line)
	}
	// The console host is listed in the job but not counted against the
	// limit; every other process is.
	ps, err := job.PIDs()
	if err != nil {
		t.Fatal(err)
	}
	counted := 0
	for _, pid := range ps {
		if !strings.EqualFold(imageName(pid), "conhost.exe") {
			counted++
		}
	}
	if counted > 4 {
		t.Fatalf("%d processes besides the console host under a limit of 4 (%v)", counted, ps)
	}
	waitViolation(t, job, ViolationProcesses)
	in.Close()

	job2 := newJob(t, Limits{MemoryBytes: 512 << 20, Processes: 4})
	p2, out2, in2, err := startHelper(job2, "breakaway", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer in2.Close()
	if line := readLine(t, out2); line == "breakaway err=<nil>" {
		t.Fatal("a child broke away from the job")
	}
	onlyBackend(t, job2, p2.Pid)
}

// TestWindowsJobCPURate: a backend that spins every processor is held to
// its CPU rate limit.
func TestWindowsJobCPURate(t *testing.T) {
	reqtest.Partial(t, "FR-21.12")
	if runtime.NumCPU() < 2 {
		t.Skip("needs at least two processors to tell a cap of half a processor from none")
	}
	job := newJob(t, Limits{MemoryBytes: 512 << 20, Processes: 4, CPUs: 0.5})
	start := time.Now()
	p, out, in, err := startHelper(job, "spin", []string{"3000"})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	_, _ = io.ReadAll(out)
	if _, err := p.Wait(); err != nil {
		t.Fatal(err)
	}
	wall := time.Since(start)
	acc, err := job.Accounting()
	if err != nil {
		t.Fatal(err)
	}
	used := time.Duration(acc.UserTime+acc.KernelTime) * 100
	if ratio := used.Seconds() / wall.Seconds(); ratio > 0.5*1.5 {
		t.Fatalf("CPU %.2f processors over %v under a cap of 0.5 (%d processors)", ratio, wall, runtime.NumCPU())
	}
}

// TestWindowsKillOnClose: when the Gateway's process ends, however it ends,
// every process of the backend's job ends with it.
func TestWindowsKillOnClose(t *testing.T) {
	reqtest.Partial(t, "FR-21.12")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	gw := exec.Command(exe)
	gw.Env = append(os.Environ(), helperEnv+"=gateway")
	stdin, err := gw.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := gw.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := gw.Start(); err != nil {
		t.Fatal(err)
	}
	var backend, grandchild uint32
	line := readLine(t, stdout)
	if _, err := fmt.Sscanf(line, "%d %d", &backend, &grandchild); err != nil {
		gw.Process.Kill()
		t.Fatalf("gateway helper: %q", line)
	}
	handles := map[uint32]windows.Handle{}
	for _, pid := range []uint32{backend, grandchild} {
		h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
		if err != nil {
			gw.Process.Kill()
			t.Fatalf("open %d: %v", pid, err)
		}
		defer windows.CloseHandle(h)
		handles[pid] = h
	}
	if err := gw.Process.Kill(); err != nil { // TerminateProcess: no cleanup runs
		t.Fatal(err)
	}
	_ = gw.Wait()
	for pid, h := range handles {
		ev, err := windows.WaitForSingleObject(h, 10_000)
		if err != nil || ev != windows.WAIT_OBJECT_0 {
			t.Errorf("process %d still running after the gateway was killed", pid)
		}
	}
}

func waitViolation(t *testing.T, job *Job, v Violation) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if slices.Contains(job.Violations(), v) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s violation reported; got %v", v, job.Violations())
}
