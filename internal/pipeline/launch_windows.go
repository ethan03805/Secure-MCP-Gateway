//go:build windows

package pipeline

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsandbox"
)

// limitExitCode is the exit code of an instance the Job Object ended
// because it broke a limit.
const limitExitCode = 0xC0000044 // STATUS_QUOTA_EXCEEDED

// startChild starts the server in its own Job Object (FR-21.11, FR-21.12):
// the process is created with CreateProcess, the argument vector is quoted
// by the Microsoft C runtime rules, the process is in the Job Object from
// creation, and the job has kill-on-close, the memory, process and CPU
// limits, and no breakaway. A broken memory or process limit ends the whole
// instance, as a cgroup limit does in the Enforced profile.
func startChild(l SubprocessLauncher, spec ServerSpec, env []string, stdin, stdout *os.File, stderr io.Writer) (child, error) {
	lim := l.limitsFor(spec)
	c := &jobChild{stderrDone: make(chan struct{})}
	job, err := winsandbox.NewJob(winsandbox.Limits{MemoryBytes: lim.MemoryBytes, CPUs: lim.CPUs, Processes: lim.Processes}, func(v winsandbox.Violation) {
		c.once.Do(func() {
			fmt.Fprintf(stderr, "\nsmcpd: the instance broke its %s limit; its Job Object was terminated (FR-21.12)\n", v)
			if j := c.jobRef.Load(); j != nil {
				_ = j.Terminate(limitExitCode)
			}
		})
	})
	if err != nil {
		return nil, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		job.Close()
		return nil, err
	}
	c.job = job
	c.jobRef.Store(job)
	p, err := winsandbox.Start(winsandbox.StartOptions{Path: spec.Command, Args: spec.Args, Env: env, Dir: spec.Dir,
		Stdin: stdin, Stdout: stdout, Stderr: errW, Job: job})
	errW.Close()
	if err != nil {
		errR.Close()
		job.Close()
		return nil, err
	}
	c.proc = p
	go func() {
		_, _ = io.Copy(stderr, errR)
		errR.Close()
		close(c.stderrDone)
	}()
	return c, nil
}

type jobChild struct {
	job        *winsandbox.Job
	jobRef     atomic.Pointer[winsandbox.Job] // read by the violation callback
	proc       *os.Process
	once       sync.Once
	stderrDone chan struct{}
}

// Wait waits for the server process and then for its diagnostic output to
// end (every holder of the pipe gone, as os/exec does).
func (c *jobChild) Wait() error {
	st, err := c.proc.Wait()
	<-c.stderrDone
	if err != nil {
		return err
	}
	if !st.Success() {
		return &exec.ExitError{ProcessState: st}
	}
	return nil
}

func (c *jobChild) Terminate() error {
	return errors.New("Windows has no SIGTERM for a backend process")
}

func (c *jobChild) Kill() error { return c.job.Terminate(1) }

func (c *jobChild) Release() {
	_ = c.job.Close()
	_ = c.proc.Release()
}
