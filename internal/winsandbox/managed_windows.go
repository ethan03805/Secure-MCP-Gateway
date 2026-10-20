//go:build windows

package winsandbox

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// Managed is a running managed process in its own Job Object.
type Managed struct {
	job     *Job
	proc    *os.Process
	done    chan struct{}
	copies  sync.WaitGroup
	waitErr error
}

// StartManaged starts the process inside a new Job Object with kill-on-close
// and the given limits, the process placed in the job at creation (FR-21.12).
// If the Gateway ends, however it ends, the kernel closes the job and the
// process and every process it started end with it.
func StartManaged(s ManagedSpec) (*Managed, error) {
	job, err := NewJob(s.Limits, nil)
	if err != nil {
		return nil, err
	}
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		job.Close()
		return nil, err
	}
	defer devnull.Close()
	m := &Managed{job: job, done: make(chan struct{})}
	pipe := func(w io.Writer) (*os.File, error) {
		r, wf, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		if w == nil {
			w = io.Discard
		}
		m.copies.Add(1)
		go func() {
			defer m.copies.Done()
			_, _ = io.Copy(w, r)
			r.Close()
		}()
		return wf, nil
	}
	outW, err := pipe(s.Stdout)
	if err != nil {
		job.Close()
		return nil, err
	}
	errW, err := pipe(s.Stderr)
	if err != nil {
		outW.Close()
		job.Close()
		return nil, err
	}
	p, err := Start(StartOptions{Path: s.Path, Args: s.Args, Env: s.Env, Dir: s.Dir, Stdin: devnull, Stdout: outW, Stderr: errW, Job: job})
	outW.Close()
	errW.Close()
	if err != nil {
		job.Close()
		m.copies.Wait()
		return nil, err
	}
	m.proc = p
	go func() {
		st, err := p.Wait()
		switch {
		case err != nil:
			m.waitErr = err
		case !st.Success():
			m.waitErr = &exec.ExitError{ProcessState: st}
		}
		close(m.done)
	}()
	return m, nil
}

// PID returns the process ID.
func (m *Managed) PID() int { return m.proc.Pid }

// Job returns the process's Job Object, for its accounting and limits.
func (m *Managed) Job() *Job { return m.job }

// Done is closed when the process has exited.
func (m *Managed) Done() <-chan struct{} { return m.done }

// Wait waits for the process to exit and its output to be copied.
func (m *Managed) Wait() error {
	<-m.done
	m.copies.Wait()
	return m.waitErr
}

// Stop ends the process and everything in its job: it waits up to grace
// for the process to exit on its own (after the caller asked it to, for
// example through its API), then terminates the job and closes it.
func (m *Managed) Stop(grace time.Duration) error {
	select {
	case <-m.done:
	case <-time.After(grace):
		_ = m.job.Terminate(1)
		select {
		case <-m.done:
		case <-time.After(10 * time.Second):
			m.job.Close()
			return errors.New("managed process did not exit")
		}
	}
	err := m.job.Close()
	m.copies.Wait()
	_ = m.proc.Release()
	return err
}
