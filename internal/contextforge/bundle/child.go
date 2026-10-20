package bundle

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsandbox"
)

// child is the managed process off Windows: a plain child process with
// the given environment and working directory. The operating system's
// resource limits of the container form do not apply to it; the health
// monitor reports it unconfined (FR-22.25).
type child struct {
	cmd  *exec.Cmd
	done chan struct{}
	once sync.Once
}

func startChild(s winsandbox.ManagedSpec) (ManagedProc, error) {
	cmd := exec.Command(s.Path, s.Args...) //nolint:gosec // G204: the configured interpreter; arguments built here
	cmd.Env, cmd.Dir = s.Env, s.Dir
	if s.Stdout != nil {
		cmd.Stdout = s.Stdout
	}
	if s.Stderr != nil {
		cmd.Stderr = s.Stderr
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &child{cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(c.done)
	}()
	return c, nil
}

func (c *child) Done() <-chan struct{} { return c.done }

func (c *child) Stop(grace time.Duration) error {
	var err error
	c.once.Do(func() {
		_ = c.cmd.Process.Signal(os.Interrupt)
		select {
		case <-c.done:
		case <-time.After(grace):
			_ = c.cmd.Process.Kill()
			select {
			case <-c.done:
			case <-time.After(10 * time.Second):
				err = errors.New("managed process did not exit")
			}
		}
	})
	return err
}
