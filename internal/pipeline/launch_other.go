//go:build !windows

package pipeline

import (
	"io"
	"os"
	"os/exec"
	"syscall"
)

// startChild starts the server as a plain child process. The resource
// limits are not applied here: the Standalone profile on Linux and macOS
// sets none, and the Enforced profile uses the sandbox launcher.
func startChild(_ SubprocessLauncher, spec ServerSpec, env []string, stdin, stdout *os.File, stderr io.Writer) (child, error) {
	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Env = env
	cmd.Dir = spec.Dir
	cmd.Stdout, cmd.Stdin, cmd.Stderr = stdout, stdin, stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return execChild{cmd}, nil
}

type execChild struct{ cmd *exec.Cmd }

func (c execChild) Wait() error      { return c.cmd.Wait() }
func (c execChild) Terminate() error { return c.cmd.Process.Signal(syscall.SIGTERM) }
func (c execChild) Kill() error      { return c.cmd.Process.Kill() }
func (c execChild) Release()         {}
