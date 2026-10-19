//go:build unix

package tunnel

import (
	"os/exec"
	"syscall"
)

// detach starts cmd in its own process group so it outlives a terminal
// signal sent to the CLI.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
