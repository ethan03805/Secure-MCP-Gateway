package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsvc"
)

// smcpctl service status|start|stop|restart [--config <file>]
//
// Controls the service that `smcpctl install` registered, through the
// platform's service manager: the launchd user agent, the systemd user or
// system unit, the Windows per-user task (its stop event and supervisor)
// or the Windows machine-mode service. The Desktop Application uses it on
// Windows (FR-20.3) so that the stop event, the supervisor start and the
// Service Control Manager calls exist only here. `status` prints one word:
// running, stopped or not-installed.
//
// On Windows a failure that the service manager reports with a Win32
// error code ends smcpctl with exit code 0x20000000 | code (the
// customer-code bit), so that a caller that cannot read the output (an
// elevated run) can still show the system's text for the error.

const serviceUsage = "usage: smcpctl service status|start|stop|restart [--config <file>]"

// serviceProbes are the status queries, replaced by tests.
type serviceProbes struct {
	machine func() (running, installed bool, err error)
	perUser func(cfgPath string) (bool, error)
	run     func(argv []string) error
	unit    func(cfgDir string) *unitFile
	control func(cfgDir, action string) error
}

func defaultServiceProbes() serviceProbes {
	return serviceProbes{
		machine: winsvc.QueryService,
		perUser: winsvc.PerUserRunning,
		run: func(argv []string) error {
			cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // fixed service-manager commands
			return cmd.Run()
		},
		unit: installedUnitFor,
		control: func(cfgDir, action string) error {
			return service{cfgDir: cfgDir}.do(action)
		},
	}
}

var probes = defaultServiceProbes()

// statusArgv is the unelevated status query of a launchd or systemd unit.
func statusArgv(u *unitFile) []string {
	switch u.kind {
	case "launchd":
		return []string{"launchctl", "print", "gui/" + strconv.Itoa(os.Getuid()) + "/" + launchdLabel}
	case "systemd-user":
		return []string{"systemctl", "--user", "is-active", "--quiet", systemdUnit}
	default:
		return []string{"systemctl", "is-active", "--quiet", systemdUnit}
	}
}

// serviceState reports running, stopped or not-installed for the unit u
// (nil: none found). On Windows a machine-mode service whose definition
// file the user cannot read is still found through the service manager.
func serviceState(goos string, u *unitFile, p serviceProbes) (string, error) {
	word := func(running bool) string {
		if running {
			return "running"
		}
		return "stopped"
	}
	if u == nil {
		if goos != "windows" {
			return "not-installed", nil
		}
		running, installed, err := p.machine()
		if err != nil || !installed {
			return "not-installed", err
		}
		return word(running), nil
	}
	switch u.kind {
	case "win-service":
		running, installed, err := p.machine()
		if err != nil {
			return "", err
		}
		if !installed {
			return "not-installed", nil
		}
		return word(running), nil
	case "win-task", "win-run":
		running, err := p.perUser(filepath.Join(filepath.Dir(u.path), "smcp.toml"))
		if err != nil {
			return "", err
		}
		return word(running), nil
	}
	// launchctl print fails once the agent is booted out; systemctl
	// is-active fails for an inactive or failed unit.
	return word(p.run(statusArgv(u)) == nil), nil
}

// serviceExitError carries the exit code for a Win32 error code.
type serviceExitError struct {
	err  error
	code int
}

func (e serviceExitError) Error() string        { return e.err.Error() }
func (e serviceExitError) Unwrap() error        { return e.err }
func (e serviceExitError) smcpctlExitCode() int { return e.code }

// customerBit marks an exit code that carries a Win32 error code.
const customerBit = 0x20000000

func withExitCode(goos string, err error) error {
	var errno syscall.Errno
	if err == nil || goos != "windows" || !errors.As(err, &errno) || errno == 0 || uint64(errno) > 0xFFFF {
		return err
	}
	return serviceExitError{err: err, code: customerBit | int(errno)}
}

func serviceCmd(args []string, out io.Writer) error {
	return serviceRun(runtime.GOOS, args, out, probes)
}

func serviceRun(goos string, args []string, out io.Writer, p serviceProbes) error {
	if len(args) < 1 {
		return errors.New(serviceUsage)
	}
	action := args[0]
	fs := flag.NewFlagSet("service "+action, flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file of the installation (default: any installation smcpctl install made)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New(serviceUsage)
	}
	cfgDir := ""
	if *cfgPath != "" {
		abs, err := filepath.Abs(*cfgPath)
		if err != nil {
			return err
		}
		cfgDir = filepath.Dir(abs)
	}
	switch action {
	case "status":
		st, err := serviceState(goos, p.unit(cfgDir), p)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, st)
		return nil
	case "start", "stop", "restart":
	default:
		return errors.New(serviceUsage)
	}
	u := p.unit(cfgDir)
	st, err := serviceState(goos, u, p)
	if err != nil {
		return withExitCode(goos, err)
	}
	if st == "not-installed" {
		return errNoManager
	}
	if action == "start" && st == "running" {
		// A second per-user supervisor would fight the first.
		fmt.Fprintln(out, "running")
		return nil
	}
	if action == "stop" || (action == "restart" && st == "running") {
		if err := p.control(cfgDir, "stop"); err != nil {
			return withExitCode(goos, err)
		}
	}
	if action == "start" || action == "restart" {
		if err := p.control(cfgDir, "start"); err != nil {
			return withExitCode(goos, err)
		}
	}
	fmt.Fprintln(out, map[string]string{"start": "started", "stop": "stopped", "restart": "restarted"}[action])
	return nil
}
