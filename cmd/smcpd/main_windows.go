//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsvc"
)

var supervise = flag.Bool("supervise", false, "Windows per-user mode: run smcpd as a child process and start it again after a failure (FR-21.6)")

// platformRun picks the Windows run mode: under the Service Control
// Manager the machine-mode service (FR-21.6, FR-21.7); with -supervise the
// per-user supervisor; otherwise a console smcpd that also stops when the
// installation's stop event is set (smcpctl uninstall).
func platformRun(cfgPath, level string) error {
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		return runService(cfgPath, level)
	}
	ctx, release, err := winsvc.StopContext(context.Background(), cfgPath)
	if err != nil {
		return err
	}
	defer release()
	if *supervise {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		args := []string{"-config", cfgPath}
		if level != "" {
			args = append(args, "-log-level", level)
		}
		return winsvc.Supervise(ctx, exe, args, winsvc.SuperviseOptions{Log: supervisorLog(cfgPath)})
	}
	return run(ctx, cfgPath, level)
}

// supervisorLog appends the supervisor's lines to supervisor.log next to
// the diagnostic log, or to standard error.
func supervisorLog(cfgPath string) io.Writer {
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg.Log.File == "" {
		return os.Stderr
	}
	f, err := os.OpenFile(filepath.Join(filepath.Dir(cfg.Log.File), "supervisor.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return os.Stderr
	}
	return f
}

// consoleCloseBudget is how long smcpd takes at most after a console
// close, logoff or shutdown event: Windows ends the process about 5
// seconds after the event whatever the handler does (FR-21.7).
const consoleCloseBudget = 3500 * time.Millisecond

// watchConsoleClose: Go delivers CTRL_CLOSE, CTRL_LOGOFF and CTRL_SHUTDOWN
// as SIGTERM on Windows (CTRL_C and CTRL_BREAK are os.Interrupt, the
// orderly stop of run). For those three the stop is recorded in the
// Evidence Journal first and the process exits within 4 seconds; the
// backends end with their Job Objects (FR-21.12). A service receives no
// console events; it stops through the Service Control Manager.
func watchConsoleClose(a *app.App, log *slog.Logger) {
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		return
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		<-ch
		time.AfterFunc(consoleCloseBudget, func() { os.Exit(1) })
		log.Warn("console close, logoff or shutdown event: recording the stop and exiting")
		a.RecordStop("console_close")
		os.Exit(0)
	}()
}

// serviceStopWait bounds an orderly service stop: CP-47's 60 s health wait.
const serviceStopWait = 60 * time.Second

type service struct {
	cfgPath, level string
}

// Execute implements svc.Handler: SERVICE_CONTROL_STOP, SHUTDOWN and
// PRESHUTDOWN are the orderly stop that SIGTERM triggers on Linux.
func (s service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		if err := prepareMachineState(s.cfgPath); err != nil {
			done <- err
			return
		}
		done <- run(ctx, s.cfgPath, s.level)
	}()
	accepts := svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown
	status <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case err := <-done:
			if err != nil {
				fmt.Fprintln(os.Stderr, "smcpd:", err)
				// A non-zero service exit code makes the Service Control
				// Manager apply the recovery actions (restart).
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown, svc.PreShutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(serviceStopWait / time.Millisecond)}
				cancel()
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, context.Canceled) {
						return true, 1
					}
					return false, 0
				case <-time.After(serviceStopWait):
					return true, 2
				}
			}
		}
	}
}

func runService(cfgPath, level string) error {
	return svc.Run(winsvc.ServiceName, service{cfgPath: cfgPath, level: level})
}

// prepareMachineState creates, as the service account, the keys that
// smcpctl install --machine leaves out: they are DPAPI blobs of NT
// SERVICE\smcpd, which only this account can make (FR-21.10). It also
// refreshes the machine-scope operator token copy that Administrators use.
func prepareMachineState(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	if err := keys.Ensure(cfg.State.Dir, "127.0.0.1"); err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	return keys.WriteMachineOperatorToken(cfg.State.Dir)
}
