//go:build windows

package winsvc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// HostVersion reads the running Windows version with RtlGetVersion, which
// is not subject to the application compatibility shims of GetVersionEx.
func HostVersion() Version {
	v := windows.RtlGetVersion()
	return Version{Major: v.MajorVersion, Minor: v.MinorVersion, Build: v.BuildNumber, Server: v.ProductType != 1} // 1: VER_NT_WORKSTATION
}

// StopContext returns a context that is cancelled when the installation's
// stop event (StopEventName) is set, and a function that releases the
// event. A per-user smcpd and its supervisor both wait on it.
func StopContext(parent context.Context, cfgPath string) (context.Context, func(), error) {
	name, err := windows.UTF16PtrFromString(StopEventName(cfgPath))
	if err != nil {
		return nil, nil, err
	}
	// Manual reset: every process waiting on the event sees it set.
	ev, err := windows.CreateEvent(nil, 1, 0, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, nil, fmt.Errorf("winsvc: stop event: %w", err)
	}
	quit, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(ev)
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		i, err := windows.WaitForMultipleObjects([]windows.Handle{ev, quit}, false, windows.INFINITE)
		if err == nil && i == windows.WAIT_OBJECT_0 {
			cancel()
		}
	}()
	release := func() {
		_ = windows.SetEvent(quit)
		<-done
		cancel()
		_ = windows.CloseHandle(quit)
		_ = windows.CloseHandle(ev)
	}
	return ctx, release, nil
}

// SignalStop sets the stop event of the installation whose configuration
// is cfgPath. It reports false when no process has the event open, that
// is, when no per-user smcpd of that installation runs.
func SignalStop(cfgPath string) (bool, error) {
	name, err := windows.UTF16PtrFromString(StopEventName(cfgPath))
	if err != nil {
		return false, err
	}
	ev, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("winsvc: open stop event: %w", err)
	}
	defer func() { _ = windows.CloseHandle(ev) }()
	if err := windows.SetEvent(ev); err != nil {
		return false, err
	}
	return true, nil
}

// killOnCloseJob creates a Job Object whose processes are terminated when
// its last handle closes, so that a supervised smcpd never outlives its
// supervisor.
func killOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil { //nolint:gosec // the structure and its size
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// SuperviseOptions bound the supervisor's restarts.
type SuperviseOptions struct {
	// StopWait is how long an orderly stop may take before the child is
	// terminated (default 70 s: CP-47's 60 s health wait plus margin).
	StopWait time.Duration
	// MinBackoff and MaxBackoff bound the delay before a restart (default
	// 1 s and 60 s); the delay doubles after each failure and returns to
	// MinBackoff after a run of ResetAfter (default 5 min).
	MinBackoff, MaxBackoff, ResetAfter time.Duration
	// Log receives one line per start, exit and restart.
	Log io.Writer
}

// Supervise runs exe with args and starts it again after it exits with a
// non-zero status, until it exits with status 0 or ctx is cancelled (the
// stop event). The child is in a kill-on-close Job Object of the
// supervisor. On cancellation the child, which waits on the same stop
// event, gets StopWait to exit before it is terminated.
func Supervise(ctx context.Context, exe string, args []string, o SuperviseOptions) error {
	if o.StopWait <= 0 {
		o.StopWait = 70 * time.Second
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = time.Second
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = time.Minute
	}
	if o.ResetAfter <= 0 {
		o.ResetAfter = 5 * time.Minute
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	job, err := killOnCloseJob()
	if err != nil {
		return fmt.Errorf("winsvc: job object: %w", err)
	}
	defer func() { _ = windows.CloseHandle(job) }()
	backoff := o.MinBackoff
	for {
		cmd := exec.Command(exe, args...)
		cmd.Stdout, cmd.Stderr = o.Log, o.Log
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		started := time.Now()
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("winsvc: start %s: %w", exe, err)
		}
		if h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid)); err == nil { //nolint:gosec // a process ID
			_ = windows.AssignProcessToJobObject(job, h)
			_ = windows.CloseHandle(h)
		}
		fmt.Fprintf(o.Log, "smcpd supervisor: started pid %d\n", cmd.Process.Pid)
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()
		select {
		case <-ctx.Done():
			select {
			case <-exited:
			case <-time.After(o.StopWait):
				_ = cmd.Process.Kill()
				<-exited
				fmt.Fprintln(o.Log, "smcpd supervisor: smcpd did not stop in time and was terminated")
			}
			return nil
		case err := <-exited:
			if err == nil {
				fmt.Fprintln(o.Log, "smcpd supervisor: smcpd stopped")
				return nil
			}
			if time.Since(started) >= o.ResetAfter {
				backoff = o.MinBackoff
			}
			fmt.Fprintf(o.Log, "smcpd supervisor: smcpd exited (%v); restarting in %s\n", err, backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, o.MaxBackoff)
		}
	}
}

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// SetRunValue registers the fallback start at logon: the RunValue of the
// user's Run key, with no restart after a failure beyond what the
// supervisor in the command line does.
func SetRunValue(commandLine string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(RunValue, commandLine)
}

// RunValueData returns the registered fallback command line, or "".
func RunValueData() string {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(RunValue)
	if err != nil {
		return ""
	}
	return v
}

// DeleteRunValue removes the fallback; a missing value is not an error.
func DeleteRunValue() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	if err := k.DeleteValue(RunValue); err != nil && !errors.Is(err, registry.ErrNotExist) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return err
	}
	return nil
}

// StartDetached starts exe with args in a new process group without a
// console window, not waiting for it, and returns its process ID.
func StartDetached(exe string, args []string, dir string, logFile *os.File) (int, error) {
	cmd := exec.Command(exe, args...)
	cmd.Dir = dir
	if logFile != nil {
		cmd.Stdout, cmd.Stderr = logFile, logFile
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	return pid, cmd.Process.Release()
}
