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
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
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

// ServiceAccount is the CP-46 virtual service account of the machine mode.
const ServiceAccount = `NT SERVICE\` + ServiceName

// InstallService registers the machine-mode service (FR-21.6): smcpd
// -config cfgPath under NT SERVICE\smcpd, automatic (delayed) start, an
// unrestricted service SID, and recovery actions that restart it after
// the first and second failures, also when it exits with an error rather
// than crashing. An existing registration is updated. It reports whether
// the service was created.
func InstallService(exe, cfgPath string) (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, fmt.Errorf("winsvc: connect to the Service Control Manager (run as Administrator): %w", err)
	}
	defer func() { _ = m.Disconnect() }()
	c := mgr.Config{
		DisplayName:      "Secure MCP Gateway",
		Description:      "Secure MCP Gateway (smcpd), machine mode. Not enforced on Windows.",
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ServiceStartName: ServiceAccount,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
		ErrorControl:     mgr.ErrorNormal,
	}
	created := false
	s, err := m.OpenService(ServiceName)
	if err == nil {
		c.BinaryPathName = CommandLine(exe, "-config", cfgPath)
		if err := s.UpdateConfig(c); err != nil {
			s.Close()
			return false, fmt.Errorf("winsvc: update service: %w", err)
		}
	} else {
		if s, err = m.CreateService(ServiceName, exe, c, "-config", cfgPath); err != nil {
			return false, fmt.Errorf("winsvc: create service: %w", err)
		}
		created = true
	}
	defer s.Close()
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.NoAction},
	}
	if err := s.SetRecoveryActions(actions, 24*60*60); err != nil {
		return created, fmt.Errorf("winsvc: recovery actions: %w", err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return created, fmt.Errorf("winsvc: recovery on non-crash failures: %w", err)
	}
	return created, nil
}

// ServiceState returns the state of the machine-mode service, or
// svc.Stopped and false when it is not installed.
func ServiceState() (svc.State, bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return svc.Stopped, false, nil
	}
	defer s.Close()
	st, err := s.Query()
	return st.State, true, err
}

// ServiceImage returns the program the machine-mode service runs (the
// first word of its command line), or false when it is not installed.
func ServiceImage() (string, bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", false, err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return "", false, nil
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return "", true, err
	}
	return ImageOf(c.BinaryPathName), true, nil
}

// StartService starts the machine-mode service when it is not running.
func StartService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State == svc.Running {
		return nil
	}
	return s.Start()
}

// StopService stops the machine-mode service and waits up to wait.
func StopService(wait time.Duration) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return nil // not installed
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return err
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("winsvc: stop: %w", err)
	}
	for deadline := time.Now().Add(wait); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if st, err := s.Query(); err == nil && st.State == svc.Stopped {
			return nil
		}
	}
	return errors.New("winsvc: the service did not stop in time")
}

// DeleteService removes the machine-mode service registration.
func DeleteService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return nil
	}
	defer s.Close()
	return s.Delete()
}

var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupAdd        = netapi32.NewProc("NetLocalGroupAdd")
	procNetLocalGroupAddMembers = netapi32.NewProc("NetLocalGroupAddMembers")
	procNetLocalGroupDel        = netapi32.NewProc("NetLocalGroupDel")
)

const (
	nerrGroupExists    = 2223
	errorAliasExists   = 1379
	errorMemberInAlias = 1378
	nerrGroupNotFound  = 2220
	errorNoSuchAlias   = 1376
)

// EnsureLocalGroup creates a local group (CP-46 smcp-harness and
// smcp-operators) and reports whether it was created.
func EnsureLocalGroup(name, comment string) (bool, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	c, err := windows.UTF16PtrFromString(comment)
	if err != nil {
		return false, err
	}
	info := struct {
		name, comment *uint16
	}{n, c}
	r, _, _ := procNetLocalGroupAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), 0) //nolint:gosec // LOCALGROUP_INFO_1
	switch r {
	case 0:
		return true, nil
	case nerrGroupExists, errorAliasExists:
		return false, nil
	}
	return false, fmt.Errorf("winsvc: NetLocalGroupAdd %s: %w", name, windows.Errno(r))
}

// AddLocalGroupMember adds an account SID to a local group; a member
// already in the group is not an error.
func AddLocalGroupMember(group, sidStr string) error {
	g, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return err
	}
	sid, err := windows.StringToSid(sidStr)
	if err != nil {
		return err
	}
	info := struct{ sid *windows.SID }{sid}
	r, _, _ := procNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(g)), 0, uintptr(unsafe.Pointer(&info)), 1) //nolint:gosec // LOCALGROUP_MEMBERS_INFO_0
	if r != 0 && r != errorMemberInAlias {
		return fmt.Errorf("winsvc: add %s to %s: %w", sidStr, group, windows.Errno(r))
	}
	return nil
}

// DeleteLocalGroup removes a local group; a missing group is not an error.
func DeleteLocalGroup(name string) error {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r, _, _ := procNetLocalGroupDel.Call(0, uintptr(unsafe.Pointer(n))) //nolint:gosec // the group name
	if r != 0 && r != nerrGroupNotFound && r != errorNoSuchAlias {
		return fmt.Errorf("winsvc: delete group %s: %w", name, windows.Errno(r))
	}
	return nil
}
