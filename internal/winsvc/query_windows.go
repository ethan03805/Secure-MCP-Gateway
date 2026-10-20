//go:build windows

package winsvc

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// QueryService reports whether the machine-mode service runs, with only
// the rights an unelevated user has (SC_MANAGER_CONNECT and
// SERVICE_QUERY_STATUS), so the Desktop Application can show it without
// User Account Control (FR-20.3). Stopped and stop pending count as not
// running; every other state as running. installed is false when no
// service of that name is registered.
func QueryService() (running, installed bool, err error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, false, fmt.Errorf("winsvc: connect to the service manager: %w", err)
	}
	defer func() { _ = windows.CloseServiceHandle(m) }()
	name, err := windows.UTF16PtrFromString(ServiceName)
	if err != nil {
		return false, false, err
	}
	h, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("winsvc: open service %s: %w", ServiceName, err)
	}
	defer func() { _ = windows.CloseServiceHandle(h) }()
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(h, &st); err != nil {
		return false, true, fmt.Errorf("winsvc: query service %s: %w", ServiceName, err)
	}
	switch svc.State(st.CurrentState) {
	case svc.Stopped, svc.StopPending:
		return false, true, nil
	default:
		return true, true, nil
	}
}

// PerUserRunning reports whether a per-user smcpd or its supervisor of the
// installation whose configuration is cfgPath runs: both hold the
// installation's stop event (StopEventName) open while they run. Unlike
// SignalStop it does not set the event.
func PerUserRunning(cfgPath string) (bool, error) {
	name, err := windows.UTF16PtrFromString(StopEventName(cfgPath))
	if err != nil {
		return false, err
	}
	ev, err := windows.OpenEvent(windows.SYNCHRONIZE, false, name)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("winsvc: open stop event: %w", err)
	}
	_ = windows.CloseHandle(ev)
	return true, nil
}
