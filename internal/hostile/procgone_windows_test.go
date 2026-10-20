//go:build hostile && windows

package hostile

import "golang.org/x/sys/windows"

// processGone reports whether the process pid has ended.
func processGone(pid int) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid)) //nolint:gosec // a process ID
	if err != nil {
		return true
	}
	defer func() { _ = windows.CloseHandle(h) }()
	ev, err := windows.WaitForSingleObject(h, 0)
	return err == nil && ev == windows.WAIT_OBJECT_0
}
