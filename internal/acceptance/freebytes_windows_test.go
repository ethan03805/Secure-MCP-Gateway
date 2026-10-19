//go:build windows

package acceptance

import (
	"testing"

	"golang.org/x/sys/windows"
)

func freeBytes(t *testing.T, dir string) uint64 {
	t.Helper()
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
		t.Fatal(err)
	}
	return avail
}
