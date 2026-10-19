//go:build windows

package probe

import (
	"time"

	"golang.org/x/sys/windows"
)

// cpuTime is the user and system CPU time the process has used.
func cpuTime() time.Duration {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u); err != nil {
		return 0
	}
	// Filetime counts 100-nanosecond intervals.
	ticks := func(f windows.Filetime) int64 { return int64(f.HighDateTime)<<32 | int64(f.LowDateTime) }
	return time.Duration((ticks(k) + ticks(u)) * 100)
}
