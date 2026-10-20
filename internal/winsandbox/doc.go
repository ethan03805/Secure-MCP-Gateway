// Package winsandbox holds the Windows side of the Server Runtime Manager
// (E-15) and the Execution Sandbox (E-16): Job Objects with the CP-24
// resource limits and kill-on-close (FR-21.12), process creation that places
// the backend in its Job Object at creation (FR-21.11), AppContainer
// profiles (FR-21.13, SR-4.6-2) and the Windows Filtering Platform egress
// filters (FR-21.14, SR-4.5-3).
//
// The package builds on every platform so that callers need no build
// constraints; off Windows every constructor returns ErrUnsupported.
//
// None of this makes a Windows installation Enforced: every Windows mode runs
// the Standalone profile with the label "not enforced" (SR-4-2).
package winsandbox

import "errors"

// ErrUnsupported is returned off Windows.
var ErrUnsupported = errors.New("winsandbox: Windows only")

// Limits are the Job Object limits of one backend instance (FR-21.12). A
// zero field sets no limit of that kind; callers fill them from CP-24.
type Limits struct {
	// MemoryBytes bounds the committed memory of each process of the job
	// and of the job as a whole.
	MemoryBytes int64
	// CPUs is the CPU rate limit in processors (1.5 is one and a half
	// processors), applied as a hard cap on the job's share of all
	// processors.
	CPUs float64
	// Processes is the active-process limit.
	Processes int
}

// Accounting is the Job Object's basic accounting (FR-21.11, FR-21.12).
type Accounting struct {
	// TotalProcesses counts every process that was ever in the job,
	// including the ones that have exited.
	TotalProcesses uint32
	// ActiveProcesses counts the processes in the job now.
	ActiveProcesses uint32
	// TerminatedProcesses counts the processes the job ended because they
	// broke a limit.
	TerminatedProcesses uint32
	// UserTime and KernelTime are the CPU time of every process of the
	// job, in 100-nanosecond units.
	UserTime, KernelTime int64
}

// Violation names a limit a job reported as broken.
type Violation string

// Violations reported by a job.
const (
	ViolationMemory    Violation = "memory"
	ViolationProcesses Violation = "processes"
)

// cpuRate converts a processor count into the Job Object CPU rate (the
// share of all processors in hundredths of a percent, 1 to 10000), or 0
// when the limit covers every processor and is not set.
func cpuRate(cpus float64, ncpu int) uint32 {
	if cpus <= 0 || ncpu <= 0 {
		return 0
	}
	r := cpus / float64(ncpu) * 10000
	switch {
	case r >= 10000:
		return 0
	case r < 1:
		return 1
	}
	return uint32(r)
}
