//go:build windows

package winsandbox

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Job Object constants that golang.org/x/sys/windows does not define.
const (
	jobObjectCPURateControlEnable  = 0x1
	jobObjectCPURateControlHardCap = 0x4

	jobObjectMsgActiveProcessLimit = 3
	jobObjectMsgActiveProcessZero  = 4
	jobObjectMsgProcessMemoryLimit = 9
	jobObjectMsgJobMemoryLimit     = 10
)

type cpuRateControlInformation struct {
	ControlFlags uint32
	CPURate      uint32
}

type basicAccountingInformation struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

type associateCompletionPort struct {
	CompletionKey  uintptr
	CompletionPort windows.Handle
}

// Job is one backend instance's Job Object (FR-21.12): kill-on-close, the
// memory, active-process and CPU rate limits, breakaway disallowed (neither
// JOB_OBJECT_LIMIT_BREAKAWAY_OK nor JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK is
// set) and the user-interface restrictions. Closing the Job, or the
// Gateway's process ending for any reason, terminates every process in it.
type Job struct {
	mu     sync.Mutex
	h      windows.Handle
	port   windows.Handle
	limits Limits
	viol   []Violation
	notify func(Violation)
	done   chan struct{}
}

// NewJob creates a Job Object with the given limits. onViolation, when not
// nil, is called once for each limit the job reports as broken; it runs on
// the job's own goroutine and must not block.
func NewJob(l Limits, onViolation func(Violation)) (*Job, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create job object: %w", err)
	}
	j := &Job{h: h, limits: l, notify: onViolation, done: make(chan struct{})}
	if err := j.configure(); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("job completion port: %w", err)
	}
	acp := associateCompletionPort{CompletionKey: 1, CompletionPort: port}
	if _, err := windows.SetInformationJobObject(h, windows.JobObjectAssociateCompletionPortInformation,
		uintptr(unsafe.Pointer(&acp)), uint32(unsafe.Sizeof(acp))); err != nil {
		_ = windows.CloseHandle(port)
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("associate job completion port: %w", err)
	}
	j.port = port
	go j.watch()
	return j, nil
}

func (j *Job) configure() error {
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	flags := uint32(windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION)
	if j.limits.MemoryBytes > 0 {
		flags |= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY | windows.JOB_OBJECT_LIMIT_JOB_MEMORY
		info.ProcessMemoryLimit = uintptr(j.limits.MemoryBytes)
		info.JobMemoryLimit = uintptr(j.limits.MemoryBytes)
	}
	if j.limits.Processes > 0 {
		flags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		info.BasicLimitInformation.ActiveProcessLimit = uint32(j.limits.Processes)
	}
	info.BasicLimitInformation.LimitFlags = flags
	if _, err := windows.SetInformationJobObject(j.h, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return fmt.Errorf("set job limits: %w", err)
	}
	if rate := cpuRate(j.limits.CPUs, runtime.NumCPU()); rate > 0 {
		cr := cpuRateControlInformation{ControlFlags: jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap, CPURate: rate}
		if _, err := windows.SetInformationJobObject(j.h, windows.JobObjectCpuRateControlInformation,
			uintptr(unsafe.Pointer(&cr)), uint32(unsafe.Sizeof(cr))); err != nil {
			return fmt.Errorf("set job CPU rate: %w", err)
		}
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: windows.JOB_OBJECT_UILIMIT_DESKTOP |
		windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | windows.JOB_OBJECT_UILIMIT_EXITWINDOWS |
		windows.JOB_OBJECT_UILIMIT_GLOBALATOMS | windows.JOB_OBJECT_UILIMIT_HANDLES |
		windows.JOB_OBJECT_UILIMIT_READCLIPBOARD | windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
		windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD}
	if _, err := windows.SetInformationJobObject(j.h, windows.JobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		return fmt.Errorf("set job UI restrictions: %w", err)
	}
	return nil
}

// watch reads the job's completion port until the port is closed.
func (j *Job) watch() {
	defer close(j.done)
	for {
		var msg uint32
		var key uintptr
		var ov *windows.Overlapped
		if err := windows.GetQueuedCompletionStatus(j.port, &msg, &key, &ov, windows.INFINITE); err != nil {
			return // the port was closed
		}
		if key != 1 {
			return // the wake-up posted by Close
		}
		var v Violation
		switch msg {
		case jobObjectMsgProcessMemoryLimit, jobObjectMsgJobMemoryLimit:
			v = ViolationMemory
		case jobObjectMsgActiveProcessLimit:
			v = ViolationProcesses
		default:
			continue
		}
		j.mu.Lock()
		j.viol = append(j.viol, v)
		notify := j.notify
		j.mu.Unlock()
		if notify != nil {
			notify(v)
		}
	}
}

// Handle returns the job's handle, valid until Close.
func (j *Job) Handle() windows.Handle { return j.h }

// Limits returns the limits the job was created with.
func (j *Job) Limits() Limits { return j.limits }

// Violations returns the limits the job has reported as broken, in order.
func (j *Job) Violations() []Violation {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]Violation(nil), j.viol...)
}

// Accounting returns the job's basic accounting.
func (j *Job) Accounting() (Accounting, error) {
	var bi basicAccountingInformation
	if err := windows.QueryInformationJobObject(j.h, windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&bi)), uint32(unsafe.Sizeof(bi)), nil); err != nil {
		return Accounting{}, fmt.Errorf("query job accounting: %w", err)
	}
	return Accounting{TotalProcesses: bi.TotalProcesses, ActiveProcesses: bi.ActiveProcesses,
		TerminatedProcesses: bi.TotalTerminatedProcesses, UserTime: bi.TotalUserTime, KernelTime: bi.TotalKernelTime}, nil
}

// PIDs returns the process IDs of the processes in the job now.
func (j *Job) PIDs() ([]uint32, error) {
	const max = 1024
	var buf struct {
		Assigned, InList uint32
		IDs              [max]uintptr
	}
	if err := windows.QueryInformationJobObject(j.h, windows.JobObjectBasicProcessIdList,
		uintptr(unsafe.Pointer(&buf)), uint32(unsafe.Sizeof(buf)), nil); err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
		return nil, fmt.Errorf("query job processes: %w", err)
	}
	out := make([]uint32, 0, buf.InList)
	for _, id := range buf.IDs[:min(buf.InList, max)] {
		out = append(out, uint32(id))
	}
	return out, nil
}

// Contains reports whether the process is in this job.
func (j *Job) Contains(process windows.Handle) (bool, error) {
	var in int32
	r, _, err := procIsProcessInJob.Call(uintptr(process), uintptr(j.h), uintptr(unsafe.Pointer(&in)))
	if r == 0 {
		return false, fmt.Errorf("IsProcessInJob: %w", err)
	}
	return in != 0, nil
}

// Terminate ends every process in the job with the exit code.
func (j *Job) Terminate(code uint32) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.h == 0 {
		return nil
	}
	return windows.TerminateJobObject(j.h, code)
}

// Close closes the job handle, which terminates every process still in it
// (kill-on-close), and stops the notification goroutine.
func (j *Job) Close() error {
	j.mu.Lock()
	h, port := j.h, j.port
	j.h, j.port = 0, 0
	j.mu.Unlock()
	if h == 0 {
		return nil
	}
	err := windows.CloseHandle(h)
	if port != 0 {
		_ = windows.PostQueuedCompletionStatus(port, 0, 0, nil)
		<-j.done
		_ = windows.CloseHandle(port)
	}
	return err
}
