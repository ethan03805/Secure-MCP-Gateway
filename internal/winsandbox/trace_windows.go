//go:build windows

package winsandbox

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// jobObjectMsgNewProcess is JOB_OBJECT_MSG_NEW_PROCESS: the overlapped
// value of the completion packet is the new process's ID.
const jobObjectMsgNewProcess = 6

// ProcessTrace records every process created in a Job Object that holds
// the calling process and, from creation, all of its descendants, nested
// Job Objects included (SR-4.8-2: the process-creation trace of a Windows
// test run). It needs no administrator.
type ProcessTrace struct {
	job, port windows.Handle
	mu        sync.Mutex
	recs      []ProcessRecord
	done      chan struct{}
}

// TraceCurrentProcess places the calling process in a new Job Object
// without limits and starts recording the processes created in it. The
// process stays in the job until it ends; Close stops the recording.
func TraceCurrentProcess() (*ProcessTrace, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create trace job: %w", err)
	}
	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("trace completion port: %w", err)
	}
	acp := associateCompletionPort{CompletionKey: 1, CompletionPort: port}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectAssociateCompletionPortInformation,
		uintptr(unsafe.Pointer(&acp)), uint32(unsafe.Sizeof(acp))); err != nil {
		_ = windows.CloseHandle(port)
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("associate trace completion port: %w", err)
	}
	if err := windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		_ = windows.CloseHandle(port)
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("assign this process to the trace job: %w", err)
	}
	t := &ProcessTrace{job: job, port: port, done: make(chan struct{})}
	go t.watch()
	return t, nil
}

func (t *ProcessTrace) watch() {
	defer close(t.done)
	self := windows.GetCurrentProcessId()
	for {
		var msg uint32
		var key uintptr
		var ov *windows.Overlapped
		if err := windows.GetQueuedCompletionStatus(t.port, &msg, &key, &ov, windows.INFINITE); err != nil || key != 1 {
			return
		}
		if msg != jobObjectMsgNewProcess {
			continue
		}
		pid := uint32(uintptr(unsafe.Pointer(ov))) //nolint:gosec // the packet carries the process ID in the pointer
		if pid == self {
			continue
		}
		rec := describeProcess(pid)
		t.mu.Lock()
		t.recs = append(t.recs, rec)
		t.mu.Unlock()
	}
}

// describeProcess reads the image path and the parent process ID.
func describeProcess(pid uint32) ProcessRecord {
	rec := ProcessRecord{PID: pid}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return rec
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var pbi windows.PROCESS_BASIC_INFORMATION
	if windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil) == nil {
		rec.ParentPID = uint32(pbi.InheritedFromUniqueProcessId) //nolint:gosec // a process ID
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
		rec.Image = windows.UTF16ToString(buf[:n])
	}
	return rec
}

// Records returns the processes recorded so far, in creation order.
func (t *ProcessTrace) Records() []ProcessRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]ProcessRecord(nil), t.recs...)
}

// Total returns the number of processes the job's accounting counted,
// the calling process included, so a caller can tell whether a record
// is missing.
func (t *ProcessTrace) Total() (uint32, error) {
	var bi basicAccountingInformation
	if err := windows.QueryInformationJobObject(t.job, windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&bi)), uint32(unsafe.Sizeof(bi)), nil); err != nil {
		return 0, err
	}
	return bi.TotalProcesses, nil
}

// Close stops the recording. The job handle is kept open, so the calling
// process and its descendants stay in it (a job without kill-on-close).
func (t *ProcessTrace) Close() error {
	err := windows.PostQueuedCompletionStatus(t.port, 0, 0, nil)
	<-t.done
	return err
}
