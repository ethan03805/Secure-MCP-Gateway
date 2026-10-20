//go:build windows

package winsandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procIsProcessInJob = modkernel32.NewProc("IsProcessInJob")
)

// Process-creation attributes that golang.org/x/sys/windows does not define.
const (
	procThreadAttributeJobList              = 0x0002000D
	procThreadAttributeSecurityCapabilities = 0x00020009
	procThreadAttributeAllAppPackagesPolicy = 0x0002000F

	processCreationAllApplicationPackagesOptOut = 1
)

// StartOptions describe one backend process.
type StartOptions struct {
	// Path is the absolute path of the executable. It is passed to
	// CreateProcess as the application name, so no search path applies.
	Path string
	// Args are the arguments after the program name. They are joined into
	// one command line by the Microsoft C runtime quoting rules
	// (CommandLineToArgvW), so a program using the C runtime or
	// CommandLineToArgvW receives them unchanged; no shell is involved and
	// nothing in them is expanded.
	Args []string
	// Env is the complete environment as KEY=value strings. SYSTEMROOT is
	// added from the Gateway's environment when absent, because Windows
	// components such as Winsock fail without it.
	Env []string
	// Dir is the working directory, or "" for the Gateway's.
	Dir string
	// Stdin, Stdout and Stderr are the child's ends of its standard
	// streams. They are the only handles the child inherits.
	Stdin, Stdout, Stderr *os.File
	// Job is the Job Object the process belongs to from creation (FR-21.11).
	// Required.
	Job *Job
	// Container, when not nil, runs the process under that AppContainer
	// profile with no capabilities (FR-21.13).
	Container *Container
}

// Start creates the process. The process is a member of o.Job from its
// creation: the job is passed with PROC_THREAD_ATTRIBUTE_JOB_LIST, so no
// instruction of the backend runs outside it (FR-21.11), and no later
// AssignProcessToJobObject call is made.
func Start(o StartOptions) (*os.Process, error) {
	if err := CheckCommand(o.Path); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(o.Path) {
		return nil, fmt.Errorf("executable %q is not an absolute path", o.Path)
	}
	if o.Job == nil || o.Job.Handle() == 0 {
		return nil, fmt.Errorf("no job object for %s", o.Path)
	}
	if o.Stdin == nil || o.Stdout == nil || o.Stderr == nil {
		return nil, fmt.Errorf("standard streams of %s not set", o.Path)
	}
	app, err := windows.UTF16PtrFromString(o.Path)
	if err != nil {
		return nil, err
	}
	line := windows.ComposeCommandLine(append([]string{o.Path}, o.Args...))
	cmdline, err := windows.UTF16PtrFromString(line)
	if err != nil {
		return nil, err
	}
	var dir *uint16
	if o.Dir != "" {
		if dir, err = windows.UTF16PtrFromString(o.Dir); err != nil {
			return nil, err
		}
	}
	required := []string{"SYSTEMROOT"}
	if o.Container != nil {
		// CreateProcess rewrites these for an AppContainer (to the
		// container's own folders) and fails with ERROR_ENVVAR_NOT_FOUND
		// when one is missing from the block.
		required = append(required, "LOCALAPPDATA", "APPDATA", "USERPROFILE", "TEMP", "TMP")
	}
	env, err := envBlock(o.Env, required...)
	if err != nil {
		return nil, err
	}

	handles := []windows.Handle{}
	for _, f := range []*os.File{o.Stdin, o.Stdout, o.Stderr} {
		if h := windows.Handle(f.Fd()); !slices.Contains(handles, h) {
			handles = append(handles, h)
		}
	}
	attrs, err := windows.NewProcThreadAttributeList(4)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return nil, fmt.Errorf("handle list: %w", err)
	}
	jobs := []windows.Handle{o.Job.Handle()}
	if err := attrs.Update(procThreadAttributeJobList, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs[0])); err != nil {
		return nil, fmt.Errorf("job list: %w", err)
	}
	var caps securityCapabilities
	var optOut uint32
	if o.Container != nil {
		caps.AppContainerSid = o.Container.SID
		if err := attrs.Update(procThreadAttributeSecurityCapabilities, unsafe.Pointer(&caps), unsafe.Sizeof(caps)); err != nil {
			return nil, fmt.Errorf("security capabilities: %w", err)
		}
		if o.Container.LessPrivileged {
			optOut = processCreationAllApplicationPackagesOptOut
			if err := attrs.Update(procThreadAttributeAllAppPackagesPolicy, unsafe.Pointer(&optOut), unsafe.Sizeof(optOut)); err != nil {
				return nil, fmt.Errorf("less privileged AppContainer: %w", err)
			}
		}
	}

	si := new(windows.StartupInfoEx)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdInput = windows.Handle(o.Stdin.Fd())
	si.StdOutput = windows.Handle(o.Stdout.Fd())
	si.StdErr = windows.Handle(o.Stderr.Fd())
	si.ProcThreadAttributeList = attrs.List()
	pi := new(windows.ProcessInformation)
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT |
		windows.CREATE_NO_WINDOW | windows.CREATE_DEFAULT_ERROR_MODE)

	// The child's ends must be inheritable for the handle list; hold the
	// fork lock so that no other process creation of this process sees them
	// inheritable (the same rule os/exec follows).
	syscall.ForkLock.Lock()
	for _, h := range handles {
		if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			syscall.ForkLock.Unlock()
			return nil, fmt.Errorf("inheritable handle: %w", err)
		}
	}
	err = windows.CreateProcess(app, cmdline, nil, nil, true, flags, env, dir, &si.StartupInfo, pi)
	for _, h := range handles {
		_ = windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, 0)
	}
	syscall.ForkLock.Unlock()
	if err != nil {
		return nil, fmt.Errorf("CreateProcess %s: %w", o.Path, err)
	}
	_ = windows.CloseHandle(pi.Thread)
	// os.FindProcess opens a second handle by PID; the PID cannot be reused
	// while pi.Process is open.
	p, ferr := os.FindProcess(int(pi.ProcessId))
	_ = windows.CloseHandle(pi.Process)
	if ferr != nil {
		_ = o.Job.Terminate(1)
		return nil, fmt.Errorf("open process %d: %w", pi.ProcessId, ferr)
	}
	return p, nil
}

// Container is the AppContainer profile a process runs under (FR-21.13).
type Container struct {
	// Name is the profile name.
	Name string
	// SID is the AppContainer SID derived from Name.
	SID *windows.SID
	// LessPrivileged runs the process as a Less Privileged AppContainer,
	// which is not granted the ALL APPLICATION PACKAGES entries.
	LessPrivileged bool
}

type securityCapabilities struct {
	AppContainerSid *windows.SID
	Capabilities    uintptr // *SID_AND_ATTRIBUTES; none
	CapabilityCount uint32
	Reserved        uint32
}

// envBlock builds a Unicode environment block: KEY=value strings sorted by
// name without regard to case, each terminated by NUL, and a final NUL.
// Each required variable the block lacks is taken from the Gateway's
// environment.
func envBlock(env []string, required ...string) (*uint16, error) {
	env = slices.Clone(env)
	has := map[string]bool{}
	for _, kv := range env {
		if strings.Contains(kv, "\x00") {
			return nil, fmt.Errorf("environment entry contains NUL")
		}
		k, _, _ := strings.Cut(kv, "=")
		has[strings.ToUpper(k)] = true
	}
	for _, k := range required {
		if !has[k] {
			if v := os.Getenv(k); v != "" {
				env = append(env, k+"="+v)
			}
		}
	}
	slices.SortStableFunc(env, func(a, b string) int {
		ka, _, _ := strings.Cut(a, "=")
		kb, _, _ := strings.Cut(b, "=")
		return strings.Compare(strings.ToUpper(ka), strings.ToUpper(kb))
	})
	var b []uint16
	for _, kv := range env {
		b = append(b, utf16.Encode([]rune(kv))...)
		b = append(b, 0)
	}
	if len(b) == 0 {
		b = append(b, 0)
	}
	b = append(b, 0)
	return &b[0], nil
}
