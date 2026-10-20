//go:build windows

package winsandbox

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

var (
	moduserenv                                    = windows.NewLazySystemDLL("userenv.dll")
	procCreateAppContainerProfile                 = moduserenv.NewProc("CreateAppContainerProfile")
	procDeleteAppContainerProfile                 = moduserenv.NewProc("DeleteAppContainerProfile")
	procDeriveAppContainerSidFromAppContainerName = moduserenv.NewProc("DeriveAppContainerSidFromAppContainerName")
)

// hresultAlreadyExists is HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS).
const hresultAlreadyExists = 0x800700B7

// hresultNotFound is HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), returned by
// DeleteAppContainerProfile for a profile that does not exist.
const hresultNotFound = 0x80070002

// CreateProfile creates the AppContainer profile name with no capabilities,
// or opens it when it exists, and returns its container (FR-21.13). The
// name is the profile's identity: ProfileName derives it from a server
// revision.
func CreateProfile(name, display string) (*Container, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	d, err := windows.UTF16PtrFromString(display)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	hr, _, _ := procCreateAppContainerProfile.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(d)),
		0, 0, uintptr(unsafe.Pointer(&sid)))
	switch uint32(hr) {
	case 0:
	case hresultAlreadyExists:
		return OpenProfile(name)
	default:
		return nil, fmt.Errorf("CreateAppContainerProfile %s: HRESULT 0x%08X", name, uint32(hr))
	}
	defer func() { _ = windows.FreeSid(sid) }()
	c, err := sid.Copy()
	if err != nil {
		return nil, err
	}
	return &Container{Name: name, SID: c}, nil
}

// OpenProfile derives the SID of the AppContainer profile name. The SID
// depends on the name only, so this works whether or not the profile
// exists; CreateProfile is what registers it.
func OpenProfile(name string) (*Container, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	hr, _, _ := procDeriveAppContainerSidFromAppContainerName.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&sid)))
	if hr != 0 {
		return nil, fmt.Errorf("DeriveAppContainerSidFromAppContainerName %s: HRESULT 0x%08X", name, uint32(hr))
	}
	defer func() { _ = windows.FreeSid(sid) }()
	c, err := sid.Copy()
	if err != nil {
		return nil, err
	}
	return &Container{Name: name, SID: c}, nil
}

// DeleteProfile removes the AppContainer profile name; a profile that does
// not exist is not an error.
func DeleteProfile(name string) error {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	hr, _, _ := procDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(n)))
	if hr != 0 && uint32(hr) != hresultNotFound {
		return fmt.Errorf("DeleteAppContainerProfile %s: HRESULT 0x%08X", name, uint32(hr))
	}
	return nil
}

// Access is the access an AppContainer SID is granted on a path (SR-4.6-2).
type Access int

// Access levels.
const (
	// ReadExecute lets the backend read and run files: the package tree
	// and read-only filesystem slots.
	ReadExecute Access = iota + 1
	// Modify adds writing, creating and deleting: the scratch directory and
	// writable slots.
	Modify
)

func (a Access) mask() windows.ACCESS_MASK {
	switch a {
	case ReadExecute:
		return windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE
	case Modify:
		return windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE | windows.FILE_GENERIC_WRITE | windows.DELETE
	}
	return 0
}

// Grant gives sid access a on path, inherited by every file and directory
// below a directory (SR-4.6-2). It is winsec.Grant, the primitive shared
// with the platform runtime: an earlier entry for sid on the path is
// replaced, so changing a grant from Modify to ReadExecute takes effect,
// and Windows propagates the inherited entry to the existing tree once,
// here, and not at each start of the backend.
func Grant(path string, sid *windows.SID, a Access) error {
	if a.mask() == 0 {
		return errors.New("winsandbox: unknown access")
	}
	if err := winsec.Grant(path, sid.String(), winsec.Access(a.mask())); err != nil {
		return fmt.Errorf("grant %s on %s: %w", sid, path, err)
	}
	return nil
}

// Revoke removes every explicit entry for sid on path and the entries its
// children inherited from them (winsec.Revoke).
func Revoke(path string, sid *windows.SID) error {
	return winsec.Revoke(path, sid.String())
}

// Entry is one access-allowed or access-denied entry of a DACL.
type Entry struct {
	SID       string
	Mask      uint32
	Allowed   bool
	Inherited bool
}

// Entries lists the access entries of path's DACL that name sid, or every
// entry when sid is nil.
func Entries(path string, sid *windows.SID) ([]Entry, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return nil, err
	}
	var out []Entry
	for i := range uint32(acl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return nil, err
		}
		t := ace.Header.AceType
		if t != windows.ACCESS_ALLOWED_ACE_TYPE && t != windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		s := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid != nil && !s.Equals(sid) {
			continue
		}
		out = append(out, Entry{SID: s.String(), Mask: uint32(ace.Mask), Allowed: t == windows.ACCESS_ALLOWED_ACE_TYPE,
			Inherited: ace.Header.AceFlags&windows.INHERITED_ACE != 0})
	}
	return out, nil
}

// tokenAppContainerSid is the TOKEN_INFORMATION_CLASS TokenAppContainerSid.
const tokenAppContainerSid = 31

// ProcessAppContainer returns the AppContainer SID of the process's token,
// or nil when the process does not run in an AppContainer (SR-4.1-3
// inspection).
func ProcessAppContainer(pid uint32) (*windows.SID, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return nil, err
	}
	defer tok.Close()
	buf := make([]byte, 256)
	var n uint32
	if err := windows.GetTokenInformation(tok, tokenAppContainerSid, &buf[0], uint32(len(buf)), &n); err != nil {
		return nil, fmt.Errorf("token AppContainer SID: %w", err)
	}
	sid := *(**windows.SID)(unsafe.Pointer(&buf[0]))
	if sid == nil {
		return nil, nil
	}
	return sid.Copy()
}
