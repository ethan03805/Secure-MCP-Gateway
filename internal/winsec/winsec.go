// Package winsec holds the Windows security primitives of the Gateway
// (SRS FR-21): security identifiers, protected DACLs on files and
// directories (FR-21.5, CP-46), DPAPI protection of private keys
// (FR-21.10, SR-2.13-4), write-through file replacement (FR-21.23) and the
// free space of a volume (FR-21.26).
//
// Every function has a Windows implementation and, on other platforms, a
// stub that returns ErrNotWindows, so callers can be written once and
// select the Windows path with runtime.GOOS or a build constraint. On
// macOS and Linux nothing in this package is called by the Gateway.
//
// This package is the boundary between the Windows platform runtime (this
// package, the named-pipe transport, the service and the installer) and
// the Windows sandbox (AppContainer profiles, Job Objects, WFP filters):
// the sandbox grants an AppContainer SID access to a package tree with
// Grant and removes it with Revoke, and reads the account the Gateway runs
// under with ProcessUserSID. Neither side changes the other's files.
package winsec

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrNotWindows is returned by every function of this package on a
// platform other than Windows.
var ErrNotWindows = errors.New("winsec: only available on Windows")

// Well-known security identifiers used by the CP-46 access control lists.
const (
	SIDSystem             = "S-1-5-18"
	SIDAdministrators     = "S-1-5-32-544"
	SIDUsers              = "S-1-5-32-545"
	SIDAuthenticatedUsers = "S-1-5-11"
	SIDEveryone           = "S-1-1-0"
	SIDNetwork            = "S-1-5-2"
	SIDAnonymous          = "S-1-5-7"
	SIDCreatorOwner       = "S-1-3-0"
	// SIDAllAppPackages is ALL APPLICATION PACKAGES, which every
	// AppContainer token carries.
	SIDAllAppPackages = "S-1-15-2-1"
)

// Access is a file access mask.
type Access uint32

// The access masks CP-46 names. They are the masks Windows Explorer and
// icacls write for the same names.
const (
	// FullControl is FILE_ALL_ACCESS.
	FullControl Access = 0x001F01FF
	// Modify is read, write, execute and delete, without changing the DACL
	// or the owner.
	Modify Access = 0x001301BF
	// ReadExecute is FILE_GENERIC_READ | FILE_GENERIC_EXECUTE.
	ReadExecute Access = 0x001200A9
	// Read is FILE_GENERIC_READ.
	Read Access = 0x00120089
	// ReadWrite is FILE_GENERIC_READ | FILE_GENERIC_WRITE, the access of a
	// named-pipe client (SR-2.8-6).
	ReadWrite Access = 0x0012019F
)

// Entry is one access control entry: an allow entry, or a deny entry when
// Deny is set.
type Entry struct {
	SID    string
	Access Access
	Deny   bool
}

func (e Entry) String() string {
	kind := "allow"
	if e.Deny {
		kind = "deny"
	}
	return fmt.Sprintf("%s %s 0x%08x", kind, e.SID, uint32(e.Access))
}

// ErrForeignAccess is returned by CheckDACL when an object grants access
// to a security identifier outside the allowed set, has inheritance
// enabled where it must be disabled, or has no DACL at all.
var ErrForeignAccess = errors.New("access control list grants access outside the allowed accounts")

// ACLError describes why CheckDACL refused an object.
type ACLError struct {
	Path string
	// Foreign lists the allow entries naming an SID outside the allowed set.
	Foreign []Entry
	// Inherited is set when the object's DACL is not protected but had to be.
	Inherited bool
	// Null is set when the object has no DACL (everyone has full access).
	Null bool
}

func (e *ACLError) Error() string {
	var why []string
	if e.Null {
		why = append(why, "it has no DACL, which grants everyone full access")
	}
	if e.Inherited {
		why = append(why, "inheritance is enabled")
	}
	for _, f := range e.Foreign {
		why = append(why, "it grants "+f.SID)
	}
	return fmt.Sprintf("%s: %s", e.Path, strings.Join(why, "; "))
}

// Unwrap makes errors.Is(err, ErrForeignAccess) true.
func (e *ACLError) Unwrap() error { return ErrForeignAccess }

// Evaluate compares a DACL, as read by DACL, with the allowed SIDs. Deny
// entries never make an object less private, so only allow entries are
// compared. requireProtected refuses a DACL that inherits from the parent.
// It returns nil or an *ACLError.
func Evaluate(path string, protected, null bool, entries []Entry, requireProtected bool, allowed ...string) error {
	e := &ACLError{Path: path, Null: null, Inherited: requireProtected && !protected}
	for _, ent := range entries {
		if ent.Deny || ent.Access == 0 {
			continue
		}
		if !slices.Contains(allowed, ent.SID) {
			e.Foreign = append(e.Foreign, ent)
		}
	}
	if e.Null || e.Inherited || len(e.Foreign) > 0 {
		return e
	}
	return nil
}

// dpapiHeader is the start of every classic DPAPI blob: dwVersion 1 and
// the provider GUID df9d8cd0-1501-11d1-8c7a-00c04fc297eb in its binary
// (mixed-endian) form.
var dpapiHeader = []byte{
	0x01, 0x00, 0x00, 0x00,
	0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb,
}

// IsProtectedBlob reports whether b starts like a classic DPAPI blob
// (CryptProtectData output). It reads only the header; Unprotect is the
// test of whether the blob is intact and belongs to this account.
func IsProtectedBlob(b []byte) bool {
	return len(b) > len(dpapiHeader) && bytes.HasPrefix(b, dpapiHeader)
}

// OwnerEntries returns the CP-46 per-user entries for a private directory
// or file: full control for the given account, SYSTEM and Administrators.
func OwnerEntries(userSID string) []Entry {
	return []Entry{
		{SID: userSID, Access: FullControl},
		{SID: SIDSystem, Access: FullControl},
		{SID: SIDAdministrators, Access: FullControl},
	}
}
