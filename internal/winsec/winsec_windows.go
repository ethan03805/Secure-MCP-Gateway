//go:build windows

package winsec

import (
	"errors"
	"fmt"
	"math"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessUserSID returns the user SID of the current process token: the
// installing user in the per-user mode, NT SERVICE\smcpd in the machine
// mode (CP-46).
func ProcessUserSID() (string, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("winsec: read process token user: %w", err)
	}
	return tu.User.Sid.String(), nil
}

// LookupSID returns the SID string of an account name such as
// "NT SERVICE\smcpd" or "smcp-harness".
func LookupSID(account string) (string, error) {
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return "", fmt.Errorf("winsec: look up %q: %w", account, err)
	}
	return sid.String(), nil
}

func explicit(entries []Entry, inherit bool) ([]windows.EXPLICIT_ACCESS, error) {
	inh := uint32(windows.NO_INHERITANCE)
	if inherit {
		inh = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	out := make([]windows.EXPLICIT_ACCESS, 0, len(entries))
	// Deny entries first: SetEntriesInAcl keeps the order it is given for
	// entries of the same kind, and canonical order puts deny before allow.
	for pass := 0; pass < 2; pass++ {
		for _, e := range entries {
			if e.Deny != (pass == 0) {
				continue
			}
			sid, err := windows.StringToSid(e.SID)
			if err != nil {
				return nil, fmt.Errorf("winsec: SID %q: %w", e.SID, err)
			}
			mode := windows.ACCESS_MODE(windows.GRANT_ACCESS)
			if e.Deny {
				mode = windows.DENY_ACCESS
			}
			out = append(out, windows.EXPLICIT_ACCESS{
				AccessPermissions: windows.ACCESS_MASK(e.Access),
				AccessMode:        mode,
				Inheritance:       inh,
				Trustee: windows.TRUSTEE{
					TrusteeForm:  windows.TRUSTEE_IS_SID,
					TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
					TrusteeValue: windows.TrusteeValueFromSID(sid),
				},
			})
		}
	}
	return out, nil
}

// SetProtectedDACL replaces the DACL of path with exactly entries and
// disables inheritance from the parent (FR-21.5). On a directory the
// entries are inherited by the files and directories below it, and
// Windows re-applies the inherited part of their DACLs.
func SetProtectedDACL(path string, entries []Entry) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	ea, err := explicit(entries, fi.IsDir())
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		return fmt.Errorf("winsec: build DACL for %s: %w", path, err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("winsec: set DACL of %s: %w", path, err)
	}
	return nil
}

// SetProtectedDACLHandle sets a protected DACL with exactly entries on an
// open handle of the given object type (a file, a named pipe).
func SetProtectedDACLHandle(h windows.Handle, objType windows.SE_OBJECT_TYPE, entries []Entry) error {
	ea, err := explicit(entries, false)
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(h, objType,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// SecurityAttributes returns security attributes whose descriptor has a
// protected DACL with exactly entries, for CreateNamedPipe and CreateFile.
// The descriptor is self-relative and owned by the Go heap.
func SecurityAttributes(entries []Entry) (*windows.SecurityAttributes, error) {
	ea, err := explicit(entries, false)
	if err != nil {
		return nil, err
	}
	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		return nil, err
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		return nil, err
	}
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return nil, err
	}
	rel, err := sd.ToSelfRelative()
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: rel}
	sa.Length = uint32(unsafe.Sizeof(*sa)) //nolint:gosec // the structure size
	return sa, nil
}

// readDescriptor returns the DACL entries of a security descriptor.
func readDescriptor(sd *windows.SECURITY_DESCRIPTOR) (protected, null bool, entries []Entry, err error) {
	ctl, _, err := sd.Control()
	if err != nil {
		return false, false, nil, err
	}
	protected = ctl&windows.SE_DACL_PROTECTED != 0
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil) {
		return protected, true, nil, nil
	}
	if err != nil {
		return false, false, nil, err
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, false, nil, err
		}
		e := Entry{Access: Access(ace.Mask)}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			e.SID = aceSID(ace)
		case windows.ACCESS_DENIED_ACE_TYPE:
			e.SID = aceSID(ace)
			e.Deny = true
		default:
			// Object, callback and conditional entries are never written by
			// the Gateway; reporting one with an unknown SID makes the check
			// refuse it rather than guess what it grants.
			e.SID = fmt.Sprintf("(ACE type %d)", ace.Header.AceType)
		}
		entries = append(entries, e)
	}
	return protected, false, entries, nil
}

// DACL reads the DACL of path: whether it is protected from inheritance,
// whether it is a NULL DACL, and its entries in order.
func DACL(path string) (protected, null bool, entries []Entry, err error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, false, nil, fmt.Errorf("winsec: read DACL of %s: %w", path, err)
	}
	return readDescriptor(sd)
}

// DACLHandle reads the DACL of an open handle (a named pipe).
func DACLHandle(h windows.Handle, objType windows.SE_OBJECT_TYPE) (protected, null bool, entries []Entry, err error) {
	sd, err := windows.GetSecurityInfo(h, objType, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, false, nil, err
	}
	return readDescriptor(sd)
}

// CheckDACL refuses path when its DACL grants access to an SID outside
// allowed, is a NULL DACL, or (with requireProtected) inherits from its
// parent (FR-21.5). The error is an *ACLError wrapping ErrForeignAccess.
func CheckDACL(path string, requireProtected bool, allowed ...string) error {
	protected, null, entries, err := DACL(path)
	if err != nil {
		return err
	}
	return Evaluate(path, protected, null, entries, requireProtected, allowed...)
}

// Grant adds an allow entry for sid to the DACL of path, keeping the
// existing entries and the protection state. On a directory the entry is
// inherited below it. It is the call the Windows sandbox uses to give an
// AppContainer SID access to a package tree (SR-4.6-2).
func Grant(path, sid string, access Access) error {
	return merge(path, sid, access, windows.GRANT_ACCESS)
}

// Revoke removes every explicit entry naming sid from the DACL of path.
func Revoke(path, sid string) error {
	return merge(path, sid, 0, windows.REVOKE_ACCESS)
}

func merge(path, sidStr string, access Access, mode windows.ACCESS_MODE) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	ctl, _, err := sd.Control()
	if err != nil {
		return err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return err
	}
	sid, err := windows.StringToSid(sidStr)
	if err != nil {
		return err
	}
	inh := uint32(windows.NO_INHERITANCE)
	if fi.IsDir() {
		inh = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.ACCESS_MASK(access),
		AccessMode:        mode,
		Inheritance:       inh,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, old)
	if err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if ctl&windows.SE_DACL_PROTECTED != 0 {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, acl, nil)
}

// Protect encrypts data with classic DPAPI under the current account
// (CryptProtectData, user scope, no UI), FR-21.10 and SR-2.13-4.
func Protect(data []byte) ([]byte, error) {
	in, err := blob(data)
	if err != nil {
		return nil, err
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("winsec: CryptProtectData: %w", err)
	}
	return take(&out, false), nil
}

// ErrUnprotect is returned by Unprotect for a blob this account cannot
// decrypt: one made by another account or on another host, or damaged.
var ErrUnprotect = errors.New("winsec: DPAPI blob cannot be decrypted by this account on this host")

// Unprotect decrypts a blob made by Protect under the same account.
func Unprotect(b []byte) ([]byte, error) {
	if !IsProtectedBlob(b) {
		return nil, fmt.Errorf("%w: not a DPAPI blob", ErrUnprotect)
	}
	in, err := blob(b)
	if err != nil {
		return nil, err
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnprotect, err)
	}
	return take(&out, true), nil
}

// aceSID returns the SID that follows the mask of an allow or deny entry.
func aceSID(ace *windows.ACCESS_ALLOWED_ACE) string {
	return (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String() //nolint:gosec // the SID starts at SidStart in ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE
}

// take copies a DATA_BLOB that CryptProtectData or CryptUnprotectData
// allocated with LocalAlloc, clears it when wipe is set (plaintext) and
// frees it.
func take(out *windows.DataBlob, wipe bool) []byte {
	if out.Data == nil {
		return nil
	}
	mem := unsafe.Slice(out.Data, out.Size) //nolint:gosec // the API returned Size bytes at Data
	b := append([]byte(nil), mem...)
	if wipe {
		clear(mem)
	}
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) //nolint:gosec // LocalFree takes the pointer LocalAlloc returned
	return b
}

// empty backs the DATA_BLOB of empty input: CryptProtectData refuses a
// NULL pbData even with cbData 0.
var empty [1]byte

func blob(b []byte) (windows.DataBlob, error) {
	if len(b) == 0 {
		return windows.DataBlob{Size: 0, Data: &empty[0]}, nil
	}
	if uint64(len(b)) > math.MaxUint32 {
		return windows.DataBlob{}, errors.New("winsec: data too large for DPAPI")
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}, nil //nolint:gosec // bounded above
}

// FreeBytes returns the bytes available to the calling account on the
// volume holding path (GetDiskFreeSpaceEx), FR-21.26.
func FreeBytes(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
		return 0, fmt.Errorf("winsec: free space of %s: %w", path, err)
	}
	return avail, nil
}

// ReplaceFile renames src over dst with MoveFileEx and
// MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH: the rename returns
// only after it is on disk (FR-21.23). src must already be flushed.
func ReplaceFile(src, dst string) error {
	from, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &os.LinkError{Op: "rename", Old: src, New: dst, Err: err}
	}
	return nil
}

// CheckOwnerOnly refuses a file or directory whose DACL grants access to
// an account other than the one running this process, SYSTEM and
// Administrators: the Windows counterpart of "mode 0600 or stricter" for
// password files, credential files and private keys. Inheritance is
// allowed; the inherited entries are checked like explicit ones.
func CheckOwnerOnly(path string) error {
	user, err := ProcessUserSID()
	if err != nil {
		return err
	}
	return CheckDACL(path, false, user, SIDSystem, SIDAdministrators)
}

// SecureOwnerOnly gives path the CP-46 per-user DACL: inheritance disabled
// and full control for the account running this process, SYSTEM and
// Administrators.
func SecureOwnerOnly(path string) error {
	user, err := ProcessUserSID()
	if err != nil {
		return err
	}
	return SetProtectedDACL(path, OwnerEntries(user))
}
