//go:build windows

package keys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

func readPrivate(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	plain, err := winsec.Unprotect(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrKeyProtection, path, err)
	}
	return plain, nil
}

func writePrivate(path string, data []byte) error {
	b, err := winsec.Protect(data)
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, b, 0o600)
}

// allowedSIDs are the accounts CP-46 lets into a per-user or machine-mode
// state directory: the account running the Gateway, SYSTEM and
// Administrators.
func allowedSIDs() ([]string, error) {
	user, err := winsec.ProcessUserSID()
	if err != nil {
		return nil, err
	}
	return []string{user, winsec.SIDSystem, winsec.SIDAdministrators}, nil
}

func secureDir(dir string) error {
	user, err := winsec.ProcessUserSID()
	if err != nil {
		return err
	}
	return winsec.SetProtectedDACL(dir, winsec.OwnerEntries(user))
}

// checkPlatform checks, in place of the POSIX modes (FR-21.10), the DACL of
// the state directory (protected, FR-21.5) and of each private file, and
// that each private file is a DPAPI blob this account can decrypt.
func checkPlatform(stateDir string) error {
	allowed, err := allowedSIDs()
	if err != nil {
		return err
	}
	if err := winsec.CheckDACL(stateDir, true, allowed...); err != nil {
		if errors.Is(err, winsec.ErrForeignAccess) {
			return fmt.Errorf("%w: %w; the state directory may grant access only to this account, SYSTEM and Administrators, with inheritance disabled", ErrStateACL, err)
		}
		return err
	}
	for _, name := range append(slices.Clone(PrivateFiles), windowsPrivateFiles...) {
		p := filepath.Join(stateDir, name)
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := winsec.CheckDACL(p, false, allowed...); err != nil {
			if errors.Is(err, winsec.ErrForeignAccess) {
				return fmt.Errorf("%w: %w", ErrStateACL, err)
			}
			return err
		}
		if _, err := readPrivate(p); err != nil {
			return err
		}
	}
	return nil
}

// windowsPrivateFiles are private files of other packages that the
// Windows check covers as well: the policy-signing key of the Policy Store
// (internal/policystore), also a DPAPI blob on Windows.
var windowsPrivateFiles = []string{"keys/policy.key", AdminTokenMachineFile}

// modeChecked is false on Windows: file modes are not read there.
const modeChecked = false

// WriteMachineOperatorToken writes, in the Windows machine mode, a copy of
// the operator token protected with machine-scope DPAPI and a protected
// DACL for SYSTEM, Administrators and the service account, so that
// smcpctl run by an Administrator can use the control API: the service's
// own copy is user-scope DPAPI of the virtual service account, which no
// other account can decrypt. As root on an Enforced host, Administrators
// can read it; a copy of the state to another host cannot be decrypted.
func WriteMachineOperatorToken(stateDir string) error {
	tok, err := readPrivate(filepath.Join(stateDir, AdminTokenFile))
	if err != nil {
		return err
	}
	blob, err := winsec.ProtectMachine(tok)
	if err != nil {
		return err
	}
	p := filepath.Join(stateDir, AdminTokenMachineFile)
	if err := WriteFileAtomic(p, blob, 0o600); err != nil {
		return err
	}
	self, err := winsec.ProcessUserSID()
	if err != nil {
		return err
	}
	return winsec.SetProtectedDACL(p, winsec.OwnerEntries(self))
}
