package keys

import (
	"errors"
	"os"
)

// ErrKeyProtection is returned on Windows for a private file that is not a
// DPAPI blob of the account running the Gateway, or cannot be decrypted by
// it: a state directory copied from another account or host, or a key
// written by hand (FR-21.10). The file is never overwritten. The health
// cause is key_protection.
var ErrKeyProtection = errors.New("key_protection: private key file cannot be decrypted by this account on this host")

// ErrStateACL is returned on Windows for a state directory or private file
// whose DACL grants access to an account other than the one running the
// Gateway, SYSTEM and Administrators, or that inherits its DACL (FR-21.5).
// The health cause is state_acl.
var ErrStateACL = errors.New("state_acl: state directory access control list grants access to other accounts")

// ReadPrivateFile reads a private key or token file. On Windows the file is
// a DPAPI blob (FR-21.10) and the plaintext is returned; elsewhere the file
// is read as it is.
func ReadPrivateFile(path string) ([]byte, error) { return readPrivate(path) }

// WritePrivateFile writes a private key or token file atomically: on
// Windows as a DPAPI blob under the current account, elsewhere as it is,
// with mode 0600.
func WritePrivateFile(path string, data []byte) error { return writePrivate(path, data) }

// SecureStateDir creates stateDir when missing and, on Windows, gives it
// the CP-46 per-user DACL: inheritance disabled, full control for the
// account running this process, SYSTEM and Administrators (FR-21.5).
// Elsewhere the directory is created with mode 0700 and an existing one is
// left as it is.
func SecureStateDir(stateDir string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return secureDir(stateDir)
}
