package keys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// PrivateFiles are the state files whose disclosure gives control of the
// Gateway: the CA and listener keys, the evidence signing keys and the
// local operator token.
var PrivateFiles = []string{CAKeyFile, CANextKeyFile, ServerKeyFile, EvidenceKeyFile, EvidencePendingKeyFile, AdminTokenFile}

// ErrPermissionsOpen is returned by CheckPrivate for a private file that
// other accounts can read or write.
var ErrPermissionsOpen = errors.New("private state file is accessible to other accounts")

// ErrUnprotectedPlatform is returned by CheckPrivate on Windows, where file
// modes do not protect the private files and the DACL check (FR-21.5) and
// DPAPI key protection (FR-21.10) are not implemented yet. The Gateway
// refuses to start rather than run with keys it cannot show are private.
var ErrUnprotectedPlatform = errors.New("private state file protection is not implemented on Windows (FR-21.5 DACL check, FR-21.10 DPAPI); refusing to start with unverified signing keys and operator token")

// CheckPrivate refuses a state directory in which a private file exists
// with group or other permission bits. Ensure creates these files with
// mode 0600; a looser mode means they were copied, restored or changed by
// hand, and any local account could read the operator token or the
// signing keys. Missing files are not an error. On Windows it always
// fails with ErrUnprotectedPlatform.
func CheckPrivate(stateDir string) error {
	if runtime.GOOS == "windows" {
		return ErrUnprotectedPlatform
	}
	for _, name := range PrivateFiles {
		p := filepath.Join(stateDir, name)
		fi, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%w: %s is not a regular file", ErrPermissionsOpen, p)
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			return fmt.Errorf("%w: %s has mode %04o; run chmod 600 %s", ErrPermissionsOpen, p, perm, p)
		}
	}
	return nil
}
