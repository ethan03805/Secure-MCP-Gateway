//go:build !windows

package keys

import (
	"errors"
	"os"
)

func readPrivate(path string) ([]byte, error) { return os.ReadFile(path) }

func writePrivate(path string, data []byte) error { return WriteFileAtomic(path, data, 0o600) }

func secureDir(string) error { return nil }

// checkPlatform is the platform part of CheckPrivate; the POSIX mode check
// in CheckPrivate is the whole check here.
func checkPlatform(string) error { return nil }

const modeChecked = true

// WriteMachineOperatorToken is used by the Windows machine mode only.
func WriteMachineOperatorToken(string) error {
	return errors.New("keys: the machine-mode operator token is Windows only")
}
