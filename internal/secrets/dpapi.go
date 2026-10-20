package secrets

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

// KeySourceDPAPI keeps the master key in DPAPIKeyFile, encrypted with
// DPAPI (CryptProtectData, user scope) under the account that runs the
// Gateway (SR-2.13-4): the installing user in the Windows per-user mode,
// NT SERVICE\smcpd in the machine mode. Windows only.
const KeySourceDPAPI = "dpapi"

// DPAPIKeyFile is the DPAPI-protected master key, under the vault
// directory.
const DPAPIKeyFile = "master.dpapi"

// DPAPI is the Windows key source of SR-2.13-4.
type DPAPI struct {
	Path string
}

// Name implements KeySource.
func (DPAPI) Name() string { return KeySourceDPAPI }

// Store implements KeySource. It refuses to overwrite a master key.
func (d DPAPI) Store(identity string) error {
	if runtime.GOOS != "windows" {
		return errors.New("key_source dpapi needs Windows")
	}
	blob, err := winsec.Protect([]byte(identity))
	if err != nil {
		return fmt.Errorf("dpapi: %w", err)
	}
	f, err := os.OpenFile(d.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("master key file: %w", err)
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Load implements KeySource. A blob that this account cannot decrypt (a
// copy on another host, or another account) is ErrLocked; the file is
// left as it is.
func (d DPAPI) Load() (string, error) {
	raw, err := os.ReadFile(d.Path)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrLocked, err)
	}
	if !winsec.IsProtectedBlob(raw) {
		return "", fmt.Errorf("%w: %s is not a DPAPI blob", ErrLocked, d.Path)
	}
	b, err := winsec.Unprotect(raw)
	if err != nil {
		// The cause the Gateway reports for any key it cannot decrypt
		// (FR-21.10).
		return "", fmt.Errorf("%w: %w: %s: %w", ErrLocked, keys.ErrKeyProtection, d.Path, err)
	}
	return strings.TrimSpace(string(b)), nil
}
