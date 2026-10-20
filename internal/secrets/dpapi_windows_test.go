//go:build windows

package secrets

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
	"github.com/ethan03805/secure-mcp-gateway/internal/wintest"
)

// TestWindowsVaultMasterKey performs SR-2.13-4 for the per-user mode on a
// Windows runner: a vault initialized with the auto key source keeps its
// master key as a DPAPI blob (no age identity in plaintext in any file of
// the vault), the account that made it opens it, a second local account
// cannot decrypt it, and the passphrase option keeps the key age-encrypted
// under scrypt instead. Partial: the machine mode (a key made by the
// service account, which the administrator cannot decrypt) and the copy to
// another host are checked by internal/acceptance
// TestWindowsStateCopyExport and TestWindowsStateCopyRefused.
func TestWindowsVaultMasterKey(t *testing.T) {
	reqtest.Partial(t, "SR-2.13-4")
	root := t.TempDir()
	if err := winsec.SecureOwnerOnly(root); err != nil {
		t.Fatal(err)
	}
	name, err := ResolveKeySource(KeySourceAuto)
	if err != nil || name != KeySourceDPAPI {
		t.Fatalf("auto key source on Windows = %q, %v; want dpapi", name, err)
	}
	dir := filepath.Join(root, "vault")
	ks, err := KeySourceFor(dir, name, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Init(dir, ks); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(filepath.Join(dir, DPAPIKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if !winsec.IsProtectedBlob(blob) {
		t.Fatalf("%s is not a DPAPI blob", DPAPIKeyFile)
	}
	noPlaintextIdentity(t, dir)
	v, err := Open(dir, ks, VaultOptions{})
	if err != nil {
		t.Fatalf("the account that made the vault cannot open it: %v", err)
	}
	if v.KeySource() != KeySourceDPAPI {
		t.Fatalf("store records key source %q", v.KeySource())
	}
	if _, err := Open(dir, ks, VaultOptions{}); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	// A second local account: DPAPI refuses the blob, also when the file
	// is readable to it (a copy in a directory it may read).
	other := wintest.NewUser(t)
	shared := t.TempDir()
	if err := winsec.Grant(shared, other.SID, winsec.ReadExecute); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(shared, DPAPIKeyFile)
	if err := os.WriteFile(copyPath, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := winsec.Grant(copyPath, other.SID, winsec.ReadExecute); err != nil {
		t.Fatal(err)
	}
	var loadErr, rawErr error
	other.As(t, func() {
		_, loadErr = DPAPI{Path: copyPath}.Load()
		_, rawErr = winsec.Unprotect(blob)
	})
	if !errors.Is(loadErr, ErrLocked) || !errors.Is(rawErr, winsec.ErrUnprotect) {
		t.Fatalf("second account %s: Load %v, Unprotect %v; both must fail", other.Name, loadErr, rawErr)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, DPAPIKeyFile)); !bytes.Equal(after, blob) {
		t.Fatal("the master key changed")
	}

	// The passphrase option: age, scrypt recipient, no DPAPI.
	pdir := filepath.Join(root, "pvault")
	pks := Passphrase{Path: filepath.Join(pdir, MasterKeyFile), Passphrase: func() (string, error) { return "windows vault passphrase", nil }, WorkFactor: 10}
	if _, err := Init(pdir, pks); err != nil {
		t.Fatal(err)
	}
	age, err := os.ReadFile(filepath.Join(pdir, MasterKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(age, []byte("age-encryption.org/v1\n-> scrypt ")) {
		t.Fatalf("%s is not age-encrypted to an scrypt recipient: %q", MasterKeyFile, age[:min(len(age), 40)])
	}
	noPlaintextIdentity(t, pdir)
	if _, err := Open(pdir, pks, VaultOptions{}); err != nil {
		t.Fatalf("passphrase vault: %v", err)
	}
	wrong := pks
	wrong.Passphrase = func() (string, error) { return "not the vault passphrase", nil }
	if _, err := Open(pdir, wrong, VaultOptions{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("wrong passphrase: %v", err)
	}
}

// noPlaintextIdentity fails when a file below dir holds an age identity.
func noPlaintextIdentity(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(strings.ToUpper(string(b)), "AGE-SECRET-KEY-") {
			t.Errorf("%s holds the master key in plaintext", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
