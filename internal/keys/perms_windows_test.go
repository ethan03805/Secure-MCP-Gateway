//go:build windows

package keys

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/winsec"
)

// TestWindowsKeyProtection: on Windows every private file is a DPAPI blob
// of the account running the Gateway (FR-21.10), the state directory has a
// protected DACL for that account, SYSTEM and Administrators (FR-21.5), and
// CheckPrivate refuses a foreign grant (state_acl) and a key it cannot
// decrypt (key_protection) without changing the file. Partial: the copy to
// a second host, the machine mode's virtual service account and the health
// report of the cause are not covered here.
func TestWindowsKeyProtection(t *testing.T) {
	reqtest.Partial(t, "FR-21.5", "FR-21.10")
	dir := filepath.Join(t.TempDir(), "state")
	if err := Ensure(dir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(dir); err != nil {
		t.Fatalf("fresh state directory: %v", err)
	}
	user, err := winsec.ProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if err := winsec.CheckDACL(dir, true, user, winsec.SIDSystem, winsec.SIDAdministrators); err != nil {
		t.Fatalf("state directory DACL: %v", err)
	}
	for _, name := range PrivateFiles {
		p := filepath.Join(dir, name)
		b, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !winsec.IsProtectedBlob(b) {
			t.Errorf("%s is not a DPAPI blob", name)
		}
		if bytes.Contains(b, []byte("PRIVATE KEY")) {
			t.Errorf("%s holds a plaintext key", name)
		}
	}
	if _, err := LoadEvidenceKey(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAdminToken(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyPair(filepath.Join(dir, ServerCertFile), filepath.Join(dir, ServerKeyFile)); err != nil {
		t.Fatal(err)
	}

	// FR-21.5: an entry for the Users group is refused with state_acl.
	if err := winsec.Grant(dir, winsec.SIDUsers, winsec.Read); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(dir); !errors.Is(err, ErrStateACL) {
		t.Fatalf("Users granted: err = %v, want ErrStateACL", err)
	}
	if err := winsec.Revoke(dir, winsec.SIDUsers); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(dir); err != nil {
		t.Fatalf("after revoking Users: %v", err)
	}

	// FR-21.10: a key that does not decrypt is refused and left unchanged.
	p := filepath.Join(dir, EvidenceKeyFile)
	orig, _ := os.ReadFile(p)
	for _, bad := range [][]byte{
		[]byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"),
		append(append([]byte(nil), orig[:len(orig)-1]...), orig[len(orig)-1]^0xff),
	} {
		if err := os.WriteFile(p, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := CheckPrivate(dir); !errors.Is(err, ErrKeyProtection) {
			t.Fatalf("undecryptable key: err = %v, want ErrKeyProtection", err)
		}
		if _, err := LoadEvidenceKey(dir); !errors.Is(err, ErrKeyProtection) {
			t.Fatalf("LoadEvidenceKey: %v", err)
		}
		if err := Ensure(dir, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(p); !bytes.Equal(got, bad) {
			t.Fatal("Ensure overwrote an undecryptable key")
		}
	}
}
